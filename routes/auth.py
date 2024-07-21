from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import EmailStr


from ..models import User as UserModel, DeletedUserModel
from ..schemas import User, UserCreate

from ..utils import authenticate_user, generate_otp, send_email, create_user, create_access_token, get_current_active_user, get_user, log_activity, get_db, get_current_user, get_password_hash
from ..utils import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, PASSWORD_RESET_TOKEN_EXPIRE_MINUTES, OTP_EXPIRE_MINUTES

router = APIRouter()

@router.post("/verify-otp", tags=["auth"])
async def verify_otp(otp: str, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if not current_user.two_factor_authentication_enabled:
        raise HTTPException(status_code=401, detail="Two Factor Authentication is not enabled") 
    
    if not current_user.otp or current_user.otp != otp or current_user.otp_expiration < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired OTP",
        )

    current_user.otp_verified = True
    current_user.otp = None
    current_user.otp_expiration = None
    db.add(current_user)
    db.commit()

    return {"msg": "OTP verified"}


@router.post("/login", tags=["auth"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), background_tasks: BackgroundTasks = BackgroundTasks()
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.two_factor_authentication_enabled:
        user.otp_verified = False
        otp = generate_otp()
        user.otp = otp
        user.otp_expiration = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)
        db.add(user)
        db.commit()

        email_body = f"""
        <html>
        <body>
            <p>Hello {user.username},</p>
            <p>Your OTP for login is: <strong>{otp}</strong></p>
            <p>This OTP is valid for 10 minutes.</p>
            <br/>
            <p>Thank you</p>
        </body>
        </html>
        """

        background_tasks.add_task(send_email, to=user.email, subject="Your OTP for Login", body=email_body)


    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/register/", tags=["auth"])
async def register_user(username: str, email: EmailStr, full_name: str, password: str, db: Session = Depends(get_db), background_tasks: BackgroundTasks = BackgroundTasks()):
    db_user = get_user(db, username)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    

    deleted_user = db.query(DeletedUserModel).filter(DeletedUserModel.email == email).first()
    if deleted_user:
        verification_token = create_access_token(data={"sub": deleted_user.username, "action": "reopen_account"})
        verification_link = f"http://localhost:8000/reopen-account?token={verification_token}"
        email_body = f"""
        <html>
        <body>
            <p>Hello {deleted_user.username},</p>
            <p>To Reopen your account, click on the button below:</p>
            <p><a href="{verification_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">Reopen Account</a></p>
            <p>If you did not requested for it, please ignore this email.</p>
            <br/>
            <p>Thank you</p>
        </body>
        </html>
        """

        background_tasks.add_task(send_email, to=deleted_user.email, subject="Account Re-activation", body=email_body)

        background_tasks.add_task(send_email, to=deleted_user.email, subject="Account Reopening", body=email_body)
        return {"message": f"Account reopening link has been sent to {deleted_user.email} successfully"}
    
    user_create = UserCreate(
        username=username,
        email=email,
        full_name=full_name,
        password=password
    )
    new_user = create_user(db, user_create)

    verification_token = create_access_token(data={"sub": new_user.username, "action": "email_verification"})
    verification_link = f"http://localhost:8000/verify-email?token={verification_token}"
    email_body = f"""
    <html>
    <body>
        <p>Hello {new_user.username},</p>
        <p>To verify your email, click on the button below:</p>
        <p><a href="{verification_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">Verify Email</a></p>
        <p>If you did not register, please ignore this email.</p>
        <br/>
        <p>Thank you</p>
    </body>
    </html>
    """
    background_tasks.add_task(send_email, to=new_user.email, subject="Email Verification", body=email_body)


    log_activity(db, new_user.id, "register")
    
    return {"message": "Verification Email has been sent on successfully"}


@router.get("/reopen-account/", tags=["auth"])
async def reopen_account(token: str, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        action: str = payload.get("action")
        if username is None or action != "reopen_account":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    deleted_user = db.query(DeletedUserModel).filter(DeletedUserModel.username == username).first()
    if not deleted_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in deleted accounts")

    reinstated_user = UserModel(
        username=deleted_user.username,
        email=deleted_user.email,
        full_name=deleted_user.full_name,
        hashed_password=deleted_user.hashed_password,
        role=deleted_user.role,
        verified=True,
        created_at=deleted_user.created_at
    )
    db.add(reinstated_user)
    db.commit()

    db.delete(deleted_user)
    db.commit()

    log_activity(db, reinstated_user.id, "account reopened")

    return {"message": "User account has been reopened successfully"}


@router.get("/verify-email/", tags=["auth"])
async def verify_email(token: str, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        action: str = payload.get("action")
        if username is None or action != "email_verification":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception

    user.verified = True
    db.add(user)
    db.commit()
    log_activity(db, user.id, "email_verified")

    return {"message": "Email has been verified successfully"}

@router.post("/logout", tags=["auth"])
async def logout_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.otp_verified = False
    current_user.otp = None
    current_user.otp_expiration = None
    db.add(current_user)
    db.commit()
    log_activity(db, current_user.id, "logout")
    return {"msg": "User logged out"}

@router.post("/password-reset-request/", tags=["auth"])
async def password_reset_request(email: EmailStr, db: Session = Depends(get_db), background_tasks: BackgroundTasks = BackgroundTasks()):
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User with this email does not exist")

    reset_token_expires = timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    reset_token = create_access_token(
        data={"sub": user.username, "action": "password_reset"}, expires_delta=reset_token_expires
    )

    reset_link = f"http://localhost:8000/reset-password?token={reset_token}"
    email_body = f"""
    <html>
    <body>
        <p>Hello {user.username},</p>
        <p>To reset your password, click on the button below:</p>
        <p><a href="{reset_link}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">Reset Password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>Thank you</p>
    </body>
    </html>
    """
    background_tasks.add_task(send_email, to=user.email, subject="Password Reset Request", body=email_body)

    return {"message": "Password reset link has been sent to your email"}

@router.post("/reset-password", tags=["auth"])
async def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        action: str = payload.get("action")
        if username is None or action != "password_reset":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    hashed_password = get_password_hash(new_password)
    user.hashed_password = hashed_password
    db.add(user)
    db.commit()
    log_activity(db, user.id, "password_reset")
    return {"message": "Password has been reset successfully"}