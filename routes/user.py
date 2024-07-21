from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from ..schemas import User, UserInDB
from ..models import DeletedUserModel
from ..utils import get_current_active_user, get_user, log_activity, get_db

router = APIRouter()

@router.get("/users/me/", tags=["user"], response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
    return current_user

@router.put("/users/me/", tags=["user"], response_model=User, description="Relogin if username is changed otherwise you will get authentication error because of changed username")
async def update_user_me(full_name: str | None = None, username: str | None = None, two_factor_authentication_enabled:bool | None = None,  current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    if username is not None and username != current_user.username:
        existing_user = get_user(db, username)
        if existing_user and existing_user.id != current_user.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already taken")
        current_user.username = username

    if full_name is not None:
        current_user.full_name = full_name

    if two_factor_authentication_enabled is not None:
        current_user.two_factor_authentication_enabled = two_factor_authentication_enabled

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    log_activity(db, current_user.id, "profile update")
    return current_user


@router.delete("/users/me/", tags=["user"])
async def delete_user_me(current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )

    deleted_user = DeletedUserModel(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        hashed_password=current_user.hashed_password,
        role=current_user.role,
        created_at=current_user.created_at,
        deleted_at=datetime.utcnow()
    )

    db.add(deleted_user)
    db.commit()

    db.delete(current_user)
    db.commit()

    log_activity(db, current_user.id, "account deleted")
    
    return {"detail": "User account has been deleted, you can re-activate it any time by trying to register using same credintials."}