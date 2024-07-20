from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from typing import Optional, List

from ..models import User as UserModel, UserActivityLog
from ..schemas import UserInDB, UserActivityLogSchema, UserAdminView

from ..utils import get_current_active_user, log_activity, get_db

router = APIRouter()

@router.post("/assign-admin/{username}", tags=["admin"])
async def assign_admin(username: str, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    
    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = "admin"
    db.add(user)
    db.commit()
    db.refresh(user)
    log_activity(db, current_user.id, f"assigned {user.username} as admin")
    log_activity(db, user.id, "user assigned as admin")
    return {"message": f"User {user.username} has been assigned as an admin"}

@router.delete("/admin/users/{username}/revoke-role/", tags=["admin"])
async def revoke_admin_role(username: str, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    
    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    user = db.query(UserModel).filter(UserModel.id == username).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User does not have admin role")
    
    user.role = "user"
    db.add(user)
    db.commit()
    log_activity(db, current_user.id, f"assigned {user.username} as admin")
    log_activity(db, user.id, "admin role revoked")
    
    return {"message": f"Admin role revoked from user {user.username}"}


@router.get("/admin/users/", tags=["admin"], response_model=List[UserAdminView])
async def list_users(user_id: Optional[int] = None, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):  
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    if user_id is not None:
        user = db.query(UserModel).filter(UserModel.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return [user]
    
    return db.query(UserModel).filter(current_user.id != UserModel.id).all()


@router.delete("/admin/users/{user_id}", tags=["admin"])
async def block_user(user_id: int, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):  
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role == 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot directly delete admin from system")
    user.disabled = True
    db.add(user)
    db.commit()
    log_activity(db, current_user.id, f"blocked user {user.username}")
    log_activity(db, user.id, "blocked")
    return {"message": f"User {user.username} has been blocked"}


@router.put("/admin/users/{user_id}", tags=["admin"])
async def unblock_user(user_id: int, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):  
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role == 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot directly delete admin from system")
    user.disabled = False
    db.add(user)
    db.commit()
    log_activity(db, current_user.id, f"un-blocked user {user.username}")
    log_activity(db, user_id, "un-blocked")
    return {"message": f"User {user.username} has been Un-blocked"}


@router.get("/admin/logs/", tags=["admin"], response_model=List[UserActivityLogSchema])
async def filter_logs(user_id: Optional[int] = None, activity_type: Optional[str] = None, current_user: UserInDB = Depends(get_current_active_user), db: Session = Depends(get_db)):  
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")

    if current_user.two_factor_authentication_enabled:
        if not current_user.otp_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OTP not verified",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    query = db.query(UserActivityLog).filter(UserActivityLog.user_id != current_user.id)
    
    if user_id is not None:
        query = query.filter(UserActivityLog.user_id == user_id)
    
    if activity_type:
        query = query.filter(UserActivityLog.activity_type == activity_type)
    
    return query.all()