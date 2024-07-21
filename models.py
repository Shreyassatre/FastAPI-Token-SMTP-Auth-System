from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)
    role = Column(String, default="user")
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_update_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    otp = Column(String, nullable=True)
    otp_expiration = Column(DateTime, nullable=True)
    otp_verified = Column(Boolean, default=False)
    two_factor_authentication_enabled = Column(Boolean, default=True)
    
    activity_logs = relationship("UserActivityLog", back_populates="user")

class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    activity_type = Column(String, index=True)
    timestamp = Column(DateTime, index=True, default=datetime.utcnow)

    user = relationship("User", back_populates="activity_logs")

class DeletedUserModel(Base):
    __tablename__ = "deleted_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    email = Column(String, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    role = Column(String)
    created_at = Column(DateTime)
    deleted_at = Column(DateTime, default=datetime.utcnow)