from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: str
    full_name: str = None

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    two_factor_authentication_enabled: bool

class UserAdminView(UserBase):
    id: int
    disabled: bool
    role: str
    created_at: datetime
    last_update_at: datetime

class TokenData(BaseModel):
    username: Optional[str] = None

class UserInDB(UserBase):
    hashed_password: str
    disabled: bool
    role: str
    two_factor_authentication_enabled: bool

class UserActivityLogSchema(BaseModel):
    user_id: int
    activity_type: str
    timestamp: datetime

class DeletedUser(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    hashed_password: str
    role: str
    created_at: datetime

