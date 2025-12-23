from pydantic import BaseModel
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

class CLISessionCreate(BaseModel):
    description: Optional[str] = "CLI Session"

class CLISessionApprove(BaseModel):
    session_id: str

class CLISessionStatus(BaseModel):
    status: str
    access_token: Optional[str] = None
