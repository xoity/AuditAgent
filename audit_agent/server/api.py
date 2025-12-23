from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict
import uuid
from datetime import timedelta

from .auth import (
    create_access_token,
    get_password_hash,
    verify_password,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    decode_access_token,
    UserInDB
)
from .schemas import (
    Token, User, CLISessionStatus, CLISessionApprove
)

app = FastAPI()

# CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock Database
users_db = {
    "admin": {
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": get_password_hash("admin"),
        "disabled": False,
    }
}

# In-memory store for CLI sessions
# session_id -> { "status": "pending" | "approved", "token": str | None }
cli_sessions: Dict[str, dict] = {}

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    token_data = decode_access_token(token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = get_user(users_db, username=token_data.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(users_db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# CLI Auth Endpoints

@app.post("/api/cli/init")
async def init_cli_session():
    session_id = str(uuid.uuid4())
    cli_sessions[session_id] = {"status": "pending", "token": None}
    # Assuming UI is running on localhost:3000
    return {
        "session_id": session_id,
        "url": f"http://localhost:3000/cli-auth?session_id={session_id}"
    }

@app.get("/api/cli/poll", response_model=CLISessionStatus)
async def poll_cli_session(session_id: str):
    if session_id not in cli_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = cli_sessions[session_id]
    return CLISessionStatus(status=session["status"], access_token=session["token"])

@app.post("/api/cli/approve")
async def approve_cli_session(
    request: CLISessionApprove,
    current_user: User = Depends(get_current_user)
):
    session_id = request.session_id
    if session_id not in cli_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Generate a long-lived token for the CLI
    access_token_expires = timedelta(days=365)
    access_token = create_access_token(
        data={"sub": current_user.username, "type": "cli"}, 
        expires_delta=access_token_expires
    )
    
    cli_sessions[session_id]["status"] = "approved"
    cli_sessions[session_id]["token"] = access_token
    
    return {"status": "success"}
