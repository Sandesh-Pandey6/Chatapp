from fastapi import FastAPI, Depends, HTTPException, WebSocket, status
from sqlalchemy.orm import Session
import websocket as ws
from database import SessionLocal, engine
import models
import auth
from auth import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    get_current_user,
    get_current_admin_user
)
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import uuid
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi

# Create all database tables
models.Base.metadata.create_all(bind=engine)

# Simplified security scheme for Swagger UI
security = HTTPBearer()

app = FastAPI()

# Disable OAuth2 in Swagger UI
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="ChatApp API",
        version="1.0.0",
        routes=app.routes,
    )
    
    # Move schemas to root level instead of components
    if "components" in openapi_schema:
        for schema_name, schema in openapi_schema["components"]["schemas"].items():
            openapi_schema["definitions"] = openapi_schema.get("definitions", {})
            openapi_schema["definitions"][schema_name] = schema
        
        # Update all $refs to point to definitions instead of components
        import json
        schema_str = json.dumps(openapi_schema)
        schema_str = schema_str.replace('"#/components/schemas/', '"#/definitions/')
        openapi_schema = json.loads(schema_str)
        
        del openapi_schema["components"]  # Remove components after migration
    
    # Add security scheme at root level
    openapi_schema["securityDefinitions"] = {
        "HTTPBearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
    
    app.openapi_schema = openapi_schema
    return openapi_schema

app.openapi = custom_openapi


# Pydantic Models (unchanged)
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class LoginData(BaseModel):
    username: str
    password: str

class RoomCreate(BaseModel):
    name: str
    description: Optional[str] = None

class RoomResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime
    creator_username: str
    
    class Config:
       from_attributes = True

class MessageResponse(BaseModel):
    id: int
    content: str
    timestamp: datetime
    username: str
    room_id: str
    
    class Config:
         from_attributes = True

# Helper function to get DB session (unchanged)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Routes
@app.get("/")
def read_root():
    return {"message": "Welcome to the ChatApp API"}

@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(auth.get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_password, role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created successfully"}

@app.post("/login")
def login(data: LoginData, db: Session = Depends(auth.get_db)):
    user = db.query(models.User).filter(models.User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.id})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/rooms/", response_model=RoomResponse, status_code=status.HTTP_201_CREATED)
def create_room(
    room: RoomCreate,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    current_user = get_current_user(token, db)
    
    room_id = str(uuid.uuid4())
    db_room = models.Room(
        id=room_id,
        name=room.name,
        description=room.description,
        creator_id=current_user.id
    )
    db.add(db_room)
    db.commit()
    db.refresh(db_room)
    return {
        "id": db_room.id,
        "name": db_room.name,
        "description": db_room.description,
        "created_at": db_room.created_at,
        "creator_username": current_user.username
    }

# Other routes remain the same...
@app.get("/rooms/", response_model=List[RoomResponse])
def list_rooms(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    rooms = db.query(
        models.Room.id,
        models.Room.name,
        models.Room.description,
        models.Room.created_at,
        models.User.username.label("creator_username")
    ).join(
        models.User, models.Room.creator_id == models.User.id
    ).offset(skip).limit(limit).all()
    return rooms

@app.get("/rooms/{room_id}/messages", response_model=List[MessageResponse])
def get_room_messages(
    room_id: str,
    last_message_id: Optional[int] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(
        models.Message.id,
        models.Message.content,
        models.Message.timestamp,
        models.User.username,
        models.Message.room_id
    ).join(
        models.User
    ).filter(
        models.Message.room_id == room_id
    ).order_by(
        models.Message.timestamp.desc()
    )
    
    if last_message_id:
        query = query.filter(models.Message.id < last_message_id)
    
    messages = query.limit(limit).all()
    return messages

@app.delete("/rooms/{room_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_room(
    room_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    room = db.query(models.Room).filter(models.Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    
    db.delete(room)
    db.commit()
    return None

@app.websocket("/ws/{room_id}")
async def chat_websocket(websocket: WebSocket, room_id: str, token: str):
    db = SessionLocal()
    await ws.websocket_endpoint(websocket, room_id, token, db)

