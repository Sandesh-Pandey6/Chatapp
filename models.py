from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")
    
    messages = relationship("Message", back_populates="user")
    rooms_created = relationship("Room", back_populates="creator")

class Room(Base):
    __tablename__ = "rooms"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey("users.id"))
    
    creator = relationship("User", back_populates="rooms_created")
    messages = relationship("Message", back_populates="room")

class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True)
    content = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    room_id = Column(String, ForeignKey("rooms.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    
    room = relationship("Room", back_populates="messages")
    user = relationship("User", back_populates="messages")