from fastapi import WebSocket, WebSocketDisconnect, Query, status,Depends
from sqlalchemy.orm import Session
from auth import verify_jwt_token
from database import SessionLocal
from models import Message
from datetime import datetime
from typing import Dict, List, Optional
import json

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, room_id: str, websocket: WebSocket):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = []
        self.active_connections[room_id].append(websocket)

    def disconnect(self, room_id: str, websocket: WebSocket):
        if room_id in self.active_connections:
            self.active_connections[room_id].remove(websocket)
            if not self.active_connections[room_id]:
                del self.active_connections[room_id]

    async def broadcast(self, room_id: str, message: dict):
        if room_id in self.active_connections:
            for connection in self.active_connections[room_id]:
                try:
                    await connection.send_json(message)
                except WebSocketDisconnect:
                    self.disconnect(room_id, connection)

manager = ConnectionManager()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def websocket_endpoint(
    websocket: WebSocket,
    room_id: str,
    token: str = Query(...),
    last_message_id: Optional[int] = 0,
    db: Session = Depends(get_db)
):
    # Verify JWT token with expiration check
    user = verify_jwt_token(token)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(room_id, websocket)

    try:
        # Fetch messages with cursor-based pagination
        query = db.query(Message).filter(Message.room_id == room_id)
        if last_message_id and last_message_id > 0:
            query = query.filter(Message.id > last_message_id)
        
        recent_msgs = query.order_by(Message.timestamp.asc()).limit(50).all()
        
        # Send initial messages
        initial_batch = {
            "type": "initial",
            "messages": [{
                "id": msg.id,
                "username": msg.sender,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat()
            } for msg in recent_msgs]
        }
        await websocket.send_json(initial_batch)

        # Handle incoming messages
        while True:
            try:
                data = await websocket.receive_json()
                
                # Validate message - strict 100 character limit
                message_content = data.get("content", "")
                if not message_content:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Message cannot be empty"
                    })
                    continue
                
                if len(message_content) > 100:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Message exceeds 100 character limit"
                    })
                    continue
                
                # Save message
                new_msg = Message(
                    room_id=room_id,
                    sender=user["sub"],
                    content=message_content[:100],  # Ensure we never exceed limit
                    timestamp=datetime.utcnow()
                )
                db.add(new_msg)
                db.commit()
                db.refresh(new_msg)
                
                # Broadcast to room
                await manager.broadcast(room_id, {
                    "type": "message",
                    "id": new_msg.id,
                    "username": new_msg.sender,
                    "content": new_msg.content,
                    "timestamp": new_msg.timestamp.isoformat(),
                    "length": len(new_msg.content)  # For client-side verification
                })

            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error", 
                    "message": "Invalid JSON format"
                })
            except Exception as e:
                db.rollback()
                await websocket.send_json({
                    "type": "error",
                    "message": f"Error processing message: {str(e)}"
                })

    except WebSocketDisconnect:
        manager.disconnect(room_id, websocket)
    finally:
        db.close()
