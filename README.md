# FastAPI Chat Application

A real-time chat application with JWT authentication, WebSocket messaging, and PostgreSQL persistence, 
## Features

### Group A: Mandatory Tasks
1. **JWT Authentication & RBAC**
   - `/signup`: Register users with `user`/`admin` roles
   - `/login`: Get JWT tokens (HS256-signed) with embedded roles
   - Protected routes using `get_current_user` and `get_current_admin_user`

2. **WebSocket Chat**
   - Secure `/ws/{room_id}` endpoint with JWT validation
   - Real-time messaging with broadcast to room participants
   - Cursor-based pagination (`last_message_id`) for message history

3. **PostgreSQL Models**
   - `User`: Stores credentials and role
   - `Room`: Tracks chat rooms with creator metadata
   - `Message`: Persists messages with timestamps

### Group B Task 1: PostgreSQL Persistence
- SQLAlchemy ORM integration
- Proper model relationships:
  - `User` → `Room` (one-to-many)
  - `Room` → `Message` (one-to-many)
  - `User` → `Message` (one-to-many)

### Extended Features
- Room management API (`POST /rooms/`, `DELETE /rooms/{room_id}`)
- Admin-only endpoints (e.g., room deletion)
- Custom OpenAPI schema with simplified security definitions

## Setup

1. **Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
