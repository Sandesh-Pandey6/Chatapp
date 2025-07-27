import os
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from models import User
from database import SessionLocal
import logging
import bcrypt


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security Configuration (should be in environment variables in production)
SECRET_KEY = os.getenv("SECRET_KEY", "e685cd790680305b9f58bdc2ae1d292de7dc957cfa0325902ae9049f81eebebd")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE", 30))

# Security schemes
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
security = HTTPBearer()

class RateLimiter:
    def __init__(self, max_calls: int = 5, time_frame: int = 60):
        self.max_calls = max_calls
        self.time_frame = time_frame
        self.access_records = {}

    async def check_limit(self, request: Request):
        client_ip = request.client.host
        now = datetime.now()
        
        if client_ip not in self.access_records:
            self.access_records[client_ip] = []
        
        # Remove old access times
        self.access_records[client_ip] = [
            t for t in self.access_records[client_ip] 
            if (now - t).seconds < self.time_frame
        ]
        
        if len(self.access_records[client_ip]) >= self.max_calls:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later."
            )
        
        self.access_records[client_ip].append(now)
        return True

rate_limiter = RateLimiter(max_calls=10, time_frame=60)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Password utilities
def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
# Token utilities
def create_access_token(
    data: dict, 
    expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    if "sub" not in to_encode:
        raise ValueError("Token must contain 'sub' claim")
    
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": "chatapp-api",
        "role": to_encode.get("role", "user")  # Default role
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            raise JWTError("Token expired")
        return payload
    except JWTError as e:
        logger.error(f"Token verification failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Authentication dependencies
async def get_token_from_header(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return credentials.credentials

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
        
        return user
    except JWTError as e:
        raise credentials_exception

def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    if current_user.role != "admin":
        logger.warning(f"Admin access denied for user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = decode_token(token)
        return {
            "id": payload.get("id"),
            "sub": payload.get("sub"),
            "role": payload.get("role")
        }
    except HTTPException:
        return None

# Security middleware utilities
async def authenticate_request(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """Middleware for additional request validation"""
    # Rate limiting check
    await rate_limiter.check_limit(request)
    
    # Token validation
    user = get_current_user(token, db)
    
    # Additional security checks could go here
    if user.is_banned:  # Assuming you have this field
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended"
        )
    
    return user
