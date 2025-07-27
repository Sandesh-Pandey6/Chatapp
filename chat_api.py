import requests
import getpass
import json
import os
import re
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta

# Configuration
BASE_URL = "http://127.0.0.1:8000"
TOKEN_FILE = ".auth_token.json"
REQUEST_TIMEOUT = 60  # seconds (changed from 60000)

class AuthError(Exception):
    """Custom exception for authentication failures"""
    pass

class RoomValidationError(Exception):
    """Custom exception for invalid room data"""
    pass

def validate_server_connection() -> bool:
    """Check if the API server is reachable"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"Server connection failed: {str(e)}")
        return False

def get_credentials() -> Tuple[str, str]:
    """Securely get username/password with validation"""
    print("\n=== Chat App Login ===")
    while True:
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ").strip()
        if username and password:
            return username, password
        print("Error: Both fields are required")

def is_valid_jwt(token: str) -> bool:
    """Validate JWT structure"""
    return token and len(token.split('.')) == 3

def login(username: str, password: str) -> str:
    """Authenticate and return JWT token with enhanced error handling"""
    try:
        response = requests.post(
            f"{BASE_URL}/login",
            json={"username": username, "password": password},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        
        token = response.json().get("access_token")
        if not is_valid_jwt(token):
            raise AuthError("Invalid token format received")
            
        return token
    except requests.exceptions.HTTPError as e:
        error_detail = e.response.json().get("detail", "Login failed")
        raise AuthError(f"Login error: {error_detail}")
    except Exception as e:
        raise AuthError(f"Connection error: {str(e)}")

def save_token_data(token: str, username: str) -> None:
    """Securely store token with metadata"""
    token_data = {
        "username": username,
        "token": token,
        "timestamp": datetime.now().isoformat()
    }
    try:
        with open(TOKEN_FILE, "w") as f:
            json.dump(token_data, f)
        os.chmod(TOKEN_FILE, 0o600)  # Restrict file permissions
    except IOError as e:
        print(f"Warning: Could not save token - {str(e)}")

def load_valid_token() -> Optional[Dict[str, str]]:
    """Load and validate stored token"""
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE) as f:
                data = json.load(f)
                if all(k in data for k in ["username", "token"]):
                    if is_valid_jwt(data["token"]):
                        return data
                    print(" Stored token is invalid")
    except (json.JSONDecodeError, IOError) as e:
        print(f" Token file error: {str(e)}")
    return None

def create_authorized_session(token: str) -> requests.Session:
    """Create a session with guaranteed auth headers"""
    session = requests.Session()
    session.headers.update({
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    })
    return session

def validate_room_name(name: str) -> bool:
    """Validate room name meets requirements"""
    if not name or len(name) > 50:
        return False
    return bool(re.match(r'^[\w\s-]+$', name))

def create_room(session: requests.Session, room_name: str, description: str = "") -> Dict:
    """Create room with automatic token refresh"""
    if not validate_room_name(room_name):
        raise RoomValidationError("Room name must be 1-50 alphanumeric characters")
    
    try:
        response = session.post(
            f"{BASE_URL}/rooms/",
            json={"name": room_name, "description": description},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            raise AuthError("Session expired - please login again")
        raise Exception(f"API error: {e.response.json().get('detail', str(e))}")
    except Exception as e:
        raise Exception(f"Network error: {str(e)}")

def handle_authentication() -> Tuple[requests.Session, str]:
    """Complete auth flow with user feedback"""
    stored_data = load_valid_token()
    token = None
    
    if stored_data:
        print(f"\nFound existing session for: {stored_data['username']}")
        if input("Use saved token? (y/n): ").lower() == 'y':
            token = stored_data["token"]

    if not token:
        print("\nNew login required")
        username, password = get_credentials()
        token = login(username, password)
        save_token_data(token, username)

    return create_authorized_session(token), token

def main_flow():
    """Main interactive flow with error recovery"""
    if not validate_server_connection():
        print(f" Cannot connect to server at {BASE_URL}")
        return

    try:
        session, token = handle_authentication()
        
        while True:
            try:
                print("\n=== Create New Room ===")
                room_name = input("Room name: ").strip()
                description = input("Description (optional): ").strip()
                
                if not room_name:
                    print(" Room name cannot be empty")
                    continue

                print("\n Creating room...")
                result = create_room(session, room_name, description)
                print("\n Room created successfully!")
                print(json.dumps(result, indent=2))
                break

            except RoomValidationError as e:
                print(f"\n Validation error: {str(e)}")
            except AuthError as e:
                print(f"\n Authentication error: {str(e)}")
                os.remove(TOKEN_FILE)
                session, token = handle_authentication()
            except Exception as e:
                print(f"\n Error: {str(e)}")
                if input("Try again? (y/n): ").lower() != 'y':
                    break

    except Exception as e:
        print(f"\n Fatal error: {str(e)}")

if __name__ == "__main__":
    main_flow()