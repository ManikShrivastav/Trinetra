"""
Authentication Database Module for Trinetra
Handles user authentication, JWT token management, and role-based access control.
"""

import os
import json
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "trinetra_super_secret_key_change_in_production")
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 1  # Token expires in 1 hour

# Database file path
DB_PATH = Path(__file__).parent / "auth_users.json"


class AuthDatabase:
    """
    Manages user authentication with in-memory mock database.
    In production, replace with actual database (PostgreSQL, MongoDB, etc.)
    """

    def __init__(self):
        """Initialize authentication database with mock users and roles."""
        self.roles = {
            1: "Admin",
            2: "User",
            3: "Guest"
        }

        # Mock users - passwords will be hashed on first use
        self.users = {
            "admin_user": {
                "id": 1,
                "userid": "admin_user",
                "password": "password123",  # Will be hashed
                "role_id": 1,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True
            },
            "test_user": {
                "id": 2,
                "userid": "test_user",
                "password": "password123",  # Will be hashed
                "role_id": 2,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True
            },
            "guest_user": {
                "id": 3,
                "userid": "guest_user",
                "password": "guest123",  # Will be hashed
                "role_id": 3,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True
            }
        }

        # Hash all passwords on initialization
        self._hash_passwords()

        # Token blacklist for logout (in production, use Redis)
        self.token_blacklist = set()

    def _hash_passwords(self):
        """Hash all plain-text passwords in the mock database."""
        for userid, user_data in self.users.items():
            password = user_data.get("password")
            # Check if password is already hashed (starts with $2b$)
            if isinstance(password, str) and not password.startswith("$2b$"):
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                user_data["password_hash"] = hashed.decode('utf-8')
                # Remove plain password after hashing
                del user_data["password"]

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a plain password against its hash.

        Args:
            plain_password: Plain text password
            hashed_password: Bcrypt hashed password

        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception as e:
            print(f"Password verification error: {e}")
            return False

    def authenticate_user(self, userid: str, password: str, role_id: int) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with userid, password, and role.

        Args:
            userid: User ID
            password: Plain text password
            role_id: Role ID (1=Admin, 2=User, 3=Guest)

        Returns:
            Dict with user info if authentication succeeds, None otherwise
        """
        # Check if user exists
        user = self.users.get(userid)
        if not user:
            return None

        # Check if user is active
        if not user.get("is_active", False):
            return None

        # Verify role matches
        if user.get("role_id") != role_id:
            return None

        # Verify password
        password_hash = user.get("password_hash")
        if not password_hash or not self.verify_password(password, password_hash):
            return None

        # Return user info (without password)
        return {
            "id": user["id"],
            "userid": user["userid"],
            "role_id": user["role_id"],
            "role": self.roles.get(user["role_id"], "Unknown"),
            "created_at": user["created_at"]
        }

    def create_access_token(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create JWT access token with 1-hour expiry.

        Args:
            user_data: Dictionary containing user information

        Returns:
            Dict with token, expiry time, and user info
        """
        # Set token expiry to 1 hour from now
        expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
        expires_in = int(expire.timestamp() * 1000)  # Convert to milliseconds for JS

        # Create JWT payload
        payload = {
            "sub": user_data["userid"],  # Subject (user identifier)
            "user_id": user_data["id"],
            "userid": user_data["userid"],
            "role": user_data["role"],
            "role_id": user_data["role_id"],
            "exp": expire,  # Expiration time
            "iat": datetime.now(timezone.utc),  # Issued at
            "type": "access"  # Token type
        }

        # Sign and encode token
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        return {
            "token": token,
            "expires_in": expires_in,
            "token_type": "Bearer",
            "user": {
                "id": user_data["id"],
                "userid": user_data["userid"],
                "role": user_data["role"],
                "role_id": user_data["role_id"]
            }
        }

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token and return payload if valid.

        Args:
            token: JWT token string

        Returns:
            Dict with token payload if valid, None otherwise
        """
        # Check if token is blacklisted (logged out)
        if token in self.token_blacklist:
            return None

        try:
            # Decode and verify token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            # Verify token hasn't expired (jwt.decode already checks this)
            # Additional check to ensure user still exists and is active
            userid = payload.get("userid")
            user = self.users.get(userid)

            if not user or not user.get("is_active", False):
                return None

            return payload

        except jwt.ExpiredSignatureError:
            # Token has expired
            return None
        except jwt.InvalidTokenError:
            # Token is invalid
            return None
        except Exception as e:
            print(f"Token verification error: {e}")
            return None

    def blacklist_token(self, token: str):
        """
        Add token to blacklist (logout).
        In production, use Redis with TTL equal to token expiry.

        Args:
            token: JWT token to blacklist
        """
        self.token_blacklist.add(token)

    def get_user_by_userid(self, userid: str) -> Optional[Dict[str, Any]]:
        """
        Get user information by userid (without password).

        Args:
            userid: User ID

        Returns:
            Dict with user info if found, None otherwise
        """
        user = self.users.get(userid)
        if not user:
            return None

        return {
            "id": user["id"],
            "userid": user["userid"],
            "role_id": user["role_id"],
            "role": self.roles.get(user["role_id"], "Unknown"),
            "created_at": user["created_at"],
            "is_active": user.get("is_active", False)
        }


# Global instance
auth_db = AuthDatabase()


# Helper functions for easy import
def authenticate_user(userid: str, password: str, role_id: int) -> Optional[Dict[str, Any]]:
    """Authenticate user and return user data if successful."""
    return auth_db.authenticate_user(userid, password, role_id)


def create_access_token(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create JWT access token for authenticated user."""
    return auth_db.create_access_token(user_data)


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token and return payload if valid."""
    return auth_db.verify_token(token)


def blacklist_token(token: str):
    """Add token to blacklist (logout)."""
    auth_db.blacklist_token(token)


def get_user_by_userid(userid: str) -> Optional[Dict[str, Any]]:
    """Get user information by userid."""
    return auth_db.get_user_by_userid(userid)
