"""Authentication, password hashing, and stateless token security for I-ITSM."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Optional

from .enums import Role
from .exceptions import AuthenticationFailed, UnauthorizedOperation
from .models import User


class PasswordHasher:
    """PBKDF2-HMAC-SHA256 password hashing with random salt and constant-time verification."""

    @staticmethod
    def hash_password(password: str) -> str:
        if not password:
            raise ValueError("Password cannot be empty")
        salt = secrets.token_bytes(16)
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        hash_b64 = base64.b64encode(dk).decode("utf-8")
        return f"pbkdf2_sha256$100000${salt_b64}${hash_b64}"

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        if not password or not hashed or not hashed.startswith("pbkdf2_sha256$"):
            return False
        try:
            parts = hashed.split("$")
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            expected = base64.b64decode(parts[3])
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(expected, actual)
        except Exception:
            return False


_PROCESS_SECRET = secrets.token_urlsafe(32)


class TokenManager:
    """Stateless HMAC-SHA256 signed bearer token provider."""

    def __init__(self, secret_key: Optional[str] = None):
        import os
        key = secret_key or os.getenv("IITSM_SECRET_KEY") or _PROCESS_SECRET
        self._secret = key.encode("utf-8")

    def create_token(self, user: User, expires_in_seconds: int = 86400) -> str:
        payload = {
            "sub": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role.value,
            "exp": int(time.time()) + expires_in_seconds
        }
        raw_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(raw_json).decode("utf-8").rstrip("=")
        sig = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
        return f"{payload_b64}.{sig_b64}"

    def decode_token(self, token: str) -> dict:
        if not token or "." not in token:
            raise AuthenticationFailed("Malformed or missing bearer token")
        payload_b64, sig_b64 = token.split(".", 1)
        expected_sig = hmac.new(self._secret, payload_b64.encode("utf-8"), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected_sig).decode("utf-8").rstrip("=")
        if not hmac.compare_digest(sig_b64, expected_b64):
            raise AuthenticationFailed("Invalid token signature")
        # Pad payload base64
        rem = len(payload_b64) % 4
        padded = payload_b64 + ("=" * (4 - rem) if rem else "")
        data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if data.get("exp", 0) <= int(time.time()):
            raise AuthenticationFailed("Token has expired")
        return data


class AuthService:
    """Handles credential verification, user sessions, and permission checks."""

    def __init__(self, user_repo, token_manager: Optional[TokenManager] = None):
        self.user_repo = user_repo
        self.tokens = token_manager or TokenManager()

    def login(self, user_id_or_email: str, password: str) -> dict:
        user = None
        for u in self.user_repo.all():
            if u.id.lower() == user_id_or_email.lower() or u.email.lower() == user_id_or_email.lower():
                user = u
                break
        if not user:
            raise AuthenticationFailed("Invalid credentials")

        pwd_hash = getattr(user, "password_hash", "")
        if not PasswordHasher.verify_password(password, pwd_hash):
            raise AuthenticationFailed("Invalid credentials")

        token = self.tokens.create_token(user)
        return {
            "token": token,
            "user_id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role.value
        }

    def authenticate(self, user_id_or_email: str, password: str):
        res = self.login(user_id_or_email, password)
        user = self.user_repo.get(res["user_id"])
        return user, res["token"]

    def authenticate_token(self, token: str) -> User:
        data = self.tokens.decode_token(token)
        return self.user_repo.get(data["sub"])

    def check_permission(self, user: User, action: str):
        if not user.can(action):
            raise UnauthorizedOperation(f"User {user.id} ({user.role.value}) cannot perform {action}")
