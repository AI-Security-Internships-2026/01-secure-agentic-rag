from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from secure_rag.settings import get_settings

bearer = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    user_id: str
    tenant_id: str = "default"
    roles: list[str] = Field(default_factory=list)


def create_token(user_id: str, tenant_id: str = "default", roles: list[str] | None = None) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "tenant": tenant_id,
        "roles": roles or [],
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Principal:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token") from exc
    user_id = str(payload.get("sub") or "")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token missing subject")
    return Principal(user_id=user_id, tenant_id=str(payload.get("tenant") or "default"), roles=list(payload.get("roles") or []))


def get_principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return decode_token(credentials.credentials)


def _site_key_matches(provided: str, expected: str) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(
        hashlib.sha256(provided.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )


def get_chat_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Principal:
    """JWT for logged-in users, or a configured site key for the website widget."""
    if credentials is not None and credentials.scheme.lower() == "bearer":
        return decode_token(credentials.credentials)
    settings = get_settings()
    provided = request.headers.get("x-site-key") or ""
    if settings.widget_enabled and _site_key_matches(provided, settings.widget_site_key):
        return Principal(
            user_id=settings.widget_user_id,
            tenant_id=settings.widget_tenant_id,
            roles=["widget"],
        )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token or site key")
