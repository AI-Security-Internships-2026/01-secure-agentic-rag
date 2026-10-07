from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

from secure_rag.audit.events import emit
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
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    emit(
        "auth.token.minted",
        user_id=user_id,
        tenant_id=tenant_id,
        extra={"exp": payload["exp"], "roles": payload["roles"]},
    )
    return token


def _token_failed(reason: str, token: str | None = None) -> None:
    jti = None
    if token:
        try:
            jti = jwt.get_unverified_claims(token).get("jti")
        except JWTError:
            jti = None
    emit("auth.token.failed", extra={"error_reason": reason, "jti": str(jti) if jti is not None else None})


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
        _token_failed(f"{type(exc).__name__}: {exc}", token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token") from exc
    user_id = str(payload.get("sub") or "")
    if not user_id:
        _token_failed("token missing subject", token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token missing subject")
    return Principal(user_id=user_id, tenant_id=str(payload.get("tenant") or "default"), roles=list(payload.get("roles") or []))


def get_principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        _token_failed("missing bearer token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    return decode_token(credentials.credentials)
