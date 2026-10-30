# SPDX-FileCopyrightText: 2026 Subramania Raja <dhanpraja231@gmail.com>
# SPDX-FileCopyrightText: 2026 Hari Srinivasan <harisrini21@gmail.com>
# SPDX-FileCopyrightText: 2026 Lokesh Selvam <lokeshselvam7025@gmail.com>
# SPDX-FileCopyrightText: 2026 Shaan Narendran <shaannaren06@gmail.com>
# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, field_validator

from models.user import UserRole
from services.registry_namespace import validate_namespace


def _normalize_email(v: str) -> str:
    """Lowercase and strip whitespace so email lookups are case-insensitive."""
    return v.strip().lower() if isinstance(v, str) else v


def _validate_username(v: str | None) -> str | None:
    if v is None:
        return None
    return validate_namespace(v)


class InitRequest(BaseModel):
    email: EmailStr
    name: str
    username: str | None = None
    password: str | None = None

    @field_validator("email", mode="before")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return _normalize_email(v)

    @field_validator("username", mode="before")
    @classmethod
    def _validate_un(cls, v: str | None) -> str | None:
        return _validate_username(v)


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return v.strip().lower() if isinstance(v, str) else v


class RegisterRequest(BaseModel):
    email: EmailStr
    name: str
    username: str | None = None
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return _normalize_email(v)

    @field_validator("username", mode="before")
    @classmethod
    def _validate_un(cls, v: str | None) -> str | None:
        return _validate_username(v)


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    name: str
    role: UserRole
    avatar_url: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class InitResponse(BaseModel):
    user: UserResponse
    access_token: str
    refresh_token: str
    expires_in: int


class CodeExchangeRequest(BaseModel):
    code: str


class TokenRequest(BaseModel):
    email: str
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return v.strip().lower() if isinstance(v, str) else v


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    # Only populated for a centrally verified/issued mobile refresh pair.
    client_id: Literal["observal-mobile"] | None = None
    audience: Literal["observal-mobile-activity-v1"] | None = None
    scope: Literal["mobile:read"] | None = None


class MobileCredentialProof(BaseModel):
    """Proof from the authenticated server, never from an unverified JWT decode."""

    token_type: Literal["bearer"] = "bearer"
    client_id: Literal["observal-mobile"] = "observal-mobile"
    audience: Literal["observal-mobile-activity-v1"] = "observal-mobile-activity-v1"
    scope: Literal["mobile:read"] = "mobile:read"
    subject_id: uuid.UUID
    device_id: str


class RefreshRequest(BaseModel):
    refresh_token: str


class RevokeRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _validate_new(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UsernameUpdateRequest(BaseModel):
    username: str

    @field_validator("username", mode="before")
    @classmethod
    def _validate_un(cls, v: str) -> str:
        result = _validate_username(v)
        if result is None:
            raise ValueError("Username is required")
        return result


# ── Device Authorization Grant (RFC 8628) ─────────────────


class DeviceAuthRequest(BaseModel):
    client_id: str | None = None
    sso: bool = False
    provider: str | None = None


class DeviceAuthResponse(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    # Server-approved initial browser origin; never an IdP redirect allowlist.
    verification_origins: list[str] | None = None
    expires_in: int
    interval: int


class DeviceTokenRequest(BaseModel):
    device_code: str
    grant_type: str


class DeviceConfirmRequest(BaseModel):
    user_code: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None
