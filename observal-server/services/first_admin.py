# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Local, one-shot first super-admin for an empty isolated candidate.

Run only inside the pinned API image with an authorized interactive container
session. No HTTP route, bootstrap secret, password argument, or demo fallback.
Any pre-existing user (including a demo account) is an explicit stop condition.
"""

import asyncio
import getpass
import re
import sys
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session
from models.user import User, UserRole
from services.username_generator import generate_unique_username


async def lock_first_user(db: AsyncSession) -> None:
    """Serialize named initializers and block every concurrent user insert.

    Table lock also covers registration, SSO JIT and other writers which do not
    take the advisory lock. The subsequent count runs after those transactions
    commit or waits until this first-user transaction has committed.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended('observal-first-user', 0))"))
    await db.execute(text("LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE"))


def _reserved_email(email: str) -> bool:
    local, separator, domain = email.rpartition("@")
    return bool(
        separator
        and re.fullmatch(r"[a-z0-9][a-z0-9._+\-]*", local)
        and ".." not in local
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+", domain)
        and domain.endswith((".test", ".invalid"))
    )


async def provision_first_super_admin(db: AsyncSession, email: str, password: str) -> UUID:
    """Create exactly one non-demo super-admin and its durable receipt atomically."""
    email = email.strip().lower()
    if not _reserved_email(email):
        raise ValueError("A new reserved-domain .test or .invalid address is required")
    # Reuse the existing password policy without implementing a weaker one.
    from api.routes.auth import _validate_password_strength

    _validate_password_strength(password)
    await lock_first_user(db)
    if await db.scalar(select(func.count()).select_from(User)):
        raise RuntimeError("Refusing to provision: candidate contains an existing user; inspect before any mutation")
    user = User(
        email=email,
        username=await generate_unique_username(email, db),
        name="Isolated mobile test Author",
        role=UserRole.super_admin,
    )
    user.set_password(password)
    db.add(user)
    try:
        await db.flush()
        await db.execute(
            text("INSERT INTO first_admin_provision_audit (actor_id,action) VALUES (:actor,:action)"),
            {"actor": user.id, "action": "local_first_super_admin"},
        )
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise RuntimeError("First-user claim lost; stop and inspect candidate users") from exc
    return user.id


def main() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive candidate-container TTY required; never pass credentials as arguments", file=sys.stderr)
        return 1
    email = input("New disposable super-admin email (.test/.invalid): ").strip()
    if input("Type 'provision isolated super-admin' to confirm: ").strip() != "provision isolated super-admin":
        print("Provisioning cancelled")
        return 1
    password = getpass.getpass("New password (not echoed): ")
    if password != getpass.getpass("Confirm password (not echoed): "):
        print("Passwords differ", file=sys.stderr)
        return 1
    try:

        async def run() -> UUID:
            async with async_session() as db:
                return await provision_first_super_admin(db, email, password)

        identifier = asyncio.run(run())
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Isolated test super-admin provisioned with durable receipt: {identifier}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
