# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""A public first-user claim is not an authorized isolated super-admin."""

import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.exc import IntegrityError

from services.first_admin import provision_first_super_admin


@pytest.mark.asyncio
async def test_first_admin_rejects_nonreserved_identity_before_db_access():
    db = AsyncMock()
    for email in ("actual-person@example.org", "author@real.example@candidate.test", "author @candidate.test"):
        with pytest.raises(ValueError, match="reserved-domain"):
            await provision_first_super_admin(db, email, "Valid1!Password")
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_first_admin_rejects_any_existing_user_including_demo():
    db = AsyncMock()
    db.scalar.return_value = 1
    with pytest.raises(RuntimeError, match="existing user"):
        await provision_first_super_admin(db, "author@candidate.test", "Valid1!Password")
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_first_admin_persists_non_demo_account_and_audit_together(monkeypatch):
    monkeypatch.setattr("services.first_admin.generate_unique_username", AsyncMock(return_value="candidate_author"))
    db = AsyncMock()
    db.scalar.return_value = 0
    identifier = uuid.uuid4()

    async def flush():
        db.add.call_args.args[0].id = identifier

    db.flush.side_effect = flush
    assert await provision_first_super_admin(db, "Author@candidate.invalid", "Valid1!Password") == identifier
    account = db.add.call_args.args[0]
    assert account.role.value == "super_admin" and account.email == "author@candidate.invalid" and not account.is_demo
    assert account.verify_password("Valid1!Password")
    assert db.execute.await_count == 3  # advisory + table lock, then durable receipt
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_first_admin_audit_failure_does_not_commit_user(monkeypatch):
    monkeypatch.setattr("services.first_admin.generate_unique_username", AsyncMock(return_value="candidate_author"))
    db = AsyncMock()
    db.scalar.return_value = 0
    db.execute.side_effect = [None, None, IntegrityError("receipt", {}, Exception("audit rejected"))]
    with pytest.raises(RuntimeError, match="First-user claim lost"):
        await provision_first_super_admin(db, "author@candidate.test", "Valid1!Password")
    db.rollback.assert_awaited_once()
    db.commit.assert_not_awaited()
