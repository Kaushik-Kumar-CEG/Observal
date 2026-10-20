# SPDX-FileCopyrightText: 2026 Kaushik <kaushikrjpm10@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Record approvals at the statement, never the transaction start.

Old approval events may predate their real transition if the reviewer began a
transaction before the Pi event. The actual historical transition time cannot
be recovered: quarantine all prior mobile publication timestamps so earlier
source cannot acquire a retroactive positive. The existing approval UPDATE
triggers invalidate affected mobile listing epochs and zero-evidence scopes.

Revision ID: 069_mobile_publication_clock
Revises: 068_mobile_erasure_epoch_guard
"""

from alembic import op

revision = "069_mobile_publication_clock"
down_revision = "068_mobile_erasure_epoch_guard"
branch_labels = None
depends_on = None


def upgrade():
    # Publication triggers omit recorded_at, so the column default is the
    # single write point for both component and agent-version transitions.
    # clock_timestamp() advances even in a transaction opened long before the
    # review update, unlike now()/transaction_timestamp().
    op.execute("ALTER TABLE mobile_publication_events ALTER COLUMN recorded_at SET DEFAULT clock_timestamp()")
    # Do not guess when historical reviews actually committed. Their old
    # timestamps cannot qualify earlier activity; newer sessions need to
    # establish fresh, independently qualified source and event time.
    op.execute("UPDATE mobile_publication_events SET recorded_at=clock_timestamp()")


def downgrade():
    raise RuntimeError("Cannot restore untrusted historic mobile publication timestamps; restore an isolated backup")
