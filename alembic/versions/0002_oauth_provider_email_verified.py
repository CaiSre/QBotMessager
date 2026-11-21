"""oauth provider email_verified

Revision ID: 0002_email_verified
Revises: 0001_init
Create Date: 2026-11-21 15:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_email_verified'
down_revision: Union[str, Sequence[str], None] = '0001_init'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # MySQL 不允许给已有表直接加 NOT NULL 且无默认值的列，先带默认值再加
    op.add_column(
        'oauth_providers',
        sa.Column(
            'email_verified',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('oauth_providers', 'email_verified')
