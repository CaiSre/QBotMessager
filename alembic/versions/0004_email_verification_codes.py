"""create email_verification_codes

Revision ID: 0004_email_verification_codes
Revises: 0003_drop_env_configs
Create Date: 2026-11-21 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0004_email_verification_codes'
down_revision: Union[str, Sequence[str], None] = '0003_drop_env_configs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """邮箱验证码表。"""
    op.create_table(
        'email_verification_codes',
        sa.Column(
            'id',
            sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('purpose', sa.String(length=32), nullable=False),
        sa.Column('code_hash', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_email_verification_codes')),
    )
    op.create_index(
        op.f('ix_email_verification_codes_email'),
        'email_verification_codes',
        ['email'],
        unique=False,
    )
    op.create_index(
        op.f('ix_email_verification_codes_purpose'),
        'email_verification_codes',
        ['purpose'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        op.f('ix_email_verification_codes_purpose'),
        table_name='email_verification_codes',
    )
    op.drop_index(
        op.f('ix_email_verification_codes_email'),
        table_name='email_verification_codes',
    )
    op.drop_table('email_verification_codes')
