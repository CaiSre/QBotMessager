"""drop env_configs

Revision ID: 0003_drop_env_configs
Revises: 0002_email_verified
Create Date: 2026-11-21 16:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0003_drop_env_configs'
down_revision: Union[str, Sequence[str], None] = '0002_email_verified'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """删除仅作存储、不参与运行的旧环境配置表。"""
    op.drop_table('env_configs')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'env_configs',
        sa.Column(
            'id',
            sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column('owner_user_id', sa.BigInteger(), nullable=False),
        sa.Column('key', sa.String(length=128), nullable=False),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('value_enc', sa.Text(), nullable=True),
        sa.Column('is_secret', sa.Boolean(), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.Column('updated_by', sa.BigInteger(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['owner_user_id'], ['users.id'], name=op.f('fk_env_configs_owner_user_id_users')
        ),
        sa.ForeignKeyConstraint(
            ['updated_by'], ['users.id'], name=op.f('fk_env_configs_updated_by_users')
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_env_configs')),
        sa.UniqueConstraint('owner_user_id', 'key', name='uq_env_owner_key'),
    )
