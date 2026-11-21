"""users.name 忽略大小写唯一索引

Revision ID: 0005_user_name_unique
Revises: 0004_email_verification_codes
Create Date: 2026-11-21 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0005_user_name_unique'
down_revision: Union[str, Sequence[str], None] = '0004_email_verification_codes'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NAME_MAX = 128
INDEX_NAME = 'uq_users_name_lower'


def _dedupe_names(connection) -> None:
    """建索引前清理历史重名（忽略大小写）与空用户名，避免升级失败。"""
    rows = connection.execute(
        sa.text('SELECT id, email, name FROM users ORDER BY id')
    ).fetchall()
    seen: set[str] = set()
    for user_id, email, name in rows:
        base = (name or '').strip()[:NAME_MAX]
        if not base:
            base = (email or '').split('@')[0][:NAME_MAX] or 'user'
        candidate = base
        index = 1
        while candidate.lower() in seen:
            index += 1
            suffix = f'-{index}'
            candidate = base[: NAME_MAX - len(suffix)] + suffix
        seen.add(candidate.lower())
        if candidate != name:
            connection.execute(
                sa.text('UPDATE users SET name = :name WHERE id = :id'),
                {'name': candidate, 'id': user_id},
            )


def upgrade() -> None:
    """先去重，再建立基于 lower(name) 的唯一索引。"""
    _dedupe_names(op.get_bind())
    op.create_index(INDEX_NAME, 'users', [sa.text('lower(name)')], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(INDEX_NAME, table_name='users')
