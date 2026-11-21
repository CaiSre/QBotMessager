"""init

Revision ID: 0001_init
Revises:
Create Date: 2026-11-21 13:12:23.179856

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision: str = '0001_init'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 建表顺序按外键依赖排列：users 先于所有引用它的表。
    op.create_table('system_settings',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('key', name=op.f('pk_system_settings'))
    )
    op.create_table('users',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=True),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_table('oauth_providers',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('display_name', sa.String(length=128), nullable=False),
    sa.Column('client_id', sa.String(length=255), nullable=False),
    sa.Column('client_secret', sa.Text(), nullable=False),
    sa.Column('authorization_url', sa.String(length=512), nullable=False),
    sa.Column('token_url', sa.String(length=512), nullable=False),
    sa.Column('userinfo_url', sa.String(length=512), nullable=False),
    sa.Column('scopes', sa.String(length=255), nullable=False),
    sa.Column('email_field', sa.String(length=64), nullable=False),
    sa.Column('id_field', sa.String(length=64), nullable=False),
    sa.Column('name_field', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_oauth_providers')),
    sa.UniqueConstraint('key', name=op.f('uq_oauth_providers_key'))
    )
    op.create_table('bot_profiles',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.BigInteger(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('qq_appid', sa.String(length=128), nullable=False),
    sa.Column('qq_app_secret', sa.Text(), nullable=False),
    sa.Column('qq_host', sa.String(length=255), nullable=False),
    sa.Column('default_openids', sa.JSON(), nullable=False),
    sa.Column('default_group_openid', sa.String(length=128), nullable=True),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], name=op.f('fk_bot_profiles_owner_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_bot_profiles'))
    )
    op.create_index(op.f('ix_bot_profiles_owner_user_id'), 'bot_profiles', ['owner_user_id'], unique=False)
    op.create_table('channels',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('bot_profile_id', sa.BigInteger(), nullable=False),
    sa.Column('platform', sa.String(length=32), nullable=False),
    sa.Column('webhook_token', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('extra', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['bot_profile_id'], ['bot_profiles.id'], name=op.f('fk_channels_bot_profile_id_bot_profiles')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_channels')),
    sa.UniqueConstraint('webhook_token', name=op.f('uq_channels_webhook_token'))
    )
    op.create_index(op.f('ix_channels_bot_profile_id'), 'channels', ['bot_profile_id'], unique=False)
    op.create_table('env_configs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.BigInteger(), nullable=False),
    sa.Column('key', sa.String(length=128), nullable=False),
    sa.Column('value', sa.Text(), nullable=True),
    sa.Column('value_enc', sa.Text(), nullable=True),
    sa.Column('is_secret', sa.Boolean(), nullable=False),
    sa.Column('description', sa.String(length=255), nullable=False),
    sa.Column('updated_by', sa.BigInteger(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], name=op.f('fk_env_configs_owner_user_id_users')),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], name=op.f('fk_env_configs_updated_by_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_env_configs')),
    sa.UniqueConstraint('owner_user_id', 'key', name='uq_env_owner_key')
    )
    op.create_table('invite_codes',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('code', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('max_uses', sa.Integer(), nullable=False),
    sa.Column('used_count', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.BigInteger(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_invite_codes_created_by_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_invite_codes')),
    sa.UniqueConstraint('code', name=op.f('uq_invite_codes_code'))
    )
    op.create_table('admin_audit_logs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('actor_user_id', sa.BigInteger(), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target_type', sa.String(length=64), nullable=True),
    sa.Column('target_id', sa.String(length=128), nullable=True),
    sa.Column('detail', sa.JSON(), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], name=op.f('fk_admin_audit_logs_actor_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_admin_audit_logs'))
    )
    op.create_index('ix_audit_actor_created', 'admin_audit_logs', ['actor_user_id', 'created_at'], unique=False)
    op.create_table('auth_identities',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.BigInteger(), nullable=False),
    sa.Column('provider', sa.String(length=64), nullable=False),
    sa.Column('provider_user_id', sa.String(length=255), nullable=False),
    sa.Column('provider_login', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_auth_identities_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_auth_identities')),
    sa.UniqueConstraint('provider', 'provider_user_id', name='uq_identity_provider_uid')
    )
    op.create_index(op.f('ix_auth_identities_user_id'), 'auth_identities', ['user_id'], unique=False)
    op.create_table('sessions',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.BigInteger(), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=255), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_sessions_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_sessions')),
    sa.UniqueConstraint('token_hash', name=op.f('uq_sessions_token_hash'))
    )
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('webauthn_credentials',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.BigInteger(), nullable=False),
    sa.Column('credential_id', sa.LargeBinary().with_variant(mysql.VARBINARY(255), 'mysql'), nullable=False),
    sa.Column('public_key', sa.LargeBinary(), nullable=False),
    sa.Column('sign_count', sa.BigInteger(), nullable=False),
    sa.Column('aaguid', sa.String(length=64), nullable=True),
    sa.Column('transports', sa.JSON(), nullable=True),
    sa.Column('device_type', sa.String(length=32), nullable=True),
    sa.Column('backed_up', sa.Boolean(), nullable=False),
    sa.Column('label', sa.String(length=64), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_webauthn_credentials_user_id_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_webauthn_credentials')),
    sa.UniqueConstraint('credential_id', name=op.f('uq_webauthn_credentials_credential_id'))
    )
    op.create_index(op.f('ix_webauthn_credentials_user_id'), 'webauthn_credentials', ['user_id'], unique=False)
    op.create_table('push_logs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('owner_user_id', sa.BigInteger(), nullable=False),
    sa.Column('channel_id', sa.BigInteger(), nullable=True),
    sa.Column('bot_profile_id', sa.BigInteger(), nullable=True),
    sa.Column('platform', sa.String(length=32), nullable=False),
    sa.Column('source_msgtype', sa.String(length=32), nullable=False),
    sa.Column('target', sa.String(length=255), nullable=False),
    sa.Column('qq_msg_type', sa.Integer(), nullable=True),
    sa.Column('content_preview', sa.Text(), nullable=False),
    sa.Column('content_len', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('duration_ms', sa.Float(), nullable=False),
    sa.Column('request_id', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['owner_user_id'], ['users.id'], name=op.f('fk_push_logs_owner_user_id_users')),
    sa.ForeignKeyConstraint(['bot_profile_id'], ['bot_profiles.id'], name=op.f('fk_push_logs_bot_profile_id_bot_profiles'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['channel_id'], ['channels.id'], name=op.f('fk_push_logs_channel_id_channels'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_push_logs'))
    )
    op.create_index('ix_push_logs_owner_created', 'push_logs', ['owner_user_id', 'created_at'], unique=False)
    op.create_index('ix_push_logs_created', 'push_logs', ['created_at'], unique=False)
    op.create_index('ix_push_logs_status', 'push_logs', ['status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_push_logs_status', table_name='push_logs')
    op.drop_index('ix_push_logs_created', table_name='push_logs')
    op.drop_index('ix_push_logs_owner_created', table_name='push_logs')
    op.drop_table('push_logs')
    op.drop_index(op.f('ix_webauthn_credentials_user_id'), table_name='webauthn_credentials')
    op.drop_table('webauthn_credentials')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_table('sessions')
    op.drop_index(op.f('ix_auth_identities_user_id'), table_name='auth_identities')
    op.drop_table('auth_identities')
    op.drop_index('ix_audit_actor_created', table_name='admin_audit_logs')
    op.drop_table('admin_audit_logs')
    op.drop_table('invite_codes')
    op.drop_table('env_configs')
    op.drop_index(op.f('ix_channels_bot_profile_id'), table_name='channels')
    op.drop_table('channels')
    op.drop_index(op.f('ix_bot_profiles_owner_user_id'), table_name='bot_profiles')
    op.drop_table('bot_profiles')
    op.drop_table('oauth_providers')
    op.drop_table('users')
    op.drop_table('system_settings')
