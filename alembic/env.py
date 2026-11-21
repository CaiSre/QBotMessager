"""Alembic 环境：连接串优先取 alembic.ini，其次取 MYSQL_URL。

异步驱动（asyncmy/aiomysql/aiosqlite）走异步引擎，其余走同步引擎，
便于用本地 SQLite 生成或校验迁移。
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from server.config import get_settings
from server.db import models  # noqa: F401 - 让 metadata 收集到全部表
from server.db.base import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

_url = config.get_main_option("sqlalchemy.url") or get_settings().mysql_url
if not _url:
    raise RuntimeError("未配置数据库连接：请设置 MYSQL_URL 或 alembic.ini 的 sqlalchemy.url")
# configparser 会把 % 当插值符，这里做转义
config.set_main_option("sqlalchemy.url", _url.replace("%", "%%"))

_ASYNC_DRIVERS = ("+asyncmy", "+aiomysql", "+aiosqlite", "+asyncpg")


def _is_async(url: str) -> bool:
    return any(marker in url for marker in _ASYNC_DRIVERS)


def run_migrations_offline() -> None:
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    if _is_async(_url):
        asyncio.run(run_async_migrations())
        return
    connectable = create_engine(_url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        do_run_migrations(connection)
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
