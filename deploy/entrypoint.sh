#!/bin/sh
set -eu

: "${MYSQL_URL:?MYSQL_URL 未设置，无法执行数据库迁移}"

# 只等待数据库可连接；迁移本身若失败（如建表冲突）直接退出，避免重复执行 DDL。
attempt=0
until python - "$MYSQL_URL" <<'PY'
import asyncio
import sys

from sqlalchemy.ext.asyncio import create_async_engine


async def main() -> None:
    engine = create_async_engine(sys.argv[1])
    try:
        async with engine.connect():
            pass
    finally:
        await engine.dispose()


asyncio.run(main())
PY
do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "数据库未就绪，已重试 ${attempt} 次" >&2
        exit 1
    fi
    echo "数据库未就绪，2 秒后重试（${attempt}/30）" >&2
    sleep 2
done

alembic upgrade head

exec "$@"
