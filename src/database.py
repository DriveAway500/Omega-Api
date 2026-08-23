import json
import aiosqlite

DB_NAME = "cve_data.db"


async def init_db():
    async with aiosqlite.connect(DB_NAME) as db:
        await db.execute("PRAGMA synchronous = OFF;")
        await db.execute("PRAGMA journal_mode = MEMORY;")

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS recent_cve (
                cve_id TEXT PRIMARY KEY,
                last_modified TEXT,
                data TEXT
            )
            """
        )
        await db.commit()


async def post_many_cves(cve_list: list[tuple[str, str, str]]):
    async with aiosqlite.connect(DB_NAME) as db:
        await db.execute("PRAGMA synchronous = OFF;")
        await db.executemany(
            """
            INSERT INTO recent_cve (cve_id, last_modified, data)
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                last_modified = excluded.last_modified,
                data = excluded.data
            """,
            cve_list,
        )
        await db.commit()


async def get_cve_by_id(cve_id: str) -> dict | None:
    async with aiosqlite.connect(DB_NAME) as db:
        async with db.execute(
            "SELECT data FROM recent_cve WHERE cve_id = ?", (cve_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None


async def get_recent_cve(limit: int = 100) -> list[dict]:
    async with aiosqlite.connect(DB_NAME) as db:
        async with db.execute(
            "SELECT data FROM recent_cve ORDER BY last_modified DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [json.loads(row[0]) for row in rows]