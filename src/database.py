import json
import aiosqlite

DB_NAME = "database.db"

db_conn = None


async def get_db():
    if db_conn is None:
        raise RuntimeError("Banco de dados não foi inicializado.")
    return db_conn


async def init_db():
    global db_conn
    db_conn = await aiosqlite.connect(DB_NAME)
    
    await db_conn.execute("PRAGMA journal_mode = WAL;")
    await db_conn.execute("PRAGMA synchronous = NORMAL;")

    await db_conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recent_cve (
            cve_id TEXT PRIMARY KEY,
            last_modified TEXT,
            data TEXT
        )
        """
    )

    async with db_conn.execute("PRAGMA table_info(tags_sha256)") as cursor:
        table_exists = bool(await cursor.fetchall())
    if table_exists:
        async with db_conn.execute("PRAGMA table_info(tags_sha256)") as cursor:
            columns = {row[1] for row in await cursor.fetchall()}
    else:
        columns = set()

    if table_exists and "url" not in columns:
        await db_conn.execute("ALTER TABLE tags_sha256 RENAME TO tags_sha256_old")

    await db_conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tags_sha256 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL,
            url TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tag, url, sha256)
        )
        """
    )

    if table_exists and "url" not in columns:
        await db_conn.execute(
            """
            INSERT INTO tags_sha256 (id, tag, url, sha256, created_at)
            SELECT id, tag, '', sha256, created_at
            FROM tags_sha256_old
            """
        )
        await db_conn.execute("DROP TABLE tags_sha256_old")

    await db_conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tags_sha256_tag ON tags_sha256(tag);"
    )
    await db_conn.commit()


async def close_db():
    global db_conn
    if db_conn:
        await db_conn.close()
        db_conn = None



async def add_tag_sha256(tag, url, sha256):
    db = await get_db()
    cursor = await db.execute(
        """
        INSERT INTO tags_sha256 (tag, url, sha256)
        VALUES (?, ?, ?)
        ON CONFLICT(tag, url, sha256) DO NOTHING
        """,
        (tag, url, sha256.lower()),
    )
    await db.commit()
    return cursor.rowcount > 0


async def get_all_by_tag(tag):
    db = await get_db()
    async with db.execute(
        "SELECT url, sha256 FROM tags_sha256 WHERE tag = ? ORDER BY id", (tag,)
    ) as cursor:
        return await cursor.fetchall()

async def post_many_cves(cve_list):
    db = await get_db()
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


async def get_cve_by_id(cve_id):
    db = await get_db()
    async with db.execute(
        "SELECT data FROM recent_cve WHERE cve_id = ?", (cve_id,)
    ) as cursor:
        row = await cursor.fetchone()
        return json.loads(row[0]) if row else None


async def get_recent_cve(limit=100):
    db = await get_db()
    async with db.execute(
        "SELECT data FROM recent_cve ORDER BY last_modified DESC LIMIT ?",
        (limit,),
    ) as cursor:
        rows = await cursor.fetchall()
        return [json.loads(row[0]) for row in rows]

async def get_cves_by_package_name(package_name):
    db = await get_db()
    
    term = f"%{package_name.lower()}%"
    
    query = """
        SELECT DISTINCT c.cve_id, c.last_modified, c.data
        FROM recent_cve c
        WHERE LOWER(c.data) LIKE ?
           OR EXISTS (
               SELECT 1 
               FROM json_each(c.data, '$.affected') AS aff,
                    json_each(aff.value, '$.affectedData') AS aff_data
               WHERE LOWER(json_extract(aff_data.value, '$.packageName')) LIKE ?
                  OR LOWER(json_extract(aff_data.value, '$.product')) LIKE ?
                  OR LOWER(json_extract(aff_data.value, '$.vendor')) LIKE ?
           )
    """
    
    async with db.execute(query, (term, term, term, term)) as cursor:
        rows = await cursor.fetchall()
        return [
            {
                "cve_id": row[0],
                "last_modified": row[1],
                "data": json.loads(row[2])
            }
            for row in rows
        ]

