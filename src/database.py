import json
import re
import aiosqlite

DB_NAME = "database.db"

db_conn: aiosqlite.Connection | None = None


async def get_db() -> aiosqlite.Connection:
    """Retorna a conexão ativa do banco de dados."""
    if db_conn is None:
        raise RuntimeError("Banco de dados não foi inicializado.")
    return db_conn


async def init_db():
    """Inicializa a conexão e cria o schema do banco."""
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

    await db_conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tags_sha256 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tag, sha256)
        )
        """
    )

    await db_conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tags_sha256_tag ON tags_sha256(tag);"
    )
    await db_conn.commit()


async def close_db():
    global db_conn
    if db_conn:
        await db_conn.close()
        db_conn = None



async def add_tag_sha256(tag: str, sha256: str) -> bool:
    """
    Insere uma tag e seu SHA-256. 
    Se a combinação já existir, ignora sem quebrar a execução.
    """
    db = await get_db()
    cursor = await db.execute(
        """
        INSERT INTO tags_sha256 (tag, sha256) 
        VALUES (?, ?)
        ON CONFLICT(tag, sha256) DO NOTHING
        """,
        (tag, sha256.lower()),
    )
    await db.commit()
    return cursor.rowcount > 0


async def get_all_by_tag(tag: str) -> list[tuple[str, str]]:
    """Retorna todas as ocorrências (tag, sha256) filtradas pela tag."""
    db = await get_db()
    async with db.execute(
        "SELECT tag, sha256 FROM tags_sha256 WHERE tag = ?", (tag,)
    ) as cursor:
        return await cursor.fetchall()


# --- OPERAÇÕES DA TABELA CVE ---

async def post_many_cves(cve_list: list[tuple[str, str, str]]):
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


async def get_cve_by_id(cve_id: str) -> dict | None:
    db = await get_db()
    async with db.execute(
        "SELECT data FROM recent_cve WHERE cve_id = ?", (cve_id,)
    ) as cursor:
        row = await cursor.fetchone()
        return json.loads(row[0]) if row else None


async def get_recent_cve(limit: int = 100) -> list[dict]:
    db = await get_db()
    async with db.execute(
        "SELECT data FROM recent_cve ORDER BY last_modified DESC LIMIT ?",
        (limit,),
    ) as cursor:
        rows = await cursor.fetchall()
        return [json.loads(row[0]) for row in rows]

