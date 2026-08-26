import asyncio
from contextlib import asynccontextmanager

import aiosqlite
import orjson

DB_NAME = "database.db"
POOL_SIZE = 4  # ajuste conforme núcleos disponíveis / carga esperada da API

_read_pool: "list[aiosqlite.Connection]" = []
_read_queue = None  # asyncio.Queue criado em init_db (precisa de event loop ativo)
_write_conn: aiosqlite.Connection | None = None

READ_PRAGMAS = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA query_only = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA cache_size = -65536;    -- ~64MB de cache por conexão
    PRAGMA mmap_size = 268435456;  -- 256MB
"""


async def _new_read_connection():
    conn = await aiosqlite.connect(f"file:{DB_NAME}?mode=ro", uri=True)
    await conn.executescript(READ_PRAGMAS)
    # Evita a decodificação UTF-8 automática do driver para colunas TEXT.
    # Campos pequenos (cve_id, last_modified) são decodificados manualmente
    # quando necessário; o campo "data" (o maior) segue como bytes crus e
    # vai direto pro orjson (que aceita bytes) ou direto pra resposta HTTP.
    conn.text_factory = bytes
    return conn


async def _ensure_cve_tables(conn):
    """Schema das tabelas de CVE. Idealmente já criadas pelo script de build;
    aqui só garantimos que existam (idempotente, não reprocessa dados)."""
    await conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recent_cve (
            cve_id TEXT PRIMARY KEY,
            last_modified TEXT,
            data TEXT
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recent_cve_last_modified "
        "ON recent_cve(last_modified DESC)"
    )
    # Mesma definição do script de build: content-linked, sem duplicar o JSON
    await conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS recent_cve_fts USING fts5(
            cve_id UNINDEXED,
            data,
            content='recent_cve',
            content_rowid='rowid'
        )
        """
    )


async def _ensure_tags_table(conn):
    async with conn.execute("PRAGMA table_info(tags_sha256)") as cursor:
        columns_info = await cursor.fetchall()

    table_exists = bool(columns_info)
    columns = {row[1] for row in columns_info}

    if table_exists and "url" not in columns:
        await conn.execute("ALTER TABLE tags_sha256 RENAME TO tags_sha256_old")

    await conn.execute(
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
        await conn.execute(
            """
            INSERT INTO tags_sha256 (id, tag, url, sha256, created_at)
            SELECT id, tag, '', sha256, created_at
            FROM tags_sha256_old
            """
        )
        await conn.execute("DROP TABLE tags_sha256_old")

    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tags_sha256_tag ON tags_sha256(tag)"
    )


async def init_db(pool_size: int = POOL_SIZE):
    global _write_conn, _read_queue

    # Conexão única de escrita: cuida de todo o DDL/migração no startup
    _write_conn = await aiosqlite.connect(DB_NAME)
    await _write_conn.execute("PRAGMA journal_mode = WAL;")
    await _write_conn.execute("PRAGMA synchronous = NORMAL;")

    await _ensure_cve_tables(_write_conn)
    await _ensure_tags_table(_write_conn)
    await _write_conn.commit()

    # Pool de conexões somente-leitura: permite buscas concorrentes de verdade
    _read_queue = asyncio.Queue(maxsize=pool_size)
    for _ in range(pool_size):
        conn = await _new_read_connection()
        _read_pool.append(conn)
        await _read_queue.put(conn)


async def close_db():
    global _write_conn, _read_queue
    if _read_queue is not None:
        while not _read_queue.empty():
            conn = await _read_queue.get()
            await conn.close()
        _read_pool.clear()
        _read_queue = None
    if _write_conn:
        await _write_conn.close()
        _write_conn = None


async def get_write_db():
    """Para operações de escrita (ex.: tags_sha256). Use com cuidado/lock
    se houver escritas concorrentes vindas de handlers diferentes."""
    if _write_conn is None:
        raise RuntimeError("Banco de dados não foi inicializado.")
    return _write_conn


@asynccontextmanager
async def read_conn():
    if _read_queue is None:
        raise RuntimeError("Banco de dados não foi inicializado.")
    conn = await _read_queue.get()
    try:
        yield conn
    finally:
        await _read_queue.put(conn)


def _escape_fts_phrase(term: str) -> str:
    """Escapa aspas duplas para não quebrar a sintaxe da query MATCH do FTS5."""
    return term.replace('"', '""')


async def get_cve_by_id(cve_id: str, raw: bool = False):
    """raw=True devolve os bytes do JSON já armazenado, sem parse/reserialize.
    Ideal para retornar direto como corpo da resposta HTTP
    (ex.: Response(content=data, media_type="application/json"))."""
    async with read_conn() as db:
        async with db.execute(
            "SELECT data FROM recent_cve WHERE cve_id = ?", (cve_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return row[0] if raw else orjson.loads(row[0])


async def get_recent_cve(limit: int = 100, offset: int = 0, raw: bool = False):
    limit = max(1, min(limit, 500))  # evita respostas gigantes por engano
    offset = max(0, offset)
    async with read_conn() as db:
        async with db.execute(
            "SELECT data FROM recent_cve "
            "ORDER BY last_modified DESC, cve_id ASC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            rows = await cursor.fetchall()

    if raw:
        # monta o array JSON por concatenação de bytes, sem tocar no
        # conteúdo de cada "data" (que já é um JSON válido no banco)
        if not rows:
            return b"[]"
        return b"[" + b",".join(row[0] for row in rows) + b"]"

    return [orjson.loads(row[0]) for row in rows]


async def get_cves_by_package_name(
    package_name: str, limit: int = 100, offset: int = 0, raw: bool = False
):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    search_term = f'"{_escape_fts_phrase(package_name)}"*'

    query = """
        SELECT c.cve_id, c.last_modified, c.data
        FROM recent_cve_fts fts
        JOIN recent_cve c ON c.rowid = fts.rowid
        WHERE recent_cve_fts MATCH ?
        ORDER BY c.last_modified DESC, c.cve_id ASC
        LIMIT ? OFFSET ?
    """

    async with read_conn() as db:
        async with db.execute(query, (search_term, limit, offset)) as cursor:
            rows = await cursor.fetchall()

    if raw:
        if not rows:
            return b"[]"
        parts = []
        for cve_id, last_modified, data in rows:
            # cve_id/last_modified são pequenos: serializa normalmente.
            # "data" (o grande) entra como bytes crus, sem parse.
            parts.append(
                b'{"cve_id":'
                + orjson.dumps(cve_id.decode())
                + b',"last_modified":'
                + orjson.dumps(last_modified.decode())
                + b',"data":'
                + data
                + b"}"
            )
        return b"[" + b",".join(parts) + b"]"

    return [
        {
            "cve_id": cve_id.decode(),
            "last_modified": last_modified.decode(),
            "data": orjson.loads(data),
        }
        for cve_id, last_modified, data in rows
    ]
