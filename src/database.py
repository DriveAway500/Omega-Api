import asyncio
import glob
import os
import re
from contextlib import asynccontextmanager

import aiosqlite
import orjson

DB_DIR = "."
DB_NAME_TEMPLATE = "cve_{year}.db"  # mesmo padrão usado no script de build
POOL_SIZE = 4  # conexões de leitura por ano / ajuste conforme núcleos e carga

# CVE-2023-12345 -> "2023"
CVE_ID_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)
# cve_2023.db -> "2023" / cve_misc.db -> "misc"
DB_YEAR_RE = re.compile(r"cve_(\w+)\.db$")

READ_PRAGMAS = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA query_only = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA cache_size = -65536;    -- ~64MB de cache por conexão
    PRAGMA mmap_size = 268435456;  -- 256MB
"""

# Um pool de leitura por ano: {"2023": {"queue": Queue, "conns": [...]}, ...}
_pools: "dict[str, dict]" = {}


def db_path_for_year(year: str) -> str:
    return os.path.join(DB_DIR, DB_NAME_TEMPLATE.format(year=year))


def extract_cve_year(cve_id: str) -> str | None:
    """Extrai o ano a partir do próprio ID (ex.: CVE-2023-12345 -> "2023")."""
    m = CVE_ID_RE.match(cve_id.strip())
    return m.group(1) if m else None


def _extract_year_from_db_path(db_path: str) -> str | None:
    m = DB_YEAR_RE.search(os.path.basename(db_path))
    return m.group(1) if m else None


async def _new_read_connection(db_path: str):
    conn = await aiosqlite.connect(f"file:{db_path}?mode=ro", uri=True)
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


async def _init_year_pool(year: str, db_path: str, pool_size: int):
    # Conexão de escrita só para garantir o schema no startup (idempotente);
    # é fechada em seguida — a API só faz leitura a partir daqui.
    admin_conn = await aiosqlite.connect(db_path)
    try:
        await admin_conn.execute("PRAGMA journal_mode = WAL;")
        await admin_conn.execute("PRAGMA synchronous = NORMAL;")
        await _ensure_cve_tables(admin_conn)
        await admin_conn.commit()
    finally:
        await admin_conn.close()

    queue: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
    conns = []
    for _ in range(pool_size):
        conn = await _new_read_connection(db_path)
        conns.append(conn)
        await queue.put(conn)

    _pools[year] = {"queue": queue, "conns": conns}


async def init_db(pool_size: int = POOL_SIZE):
    """Descobre todos os bancos cve_{year}.db existentes e abre um pool de
    leitura para cada um. Rodar o script de build antes de subir a API."""
    db_files = sorted(glob.glob(db_path_for_year("*")))
    if not db_files:
        raise RuntimeError(
            f"Nenhum banco encontrado em {DB_DIR!r} com o padrão "
            f"{DB_NAME_TEMPLATE.format(year='*')!r}. Rode o script de build primeiro."
        )

    await asyncio.gather(
        *(
            _init_year_pool(year, db_path, pool_size)
            for db_path in db_files
            if (year := _extract_year_from_db_path(db_path)) is not None
        )
    )


async def close_db():
    for pool in _pools.values():
        while not pool["queue"].empty():
            await pool["queue"].get()
        for conn in pool["conns"]:
            await conn.close()
    _pools.clear()


@asynccontextmanager
async def read_conn(year: str):
    pool = _pools.get(year)
    if pool is None:
        raise ValueError(f"Nenhum banco disponível para o ano {year!r}.")
    conn = await pool["queue"].get()
    try:
        yield conn
    finally:
        await pool["queue"].put(conn)


def _escape_fts_phrase(term: str) -> str:
    """Escapa aspas duplas para não quebrar a sintaxe da query MATCH do FTS5."""
    return term.replace('"', '""')


async def get_cve_by_id(cve_id: str, raw: bool = False):
    """raw=True devolve os bytes do JSON já armazenado, sem parse/reserialize.
    Ideal para retornar direto como corpo da resposta HTTP
    (ex.: Response(content=data, media_type="application/json"))."""
    year = extract_cve_year(cve_id)
    if year is None or year not in _pools:
        return None

    async with read_conn(year) as db:
        async with db.execute(
            "SELECT data FROM recent_cve WHERE cve_id = ?", (cve_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            return row[0] if raw else orjson.loads(row[0])


async def get_cves_by_package_name(
    package_name: str,
    year: str,
    limit: int = 100,
    offset: int = 0,
    raw: bool = False,
):
    """"year" é obrigatório: a busca sempre acontece dentro do banco daquele
    ano, evitando varrer bancos que não interessam à consulta."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    if year not in _pools:
        return b"[]" if raw else []

    search_term = f'"{_escape_fts_phrase(package_name)}"*'
    query = """
        SELECT c.cve_id, c.last_modified, c.data
        FROM recent_cve_fts fts
        JOIN recent_cve c ON c.rowid = fts.rowid
        WHERE recent_cve_fts MATCH ?
        ORDER BY c.last_modified DESC, c.cve_id ASC
        LIMIT ? OFFSET ?
    """

    async with read_conn(year) as db:
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