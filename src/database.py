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

# >>> EDITE AQUI <<<
# Anos que devem ser carregados 100% em RAM ao iniciar. Basta listar os anos
# como string, ex.: ["2024", "2025"]. Os demais anos continuam servidos
# normalmente a partir do arquivo em disco (com cache de página).
MEMORY_YEARS: "set[str]" = {
    "2026",
    "2025"
    # "2024",
    # "2025",
}

# CVE-2023-12345 -> "2023"
CVE_ID_RE = re.compile(r"^CVE-(\d{4})-\d+$", re.IGNORECASE)
# cve_2023.db -> "2023" / cve_misc.db -> "misc"
DB_YEAR_RE = re.compile(r"cve_(\w+)\.db$")

# Faixas de severidade usadas nas pesquisas (mesmos valores do SelectOption
# do bot: "low", "medium", "high", "critical")
SEVERITY_RANGES = {
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}

# Pragmas para conexões de leitura em DISCO. cache_size/mmap_size existem pra
# compensar I/O de disco — fazem sentido aqui porque o banco mora num arquivo.
READ_PRAGMAS = """
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA query_only = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA cache_size = -65536;    -- ~64MB de cache por conexão
    PRAGMA mmap_size = 268435456;  -- 256MB
"""

# Pragmas para conexões de bancos que já vivem inteiramente em RAM
# (:memory: com cache=shared). Não faz sentido configurar cache_size/mmap_size
# (não existe página de disco pra cachear) nem journal_mode/synchronous
# (bancos :memory: não têm journal em disco) — por isso ficam de fora.
MEMORY_PRAGMAS = """
    PRAGMA query_only = ON;
    PRAGMA temp_store = MEMORY;
"""

# Um pool de leitura por ano: {"2023": {"queue": Queue, "conns": [...], "in_memory": bool}, ...}
_pools: "dict[str, dict]" = {}


def db_path_for_year(year: str) -> str:
    return os.path.join(DB_DIR, DB_NAME_TEMPLATE.format(year=year))


def _memory_uri_for_year(year: str) -> str:
    """URI de um banco :memory: nomeado com cache compartilhado. Enquanto
    houver ao menos uma conexão aberta pra essa URI, o conteúdo persiste em
    RAM e pode ser acessado por múltiplas conexões concorrentes."""
    return f"file:cve_{year}_ram?mode=memory&cache=shared"


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
            data TEXT,
            cvss_score REAL
        )
        """
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recent_cve_last_modified "
        "ON recent_cve(last_modified DESC)"
    )
    # Mesmo índice do script de build: acelera o filtro por faixa de CVSS
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recent_cve_cvss_score "
        "ON recent_cve(cvss_score)"
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


async def _build_disk_pool(db_path: str, pool_size: int) -> list:
    return [await _new_read_connection(db_path) for _ in range(pool_size)]


async def _build_memory_pool(year: str, db_path: str, pool_size: int) -> list:
    """Copia o banco inteiro (schema + dados + índices + FTS) do disco pra um
    banco :memory: com cache compartilhado, e abre `pool_size` conexões de
    leitura apontando pra esse mesmo banco em RAM."""
    mem_uri = _memory_uri_for_year(year)

    # Conexão "âncora": enquanto ela ficar aberta, o banco em memória
    # permanece vivo. Também é o destino do backup abaixo.
    anchor = await aiosqlite.connect(mem_uri, uri=True)

    src = await aiosqlite.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        await src.backup(anchor)
    finally:
        await src.close()

    conns = [anchor]
    for _ in range(pool_size - 1):
        conns.append(await aiosqlite.connect(mem_uri, uri=True))

    for conn in conns:
        await conn.executescript(MEMORY_PRAGMAS)
        conn.text_factory = bytes

    return conns


async def _init_year_pool(year: str, db_path: str, pool_size: int, in_memory: bool):
    # Conexão de escrita só para garantir o schema no startup (idempotente);
    # é fechada em seguida — a API só faz leitura a partir daqui. Isso roda
    # sempre no arquivo em disco, mesmo quando o ano vai pra RAM depois,
    # porque é a fonte que será copiada pelo backup.
    admin_conn = await aiosqlite.connect(db_path)
    try:
        await admin_conn.execute("PRAGMA journal_mode = WAL;")
        await admin_conn.execute("PRAGMA synchronous = NORMAL;")
        await _ensure_cve_tables(admin_conn)
        await admin_conn.commit()
    finally:
        await admin_conn.close()

    if in_memory:
        conns = await _build_memory_pool(year, db_path, pool_size)
    else:
        conns = await _build_disk_pool(db_path, pool_size)

    queue: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
    for conn in conns:
        await queue.put(conn)

    _pools[year] = {"queue": queue, "conns": conns, "in_memory": in_memory}


async def init_db(pool_size: int = POOL_SIZE):
    """Descobre todos os bancos cve_{year}.db existentes e abre um pool de
    leitura para cada um. Rodar o script de build antes de subir a API.

    Os anos listados em MEMORY_YEARS (topo do arquivo) são carregados
    inteiramente em RAM; os demais são servidos normalmente a partir do
    arquivo em disco.
    """
    db_files = sorted(glob.glob(db_path_for_year("*")))
    if not db_files:
        raise RuntimeError(
            f"Nenhum banco encontrado em {DB_DIR!r} com o padrão "
            f"{DB_NAME_TEMPLATE.format(year='*')!r}. Rode o script de build primeiro."
        )

    await asyncio.gather(
        *(
            _init_year_pool(
                year, db_path, pool_size, in_memory=year in MEMORY_YEARS
            )
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


def is_in_memory(year: str) -> bool:
    """Útil pra debug/monitoramento: diz se o ano está servindo a partir de RAM."""
    pool = _pools.get(year)
    return bool(pool and pool["in_memory"])


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
    severity: str | None = None,
):
    """"year" é obrigatório: a busca sempre acontece dentro do banco daquele
    ano, evitando varrer bancos que não interessam à consulta.

    "severity" é opcional e aceita os mesmos valores do SelectOption do bot:
    "low", "medium", "high" ou "critical". Quando informado, filtra também
    por cvss_score dentro da faixa correspondente, usando o índice
    idx_recent_cve_cvss_score (sem custo extra de varredura)."""
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    if year not in _pools:
        return b"[]" if raw else []

    params: list = []
    severity_clause = ""
    if severity is not None:
        if severity not in SEVERITY_RANGES:
            raise ValueError(
                f"Severidade inválida: {severity!r}. "
                f"Use um de: {', '.join(SEVERITY_RANGES)}."
            )
        min_score, max_score = SEVERITY_RANGES[severity]
        severity_clause = "AND c.cvss_score BETWEEN ? AND ?"
        params.extend([min_score, max_score])

    search_term = f'"{_escape_fts_phrase(package_name)}"*'
    query = f"""
        SELECT c.cve_id, c.last_modified, c.data
        FROM recent_cve_fts fts
        JOIN recent_cve c ON c.rowid = fts.rowid
        WHERE recent_cve_fts MATCH ?
        {severity_clause}
        ORDER BY c.last_modified DESC, c.cve_id ASC
        LIMIT ? OFFSET ?
    """

    query_params = [search_term, *params, limit, offset]

    async with read_conn(year) as db:
        async with db.execute(query, query_params) as cursor:
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