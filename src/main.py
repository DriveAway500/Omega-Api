from contextlib import asynccontextmanager
from enum import Enum
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from exploitdb import exploit_db
from zerodaytodaydb import zeroday_mgr

from database import (
    close_db,
    get_cve_by_id,
    init_db,
    get_cves_by_package_name,
)

JSON_MEDIA_TYPE = "application/json"
# Mesmo padrão usado no build/database.py, só pra validar o formato do "year"
# recebido na query string antes de bater no banco.
YEAR_PATTERN = r"^\d{4}$|^misc$"


class Severity(str, Enum):
    """Mesmos valores usados no SelectOption do bot Discord."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await exploit_db.initialize()
    await zeroday_mgr.initialize()
    yield
    await close_db()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Comprime respostas acima de ~1KB (a listagem de CVEs facilmente passa disso).
# O ganho aqui é de rede/latência percebida pelo cliente, não de CPU do servidor.
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/cve/search/package")
async def search_cves_by_package(
    package_name: str = Query(..., min_length=1),
    year: str = Query(..., pattern=YEAR_PATTERN, description="Ano do CVE (ex.: 2023)."),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Severity | None = Query(
        None,
        description="Filtra por faixa de CVSS: low (0.1-3.9), medium (4.0-6.9), "
        "high (7.0-8.9) ou critical (9.0-10.0).",
    ),
):
    data = await get_cves_by_package_name(
        package_name,
        year,
        limit=limit,
        offset=offset,
        raw=True,
        severity=severity.value if severity else None,
    )
    if data == b"[]":
        detail = f"No CVEs found affecting package '{package_name}' in {year}"
        if severity:
            detail += f" with severity '{severity.value}'"
        raise HTTPException(status_code=404, detail=detail + ".")
    return Response(content=data, media_type=JSON_MEDIA_TYPE)

@app.get("/cve/{cve_id}")
async def search_cve(cve_id: str):
    data = await get_cve_by_id(cve_id, raw=True)
    if data is None:
        raise HTTPException(status_code=404, detail="Not found.")
    return Response(content=data, media_type=JSON_MEDIA_TYPE)


@app.get("/exploit/search")
async def search_exploits(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    results = await exploit_db.search(q, limit=limit, offset=offset)
    return results


@app.get("/exploit/{exploit_id}")
async def get_exploit_by_id(exploit_id: str) -> dict[str, Any]:
    data, error = await exploit_db.get_exploit_by_id(exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data


@app.get("/zeroday/search")
async def search_zeroday_exploits(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    results = await zeroday_mgr.search_by_term(q, limit=limit, offset=offset)
    return results


@app.get("/zeroday/{exploit_id}")
async def get_zeroday_exploit_by_id(exploit_id: str) -> dict[str, Any]:
    data, error = await zeroday_mgr.get_exploit_by_id(exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data


if __name__ == "__main__":
    # Em produção: remova reload=True, ajuste host para "0.0.0.0" e considere
    # workers>1 (uvicorn --workers N) já que cada worker abre seu próprio pool
    # de conexões de leitura (init_db roda por processo).
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=True)