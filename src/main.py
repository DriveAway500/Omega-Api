from contextlib import asynccontextmanager
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
    get_recent_cve,
    init_db,
    get_cves_by_package_name,
)

JSON_MEDIA_TYPE = "application/json"


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


@app.get("/cve")
async def list_recent_cves(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    data = await get_recent_cve(limit=limit, offset=offset, raw=True)
    return Response(content=data, media_type=JSON_MEDIA_TYPE)


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/cve/search/package")
async def search_cves_by_package(
    package_name: str = Query(..., min_length=1),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    data = await get_cves_by_package_name(
        package_name, limit=limit, offset=offset, raw=True
    )
    if data == b"[]":
        raise HTTPException(
            status_code=404,
            detail=f"No CVEs found affecting package '{package_name}'.",
        )
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