from contextlib import asynccontextmanager
import json
import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from exploitdb import exploit_db
from zerodaytodaydb import zeroday_mgr

from database import (
    close_db,
    get_cve_by_id,
    get_recent_cve,
    init_db,
    get_cves_by_package_name,
)


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


@app.get("/cve")
async def list_recent_cves(limit: int = 100):
    return await get_recent_cve(limit=limit)


@app.get("/cve/{cve_id}")
async def search_cve(cve_id: str):
    cve = await get_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Not found.")
    return cve


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/cve/search/package")
async def search_cves_by_package(package_name: str = Query(..., min_length=1)):
    cves = await get_cves_by_package_name(package_name)
    if not cves:
        raise HTTPException(
            status_code=404,
            detail=f"No CVEs found affecting package '{package_name}'.",
        )
    return cves


@app.get("/exploit/search")
async def search_exploits(q: str = Query(..., min_length=1), limit: int = 50):
    results = await exploit_db.search_by_term(q, limit=limit)
    return results


@app.get("/exploit/{exploit_id}")
async def get_exploit_by_id(exploit_id: str):
    data, error = await exploit_db.get_exploit_by_id(exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data

@app.get("/zeroday/search")
async def search_zeroday_exploits(q: str = Query(..., min_length=1), limit: int = 50):
    results = await zeroday_mgr.search_by_term(q, limit=limit)
    return results

@app.get("/zeroday/{exploit_id}")
async def get_zeroday_exploit_by_id(exploit_id: str):
    data, error = await zeroday_mgr.get_exploit_by_id(exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=True)