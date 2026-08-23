from contextlib import asynccontextmanager
import json
import uvicorn
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from exploitdb import exploit_db

from database import (
    add_tag_sha256,
    close_db,
    get_all_by_tag,
    get_cve_by_id,
    get_recent_cve,
    init_db,
    post_many_cves,
    get_cves_by_package_name,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await exploit_db.initialize()
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


@app.post("/cve", status_code=status.HTTP_201_CREATED)
async def create_recent_cve(payload: dict):
    cves_to_insert = []

    if "vulnerabilities" in payload:
        for item in payload["vulnerabilities"]:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")
            if cve_id:
                cves_to_insert.append(
                    (cve_id, cve_obj.get("lastModified", ""), json.dumps(cve_obj))
                )

    elif "CVE_Items" in payload:
        for item in payload["CVE_Items"]:
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            if cve_id:
                cves_to_insert.append(
                    (cve_id, item.get("lastModifiedDate", ""), json.dumps(item))
                )

    if not cves_to_insert:
        raise HTTPException(
            status_code=400,
            detail="No valid CVEs found in the submitted JSON.",
        )

    await post_many_cves(cves_to_insert)
    return {"status": "success", "cves_processed": len(cves_to_insert)}


@app.get("/cve")
async def list_recent_cves(limit: int = 100):
    return await get_recent_cve(limit=limit)


@app.get("/cve/{cve_id}")
async def search_cve(cve_id: str):
    cve = await get_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Not found.")
    return cve


@app.post("/post_nvd_tags", status_code=status.HTTP_201_CREATED)
async def create_tags_sha256(payload: list[dict]):
    for item in payload:
        await add_tag_sha256(item["tag"], item["url"], item["sha256"])

    return {"status": "success"}


@app.get("/get_nvd_tags/{tag}")
async def fetch_by_tag(tag: str):
    results = await get_all_by_tag(tag)
    return [{"url": item[0], "sha256": item[1]} for item in results]


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


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=True)