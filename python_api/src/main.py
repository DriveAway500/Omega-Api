from contextlib import asynccontextmanager
import json
import uvicorn
from fastapi import FastAPI, HTTPException, Request

from database import (
    get_cve_by_id,
    get_recent_cve,
    init_db,
    post_many_cves,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(lifespan=lifespan)


@app.post("/cve")
async def create_recent_cve(request: Request):
    try:
        content_bytes = await request.body()
        payload = json.loads(content_bytes)

        cves_to_insert = []

        if "vulnerabilities" in payload:
            for item in payload["vulnerabilities"]:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                last_modified = cve_obj.get("lastModified", "")

                if cve_id:
                    cves_to_insert.append(
                        (cve_id, last_modified, json.dumps(cve_obj))
                    )

        elif "CVE_Items" in payload:
            for item in payload["CVE_Items"]:
                cve_id = item.get("cve", {}) \
                             .get("CVE_data_meta", {}) \
                             .get("ID")
                last_modified = item.get("lastModifiedDate", "")

                if cve_id:
                    cves_to_insert.append(
                        (cve_id, last_modified, json.dumps(item))
                    )

        if not cves_to_insert:
            raise HTTPException(
                status_code=400,
                detail="No valid CVEs found in the submitted JSON.",
            )

        await post_many_cves(cves_to_insert)

        return {
            "status": "success",
            "cves_processed": len(cves_to_insert),
        }

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cve")
async def list_recent_cves(limit: int = 100):
    return await get_recent_cve(limit=limit)


@app.get("/cve/{cve_id}")
async def search_cve(cve_id: str):
    cve = await get_cve_by_id(cve_id)
    if not cve:
        raise HTTPException(
            status_code=404, detail="Not found."
        )
    return cve


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=True)