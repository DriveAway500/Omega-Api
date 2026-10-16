from contextlib import asynccontextmanager
from enum import Enum
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.gzip import GZipMiddleware

from exploitdb import exploit_db
from zerodaytodaydb import zeroday_mgr

import kev_catalog

from database import (
    close_db,
    get_cve_by_id,
    init_db,
    get_cves_by_package_name,
)

JSON_MEDIA_TYPE = "application/json"
YEAR_PATTERN = r"^\d{4}$|^misc$"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --------------------------------------------------------------------------- #
# Schemas (request payloads)
# --------------------------------------------------------------------------- #
class BaseRequest(BaseModel):
    # Strips whitespace from strings and rejects unknown fields in the payload
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class PaginationRequest(BaseRequest):
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0)


class PackageSearchRequest(BaseRequest):
    package_name: str = Field(..., min_length=1)
    year: str = Field(
        ...,
        pattern=YEAR_PATTERN,
        description="CVE year (e.g. 2023) or 'misc'.",
        examples=["2023"],
    )
    limit: int = Field(100, ge=1, le=500)
    offset: int = Field(0, ge=0)
    severity: Severity | None = Field(
        None,
        description="low (0.1-3.9), medium (4.0-6.9), "
        "high (7.0-8.9) or critical (9.0-10.0).",
    )


class CveIdRequest(BaseRequest):
    cve_id: str = Field(..., min_length=1, examples=["CVE-2023-12345"])


class ExploitSearchRequest(PaginationRequest):
    q: str = Field(..., min_length=1, description="Search term.")


class ExploitIdRequest(BaseRequest):
    exploit_id: str = Field(..., min_length=1)


class HealthResponse(BaseModel):
    status: str


class KevSearchRequest(PaginationRequest):
    q: str = Field(..., min_length=1, description="Search term.")
    fields: list[str] | None = Field(
        None,
        description="Subset of fields to search; defaults to all searchable fields "
        f"({', '.join(kev_catalog.SEARCHABLE_FIELDS)}).",
    )


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #
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

app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "healthy"}


# --------------------------------- CVE --------------------------------------- #
@app.post("/cve/search/package")
async def search_cves_by_package(payload: PackageSearchRequest):
    data = await get_cves_by_package_name(
        payload.package_name,
        payload.year,
        limit=payload.limit,
        offset=payload.offset,
        raw=True,
        severity=payload.severity.value if payload.severity else None,
    )
    if data == b"[]":
        detail = (
            f"No CVEs found affecting package '{payload.package_name}' "
            f"in {payload.year}"
        )
        if payload.severity:
            detail += f" with severity '{payload.severity.value}'"
        raise HTTPException(status_code=404, detail=detail + ".")
    return Response(content=data, media_type=JSON_MEDIA_TYPE)


@app.post("/cve/search")
async def search_cve(payload: CveIdRequest):
    data = await get_cve_by_id(payload.cve_id, raw=True)
    if data is None:
        raise HTTPException(status_code=404, detail="Not found.")
    return Response(content=data, media_type=JSON_MEDIA_TYPE)


# ------------------------------ Exploit-DB ---------------------------------- #
@app.post("/exploit/search")
async def search_exploits(payload: ExploitSearchRequest) -> list[dict[str, Any]]:
    return await exploit_db.search(
        payload.q, limit=payload.limit, offset=payload.offset
    )


@app.post("/exploit/get")
async def get_exploit_by_id(payload: ExploitIdRequest) -> dict[str, Any]:
    data, error = await exploit_db.get_exploit_by_id(payload.exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data


# ------------------------------ 0day.today ---------------------------------- #
@app.post("/zeroday/search")
async def search_zeroday_exploits(
    payload: ExploitSearchRequest,
) -> list[dict[str, Any]]:
    return await zeroday_mgr.search_by_term(
        payload.q, limit=payload.limit, offset=payload.offset
    )


@app.post("/zeroday/get")
async def get_zeroday_exploit_by_id(payload: ExploitIdRequest) -> dict[str, Any]:
    data, error = await zeroday_mgr.get_exploit_by_id(payload.exploit_id)
    if error:
        raise HTTPException(status_code=404, detail=error)
    return data


# --------------------------------- KEV ---------------------------------------- #
# Read-only: the index itself is produced out-of-band by build_kev_index.py
# (a separate, standalone script run via cron/systemd/etc). These routes only
# ever read what that script already wrote to disk.
_NO_PREVIOUS_INDEX_DETAIL = (
    "No previous index yet — build_kev_index.py needs to have run at least twice."
)


@app.get("/kev/diff")
async def get_kev_diff() -> dict[str, Any]:
    """Full diff (added / removed / modified) between the current index
    and the one from the previous builder run."""
    diff = kev_catalog.diff_against_previous()
    if diff["old_generated_at"] is None:
        raise HTTPException(status_code=404, detail=_NO_PREVIOUS_INDEX_DETAIL)
    return diff


@app.get("/kev/new")
async def get_kev_new() -> dict[str, Any]:
    """CVEs present in the current index but not in the previous one."""
    diff = kev_catalog.diff_against_previous()
    if diff["old_generated_at"] is None:
        raise HTTPException(status_code=404, detail=_NO_PREVIOUS_INDEX_DETAIL)
    return {"count": diff["added_count"], "entries": diff["added"]}


@app.get("/kev/removed")
async def get_kev_removed() -> dict[str, Any]:
    """CVEs present in the previous index but no longer in the current one."""
    diff = kev_catalog.diff_against_previous()
    if diff["old_generated_at"] is None:
        raise HTTPException(status_code=404, detail=_NO_PREVIOUS_INDEX_DETAIL)
    return {"count": diff["removed_count"], "entries": diff["removed"]}


@app.post("/kev/search")
async def search_kev(payload: KevSearchRequest) -> dict[str, Any]:
    """Free-text search across the indexed KEV rows."""
    index = kev_catalog.load_index()
    if index["count"] == 0:
        raise HTTPException(
            status_code=404,
            detail="Index not built yet — build_kev_index.py needs to run first.",
        )
    return kev_catalog.search(
        index,
        payload.q,
        fields=payload.fields,
        limit=payload.limit,
        offset=payload.offset,
    )


@app.get("/kev/get/{cve_id}")
async def get_kev_entry(cve_id: str) -> dict[str, Any]:
    """Direct lookup of a single CVE from the index by id."""
    index = kev_catalog.load_index()
    entry = kev_catalog.get_by_id(index, cve_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Not found in KEV index.")
    return entry


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=3000, reload=False)