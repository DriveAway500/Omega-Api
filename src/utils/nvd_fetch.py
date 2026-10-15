#this script can be used almost independently,
#except for the httpx client which you can replace
#by replacing the import line with an import to your own client
from dataclasses import dataclass, replace, asdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
import asyncio
import re

from httpx_client import client #if you don't have a client use this one (very simple, still)
from json_handler import JSONHandler

_SHA256_RE = re.compile(r"[0-9a-f]{64}")

#some of the data stored here is not being used for now, but will be used later in better versions of this script
@dataclass(frozen=True)
class MetaData:
    last_modified: datetime
    size:          int
    zip_size:      int
    gzip_size:     int
    sha256:        str

@dataclass(frozen=True)
class MetaLink:
    link:     str
    sha256:   str
    gzip_url: str

class DataControl:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else Path("../data")
        self.fetch_file = self.path / "last_fetch.json"
        self.meta_link_file = self.path / "meta_links.json"

    @staticmethod
    def _load_json(path: Path) -> list[dict]:
        return JSONHandler.load(path)

    def parse_meta(self) -> list[MetaLink]:
        """Reads meta_links.json from self.path"""
        data = self._load_json(self.meta_link_file)
        return [
            MetaLink(link=item["link"], sha256=item["sha256"], gzip_url=item["gzip_url"])
            for item in data
        ]

    def last_fetch(self) -> list[str]:
        """Reads last_fetch.json from self.path"""
        data = self._load_json(self.fetch_file)
        return [item["last_fetch"] for item in data]

class FetchNvd(DataControl):
    def __init__(self):
        super().__init__("../../data")
        self.meta_link_list:  list[MetaLink] = []
        self.last_fetch_list: list[str]      = []

    def _load(self, meta_link:  bool = True,
                    last_fetch: bool = True
               ) -> None :
        """Populate this handler's lists from the JSON files on disk.

        Each flag opts in to loading one file, appending to the corresponding
        list (does not clear it first):

            meta_link:   append parse_meta() to self.meta_link_list
            last_fetch:  append last_fetch() to self.last_fetch_list
        """
        if meta_link:
            self.meta_link_list.extend(self.parse_meta())
        if last_fetch:
            self.last_fetch_list.extend(self.last_fetch())

    def _upsert(self, key: str | None = None, **changes) -> None:
        """Update a tracked link, or store standalone fetch data.

        The behavior depends on whether ``key`` is provided:

        * ``key`` given: finds the ``MetaLink`` whose ``link`` equals ``key``,
          replaces it with a copy updated by ``changes`` (``MetaLink`` is frozen,
          so ``dataclasses.replace`` is used), and persists the full list to
          ``meta_link_file``.
        * ``key`` omitted: ``changes`` is treated as standalone data (e.g. a
          timestamp) and written to ``fetch_file``, replacing its previous contents.

        Args:
            key: ``link`` of the ``MetaLink`` to update. If ``None``, ``changes``
                is written to ``fetch_file`` instead.
            **changes: Fields to update on the matched ``MetaLink`` (``sha256``,
                ``gzip_url``), or arbitrary data when ``key`` is ``None``.

        Raises:
            KeyError: if ``key`` is given but no ``MetaLink`` has that link.
            JSONSaveError: if the data cannot be serialized or written.
        """
        if key is None:
            self.last_fetch_list[0] = changes["last_fetch"]
            JSONHandler.save(self.fetch_file, [changes])
            return

        for i, meta in enumerate(self.meta_link_list):
            if meta.link == key:
                self.meta_link_list[i] = replace(meta, **changes)
                break
        else:
            raise KeyError(f"Link not Found: {key}")

        JSONHandler.save(
            self.meta_link_file,
            [asdict(m) for m in self.meta_link_list],
        )

    @staticmethod
    def _normalize_sha256(value: str) -> str:
        """Normalize and validate an SHA-256 hash (64 hexadecimal characters)."""
        if not isinstance(value, str):
            raise TypeError(f"Hash must be str, got: {type(value).__name__}")

        normalized = value.strip().lower()

        if not _SHA256_RE.fullmatch(normalized):
            raise ValueError(f"Invalid SHA-256 hash: {value!r}")

        return normalized

    def _check_sha256(self, current_hash: str, new_hash: str) -> bool:
        """Compare two SHA-256 hashes. Returns True if they are different."""
        return self._normalize_sha256(current_hash) != self._normalize_sha256(new_hash)

    @staticmethod
    def _check_lastrun(lastrun:str) -> bool:
        """checks if the lastrun is bigger than 5 minutes"""
        lastrun = datetime.fromisoformat(lastrun)
        now     = datetime.now(lastrun.tzinfo)
        return (now - lastrun) > timedelta(minutes=5)


    @staticmethod
    async def _fetch_nvd_meta(url: str) -> MetaData:
        """Fetch and parse an NVD `.meta` sidecar file.

        The file is line-based `key: value`, not JSON. Expected keys:
        `lastModifiedDate` (ISO 8601), `size`, `zipSize`, `gzSize` (ints),
        and `sha256`.

        Args:
            url: URL of the `.meta` file.

        Returns:
            MetaData populated from the file's fields.

        Raises:
            httpx.HTTPStatusError: on 4xx/5xx responses.
            ValueError: if a required field is missing, or if a size or
                date field can't be parsed.
        """
        response = await client.get(url)
        response.raise_for_status()

        fields: dict[str, str] = {}
        for line in response.text.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip()] = value.strip()

        try:
            return MetaData(
                last_modified = datetime.fromisoformat(fields["lastModifiedDate"]),
                size          = int(fields["size"]),
                zip_size      = int(fields["zipSize"]),
                gzip_size     = int(fields["gzSize"]),
                sha256        = fields["sha256"],
            )

        except KeyError as e:
            raise ValueError(f"Field not found in NVD .meta data: {e}")

    async def _fetch_nvd_data(self, changed: bool, url: str) -> None:
        """Download an NVD feed into ``self.path``, creating or replacing the file.

        The file name is taken from the last segment of ``url``, so it matches the
        name published by the server. The download happens when ``changed`` is
        ``True`` or when the file does not exist yet. Otherwise, nothing is fetched.

        The response is streamed to a ``.tmp`` file next to the target and moved
        into place with ``Path.replace``, so an existing file is only overwritten
        after the new download has completed. If anything goes wrong (including
        cancellation), the temporary file is removed and the exception is
        re-raised, leaving any existing file untouched.

        ``self.path`` is created if it does not exist.

        Args:
            changed: Whether the remote feed differs from the one already stored
                (typically the result of ``_check_sha256``).
            url: URL of the file to download (the feed's ``gzip_url``).

        Raises:
            httpx.HTTPStatusError: on 4xx/5xx responses.
            httpx.HTTPError: on network-level failures (timeouts, connection errors).
            OSError: if the directory or file cannot be created, written or moved.
        """
        dest = self.path / Path(urlparse(url).path).name

        if not (changed or not dest.exists()):
            return

        self.path.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")  # foo.json.gz.tmp

        try:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                with open(tmp, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)
            tmp.replace(dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    async def _update_all(self, last_fetch: str) -> None:
        """Check every tracked feed and refresh the ones that need it.

            For each ``MetaLink`` in ``self.meta_link_list``:

            1. Fetch its ``.meta`` file and compare the remote sha256 with the stored one.
            2. Download the feed's gzip file if the hashes differ or the local file is
               missing (see ``_fetch_nvd_data``).
            3. Persist the new sha256 via ``_upsert``, only after the download finished.

            Feeds are processed sequentially. After all feeds are processed, the
            last-fetch timestamp is updated and saved to ``fetch_file``.

            Args:
                last_fetch: ISO 8601 timestamp of the previous run. Only its timezone
                    is used, so the new timestamp is written in the same timezone.

            Raises:
                httpx.HTTPError: if a request fails. The error is not caught here, so
                    the remaining feeds and the timestamp update are skipped.
                ValueError: if a ``.meta`` file is missing a field or has an
                    unparseable value.
                KeyError: if the link being updated is not in ``meta_link_list``.
                JSONSaveError: if the updated state cannot be written to disk.
            """
        for meta in self.meta_link_list:
            data = await self._fetch_nvd_meta(meta.link)
            await self._fetch_nvd_data(
                self._check_sha256(meta.sha256, data.sha256),
                meta.gzip_url
            )
            self._upsert(meta.link, sha256=data.sha256)

        tz = datetime.fromisoformat(last_fetch).tzinfo
        self._upsert(last_fetch=datetime.now(tz).isoformat())

    async def run(self) -> None:
        """Run the update loop forever.

        Loads the persisted state (tracked links and last fetch time) once, then
        wakes up every 60 seconds. On each wake-up, if more than 5 minutes have
        passed since the last fetch (see ``_check_lastrun``), it calls
        ``_update_all``.

        This coroutine never returns normally. Run it as a task and cancel it
        to stop it.

        Raises:
            httpx.HTTPError: propagated from ``_update_all``; it ends the loop.
            ValueError: propagated from ``_update_all``; it ends the loop.
            IndexError: if ``last_fetch.json`` has no entries when the loop starts.
        """
        self._load()

        last_fetch = self.last_fetch_list[0]

        if self._check_lastrun(last_fetch):
            await self._update_all(last_fetch)


def main():
    nvd = FetchNvd()
    try:
        asyncio.run(nvd.run())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()