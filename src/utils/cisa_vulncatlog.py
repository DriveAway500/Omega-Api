from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta
import asyncio
import hashlib

from httpx_client import client
from json_handler import JSONHandler

@dataclass
class CISAData:
    """
    Metadata for the last CISA CSV download.

    Stores the CSV link, the timestamp of the last fetch, and the SHA-256
    hash of the last saved file, so content changes can be detected between
    runs. Data is persisted in `cisa_data.json`.

    Attributes:
        link: Download URL of the CISA CSV.
        fetch: Timestamp of the last fetch (keeps the timezone, if any).
        sha256: SHA-256 hex digest of the last CSV saved to disk.
        path: Path to the `cisa_data.json` file. Excluded from `repr`.
    """
    link:   str
    fetch:  datetime
    sha256:   str
    path:   Path     = field(default=Path("."), repr=False)

    @classmethod
    def load(cls, path: str | Path) -> "CISAData":
        """
        Load metadata from `<path>/cisa_data.json`.

        Reads the first record of the JSON list and converts
        `cisa_last_fetch` (ISO 8601) to `datetime`.

        Args:
            path: Directory containing `cisa_data.json`.

        Returns:
            A `CISAData` instance with `path` pointing to the file read.

        Raises:
            KeyError: If an expected key is missing from the JSON.
            ValueError: If `cisa_last_fetch` is not valid ISO 8601.
            IndexError: If the JSON contains no records.
        """
        file  = Path(path) / "cisa_data.json"
        data  = JSONHandler.load(file)[0]
        fetch = datetime.fromisoformat(data["cisa_last_fetch"])

        return cls(
            link   = data["cisa_csv_link"],
            sha256   = data["cisa_csv_sha256"],
            fetch  = fetch,
            path   = file
        )

    def save(self) -> None:
        """
        Save metadata to the JSON file at `self.path`.

        The file is overwritten with a list containing a single record.
        """
        record = {
            "cisa_csv_link":   self.link,
            "cisa_last_fetch": self.fetch.isoformat(),
            "cisa_csv_sha256": self.sha256
        }
        JSONHandler.save(self.path, [record])


class FetchCisaJson:
    """Downloads the CISA CSV and stores it only when its content changes."""
    def __init__(self):
        self.data = CISAData.load("../../cisa_data")

    def _check_lastrun(self) -> bool:
        """
        Check whether enough time has passed since the last fetch.

        Returns:
            True if the last fetch happened more than 60 minutes ago.
        """
        now = datetime.now(self.data.fetch.tzinfo)
        return (now - self.data.fetch) > timedelta(minutes=60)

    async def _fetch_cisa_csv(self) -> None:
        """
        Download the CISA CSV in chunks and save it if its content changed.

        The file is streamed to a temporary file while its SHA-256 is
        computed incrementally, so it is never fully loaded into memory.
        After the download:

        - If the hash equals the stored one, the temporary file is discarded.
        - Otherwise, it is renamed to `<timestamp>_<sha256>.csv` in the same
          directory as `cisa_data.json`, and the new hash is stored.

        In both cases `fetch` is updated and the metadata is saved, so the
        60-minute throttle in `_check_lastrun` applies to the next call.

        Raises:
            httpx.HTTPStatusError: If the server returns a 4xx/5xx status.
            BaseException: Any error during download or writing is re-raised
                after the temporary file is removed.
        """
        dest_dir = self.data.path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Skip the request if the last fetch was less than 60 minutes ago
        if not self._check_lastrun():
            return

        tz = self.data.fetch.tzinfo
        tmp = dest_dir / "cisa_csv.tmp"
        hasher = hashlib.sha256()

        async with client.stream("GET", self.data.link) as response:
            response.raise_for_status()

            try:
                with open(tmp, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk) # write to disk chunk by chunk
                        hasher.update(chunk) # hash incrementally, same digest as the whole file
            except BaseException:
                # Never leave a partial download behind
                tmp.unlink(missing_ok=True)
                raise

        sha256 = hasher.hexdigest()
        now = datetime.now(tz)

        if sha256 == self.data.sha256:
            tmp.unlink(missing_ok=True)
        else:
            dest = dest_dir / f"{now.strftime('%Y%m%dT%H%M%S')}_{sha256}.csv"
            tmp.replace(dest)
            self.data.sha256 = sha256

        self.data.fetch = now
        self.data.save()

    async def run(self):
        await self._fetch_cisa_csv()


def main():
    cisa_fetch = FetchCisaJson()
    try:
        asyncio.run(cisa_fetch.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()