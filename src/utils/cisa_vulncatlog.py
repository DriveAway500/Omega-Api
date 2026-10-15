from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta
import asyncio

from httpx_client import client
from json_handler import JSONHandler

@dataclass
class CISAData:
    """
    Metadata for the last CISA CSV download.

    Stores the CSV link, the timestamp of the last fetch, and the SHA-256
    hash of the file, so changes can be detected between runs.
    Data is persisted in `cisa_data.json`.

    Attributes:
        link: Download URL of the CISA CSV.
        fetch: Timestamp of the last fetch (keeps the timezone, if any).
        etag: Etag from the header of the downloaded CSV.
        path: Path to the `cisa_data.json` file. Excluded from `repr`.
    """
    link:   str
    fetch:  datetime
    etag:   str      = ""
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
            etag   = data["cisa_csv_etag"],
            fetch  = fetch,
            path   = file
        )

    def save(self) -> None:
        """
        Save metadata to the JSON file at `self.path`.

        Before writing, sets `fetch` to the current time, preserving the
        original timezone. The file is overwritten with a list containing
        a single record.
        """
        record = {
            "cisa_csv_link":   self.link,
            "cisa_last_fetch": self.fetch.isoformat(),
            "cisa_csv_etag": self.etag
        }
        JSONHandler.save(self.path, [record])


class FetchCisaJson:
    def __init__(self):
        self.data = CISAData.load("../../cisa_data")

    def _check_lastrun(self) -> bool:
        """True if run after more than 60 minutes"""
        now = datetime.now(self.data.fetch.tzinfo)
        return (now - self.data.fetch) > timedelta(minutes=60)

    async def _fetch_cisa_csv(self) -> None:
        dest_dir = self.data.path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        if not self._check_lastrun():
            return

        tz = self.data.fetch.tzinfo
        headers = {"If-None-Match": self.data.etag} if self.data.etag else {}

        async with client.stream("GET", self.data.link, headers=headers) as response:
            if response.status_code == 304:
                self.data.fetch = datetime.now(tz)
                self.data.save()
                return

            response.raise_for_status()

            etag = response.headers.get("ETag", "")
            safe_etag = etag.removeprefix("W/").strip('"')
            timestamp = datetime.now(tz).strftime("%Y%m%dT%H%M%S")
            dest = dest_dir / f"{timestamp}_{safe_etag}.csv"
            tmp = dest.with_name(dest.name + ".tmp")

            try:
                with open(tmp, "wb") as f:
                    async for chunk in response.aiter_bytes():
                        f.write(chunk)
                tmp.replace(dest)
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise

        self.data.etag = etag
        self.data.fetch = datetime.now(tz)
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