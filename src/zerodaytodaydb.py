import asyncio
import json
import os

REPO_DIR = os.path.abspath("0day.today.archive")


class ZeroDayArchiveManager:
    def __init__(self, repo_path=REPO_DIR):
        self.repo_path = repo_path
        self.index_path = os.path.join(repo_path, "index.json")
        self.cache = []
        self.lock = asyncio.Lock()

    async def load_data_to_memory(self):
        if not os.path.exists(self.index_path):
            print(f"Index file not found at: {self.index_path}")
            return

        def read_json():
            with open(
                self.index_path, mode="r", encoding="utf-8", errors="ignore"
            ) as f:
                return json.load(f)

        new_data = await asyncio.to_thread(read_json)

        async with self.lock:
            self.cache = new_data
        print(
            f"0day.today archive loaded successfully ({len(new_data)} records)."
        )

    async def initialize(self):
        await self.load_data_to_memory()

    async def search_by_term(self, term, limit=50):
        term_lower = term.lower()
        results = []

        async with self.lock:
            data = self.cache

        for item in data:
            title = item.get("title", "").lower()
            cves = " ".join(item.get("cve", [])).lower()

            if term_lower in title or term_lower in cves:
                results.append(item)
                if len(results) >= limit:
                    break

        return results

    async def get_exploit_by_id(self, exploit_id):
        async with self.lock:
            item_data = next(
                (
                    item
                    for item in self.cache
                    if str(item.get("exploit_id")) == str(exploit_id)
                ),
                None,
            )

        if not item_data:
            return None, "Exploit ID not found."

        category = item_data.get("category")
        if not category:
            return None, "Category metadata missing for this entry."

        relative_path = os.path.join(category, f"{exploit_id}.txt")
        absolute_path = os.path.join(self.repo_path, relative_path)

        def read_file():
            if not os.path.exists(absolute_path):
                return None
            with open(
                absolute_path, mode="r", encoding="utf-8", errors="ignore"
            ) as f:
                return f.read()

        content = await asyncio.to_thread(read_file)

        if content is None:
            return None, "Exploit file does not exist locally."

        return {"metadata": item_data, "code": content}, None


zeroday_mgr = ZeroDayArchiveManager()