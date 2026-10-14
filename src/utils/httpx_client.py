#small client definition just for now

import httpx

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
        "Gecko/20100101 Firefox/119.0"
    )
}

client = httpx.AsyncClient(
    timeout=10.0,
    headers=HEADERS,
)


async def close():
    await client.aclose()