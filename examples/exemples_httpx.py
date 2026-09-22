import asyncio

import httpx


BASE_URL = "http://127.0.0.1:3000"


async def verificar_saude(client):
    response = await client.get("/health")
    response.raise_for_status()
    print("Saude:", response.json())


async def salvar_tags(client):
    payload = [
        {
            "tag": "foo",
            "url": "http://example.com/arquivo-a.zip",
            "sha256": "ASJ1234567890ABCDEF",
        },
        {
            "tag": "foo",
            "url": "http://example.com/arquivo-b.zip",
            "sha256": "DEF9876543210ABCDEF",
        },
    ]

    response = await client.post("/post_nvd_tags", json=payload)
    response.raise_for_status()
    print("Tags salvas:", response.json())


async def buscar_tags(client, tag):
    response = await client.get(f"/get_nvd_tags/{tag}")
    response.raise_for_status()

    print(f"Resultados da tag '{tag}':")
    for item in response.json():
        print(f"url={item['url']}")
        print(f"sha256={item['sha256']}")


async def listar_cves(client):
    response = await client.get("/cve", params={"limit": 10})
    response.raise_for_status()
    print("CVEs recentes:", response.json())


async def buscar_cve(client, cve_id):
    response = await client.get(f"/cve/{cve_id}")
    if response.status_code == 404:
        print(f"CVE nao encontrada: {cve_id}")
        return

    response.raise_for_status()
    print("CVE encontrada:", response.json())


async def main():
    timeout = httpx.Timeout(10.0)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=timeout) as client:
        await verificar_saude(client)
        await salvar_tags(client)
        await buscar_tags(client, "foo")
        await listar_cves(client)
        await buscar_cve(client, "CVE-2026-1001")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.ConnectError:
        print(f"Nao foi possivel conectar a API em {BASE_URL}.")
        print("Inicie o servidor com: python main.py")
