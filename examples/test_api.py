import hashlib
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from main import app
from database import init_db, close_db, get_db


def generate_sha256(val: str) -> str:
    return hashlib.sha256(val.encode()).hexdigest()


@pytest_asyncio.fixture
async def client():
    """Inicializa o banco, limpa as tabelas para isolamento e fornece o cliente de teste HTTP."""
    await init_db()
    
    # Limpa dados anteriores para garantir testes isolados
    db = await get_db()
    await db.execute("DELETE FROM tags_sha256;")
    await db.execute("DELETE FROM recent_cve;")
    await db.commit()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
    
    await close_db()


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Testa a rota de status da API."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.asyncio
async def test_post_last_modified_route(client: AsyncClient):
    """Testa a inserção de SHA-256 no endpoint /last_modified."""
    sha = generate_sha256("payload_teste_1")

    response = await client.post("/last_modified", params={"sha256": sha})
    assert response.status_code == 201
    assert response.json() == {"status": "success"}


@pytest.mark.asyncio
async def test_post_and_get_tags_bulk(client: AsyncClient):
    """Insere múltiplos SHA-256 via API para diferentes tags e valida os retornos."""
    tag_name = "malware_samples"
    hashes = [generate_sha256(f"sample_{i}") for i in range(50)]

    for sha in hashes:
        response = await client.post(f"/tags/{tag_name}", params={"sha256": sha})
        assert response.status_code == 201
        assert response.json() == {"status": "success"}

    get_response = await client.get(f"/tags/{tag_name}")
    assert get_response.status_code == 200

    data = get_response.json()
    assert len(data) == 50

    # Garante integridade comparando conjuntos (set) independente da ordem
    retrieved_shas = {item["sha256"] for item in data}
    expected_shas = set(hashes)
    assert retrieved_shas == expected_shas


@pytest.mark.asyncio
async def test_create_and_fetch_cve(client: AsyncClient):
    """Testa o envio de lote de CVEs e a busca individual/listagem."""
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1001",
                    "lastModified": "2026-08-20T10:00:00.000",
                    "description": "Test Vulnerability 1",
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-1002",
                    "lastModified": "2026-08-21T12:00:00.000",
                    "description": "Test Vulnerability 2",
                }
            },
        ]
    }

    post_res = await client.post("/cve", json=payload)
    assert post_res.status_code == 201
    assert post_res.json() == {"status": "success", "cves_processed": 2}

    list_res = await client.get("/cve?limit=10")
    assert list_res.status_code == 200
    recent_list = list_res.json()
    assert len(recent_list) >= 2

    get_res = await client.get("/cve/CVE-2026-1001")
    assert get_res.status_code == 200
    cve_data = get_res.json()
    assert cve_data["id"] == "CVE-2026-1001"


@pytest.mark.asyncio
async def test_cve_not_found(client: AsyncClient):
    """Valida retorno 404 para CVE inexistente."""
    response = await client.get("/cve/CVE-0000-0000")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found."}