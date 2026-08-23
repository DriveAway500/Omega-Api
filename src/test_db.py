import hashlib
import pytest
import pytest_asyncio
from database import init_db, close_db, get_db, add_tag_sha256, get_all_by_tag


def generate_sha256(index: int) -> str:
    return hashlib.sha256(f"test_payload_{index}".encode()).hexdigest()


@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Inicializa o banco e limpa as tabelas antes de cada teste."""
    await init_db()
    
    db = await get_db()
    await db.execute("DELETE FROM tags_sha256;")
    await db.execute("DELETE FROM recent_cve;")
    await db.commit()
    
    yield
    await close_db()


@pytest.mark.asyncio
async def test_single_tag_insertion():
    """Testa inserção individual de tag, URL e SHA-256."""
    sha = generate_sha256(1)
    await add_tag_sha256("last_modified", "http://example.test/1", sha)

    results = await get_all_by_tag("last_modified")
    assert len(results) == 1
    assert results[0] == ("http://example.test/1", sha)


@pytest.mark.asyncio
async def test_bulk_insertion_multiple_tags():
    """Testa inserção em massa de centenas de SHA-256 divididos em tags diferentes."""
    tag_counts = {
        "tag_alpha": 150,
        "tag_beta": 250,
        "last_modified": 100,
    }

    inserted_map = {"tag_alpha": [], "tag_beta": [], "last_modified": []}
    counter = 0

    for tag, count in tag_counts.items():
        for _ in range(count):
            sha = generate_sha256(counter)
            await add_tag_sha256(tag, f"http://example.test/{counter}", sha)
            inserted_map[tag].append(sha)
            counter += 1

    for tag, expected_count in tag_counts.items():
        results = await get_all_by_tag(tag)
        assert len(results) == expected_count

        # Compara como conjunto (set) para ignorar a ordem de retorno do SQLite
        retrieved_shas = {item[1] for item in results}
        expected_shas = set(inserted_map[tag])
        assert retrieved_shas == expected_shas


@pytest.mark.asyncio
async def test_deduplication():
    """Garante que registros idênticos (mesma tag e mesmo sha256) não gerem duplicatas."""
    sha = generate_sha256(999)

    await add_tag_sha256("duplicate_test", "http://example.test/duplicate", sha)
    await add_tag_sha256("duplicate_test", "http://example.test/duplicate", sha)
    await add_tag_sha256("duplicate_test", "http://example.test/duplicate", sha)

    results = await get_all_by_tag("duplicate_test")
    assert len(results) == 1


@pytest.mark.asyncio
async def test_non_existing_tag():
    """Garante que buscar por uma tag inexistente retorne lista vazia."""
    results = await get_all_by_tag("non_existent_tag")
    assert results == []