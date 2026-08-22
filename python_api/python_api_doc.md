# Documentação de Uso

Esta aplicação foi desenvolvida em Python com FastAPI e SQLite (aiosqlite) para permitir a realização de testes rápidos e prototipagem sem a necessidade de alterar ou recompilar a versão original escrita em Rust.

Ela reproduz os mesmos endpoints e comportamentos da implementação original, processando cargas de dados e salvando registros para pesquisas posteriores.

---

## Requisitos e Instalação

### Dependências

Para instalar os pacotes necessários, execute:

`pip install fastapi "uvicorn[standard]" aiosqlite`

Arquivo `requirements.txt`:

fastapi
uvicorn[standard]
aiosqlite

---

## Como Executar

Para iniciar o servidor localmente na porta 3000:

`python main.py`

A aplicação ficará disponível em `http://127.0.0.1:3000`.

A documentação interativa das rotas pode ser acessada pelo navegador em:
- `http://127.0.0.1:3000/docs`

---

## Estrutura dos Arquivos

- `main.py`: Contém a definição das rotas do servidor e o recebimento das requisições HTTP.
- `database.py`: Contém as funções de conexão e escrita assíncrona no arquivo de banco de dados SQLite (`cve_data.db`).

---

## Guia de Uso

### 1. Enviar arquivo de dados (`POST /cve`)

Recebe o conteúdo bruto em bytes do arquivo JSON no corpo da requisição, extrai cada registro individualmente e faz a gravação em lote no banco de dados.

- **Rota:** `/cve`
- **Método:** `POST`
- **Corpo:** Dados em bytes do arquivo JSON.

**Exemplo de envio em Python:**

import asyncio
import httpx


async def main():
    with open("nvd.json", "rb") as f:
        raw_file = f.read()

    async with httpx.AsyncClient(timeout=100) as client:
        response = await client.post(
            "http://localhost:3000/cve",
            content=raw_file,
        )
        print("Status:", response.status_code)
        print("Resposta:", response.json())


asyncio.run(main())

---

### 2. Pesquisar registro por ID (`GET /cve/{cve_id}`)

Realiza a busca direta de um registro específico armazenado no banco de dados.

- **Rota:** `/cve/{cve_id}`
- **Método:** `GET`

**Exemplo de uso via terminal:**

`curl http://localhost:3000/cve/CVE-2023-38545`

---

### 3. Listar registros recentes (`GET /cve`)

Retorna a lista dos registros mais recentes gravados no banco, ordenados pela data de modificação.

- **Rota:** `/cve`
- **Método:** `GET`
- **Parâmetros de URL:**
  - `limit` (opcional, valor padrão: 100): Quantidade de itens retornados.

**Exemplo de uso via terminal:**

`curl "http://localhost:3000/cve?limit=10"`

AI FOI E ESTA SENDO FORTMENTE UTILIZADA NESTA PARTE DO PROJETO, SAO ESPERADOS ERROS.