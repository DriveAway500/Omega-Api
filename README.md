# Omega API

© 2026 WhaleHook. All rights reserved.

A **Omega API** fornece uma interface para os serviços do ecossistema Omega, centralizando o acesso e o gerenciamento dos dados utilizados por seus componentes.

A aplicação utiliza uma arquitetura assíncrona baseada em **Rust**, **Axum**, **Tokio** e **SQLite**.

## Tecnologias

* [Rust](https://www.rust-lang.org/)
* [Axum](https://github.com/tokio-rs/axum)
* [Tokio](https://tokio.rs/)
* [SQLx](https://github.com/launchbadge/sqlx)
* SQLite

## Estrutura

```text
src/
├── api.rs       # Rotas e handlers da API
├── db.rs        # Camada de acesso ao banco de dados
└── main.rs      # Inicialização da aplicação
```

A separação entre API, banco de dados e inicialização permite que os componentes sejam desenvolvidos e modificados de forma independente.

## Executando

Clone o projeto e execute:

```bash
cargo run
```

Por padrão, a aplicação inicia o servidor em:

```text
http://localhost:3000
```

O banco de dados SQLite é criado automaticamente no diretório de execução quando necessário.

## Testando

A API pode ser testada diretamente utilizando `curl`.

Para adicionar um tópico:

```bash
curl -X POST localhost:3000/topics -d "rust"
```

Para consultar os tópicos registrados:

```bash
curl localhost:3000/topics
```

Uma resposta pode ser semelhante a:

```json
[[1,"rust"]]
```

Esses endpoints também podem ser utilizados para validar a comunicação entre os componentes que consomem a API.

## API

### `POST /topics`

Adiciona um tópico ao banco de dados.

**Corpo da requisição:**

```text
rust
```

**Resposta:**

```json
1
```

O valor retornado corresponde ao identificador atribuído ao registro.

### `GET /topics`

Retorna os tópicos armazenados no banco de dados.

**Resposta:**

```json
[
    [1, "rust"],
    [2, "python"]
]
```

## Desenvolvimento

A API foi estruturada para servir como uma camada de comunicação entre os componentes do sistema e sua camada de persistência.

Novos endpoints, recursos e modelos de dados podem ser adicionados conforme os requisitos do ecossistema evoluem, mantendo a separação entre as responsabilidades de cada módulo.

## Licença

Este projeto é software proprietário.

© 2026 WhaleHook. All rights reserved.
