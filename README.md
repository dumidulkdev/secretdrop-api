# SecretDrop API

SecretDrop is a self-destructing, encrypted secret-sharing REST API. It solves the everyday problem of sending passwords, API keys, and recovery codes over chat or email—channels that leave permanent copies in inboxes and logs.

Each secret is encrypted at rest, accessed only via an unguessable token, and destroyed after a view limit or TTL. Optional passphrases add another layer when you need to share the link and the password through different channels.

## Features

- **Create secrets** with configurable expiry (5 minutes to 7 days), view limits (1–10), and optional passphrase
- **AES-256-GCM** encryption at rest with per-secret IVs; master key from environment
- **Token hashing** — only SHA-256 hashes of access/delete tokens are stored
- **Burn after read** — atomic reveal with pessimistic locking for concurrent access
- **Passphrase protection** — PBKDF2 key derivation plus BCrypt verification; burn after repeated failures
- **Rate limiting** — per-IP limits on reveal/status (Bucket4j, in-memory)
- **Scheduled cleanup** of expired records
- **Audit log** — lifecycle events without content or raw tokens
- **OpenAPI** documentation at [`/swagger-ui.html`](http://localhost:8080/swagger-ui.html)

## Security design

| Layer | Approach |
|--------|-----------|
| Content | AES-256-GCM; random 12-byte IV per secret |
| Keys | Master key from `SECRETDROP_MASTER_KEY`; optional PBKDF2WithHmacSHA256 (210k iterations) when a passphrase is set |
| Tokens | URL-safe random (≥128 bits); only hashes persisted |
| Access | Stateless Spring Security; hardened HTTP headers; sessions disabled |
| Abuse | IP rate limits; passphrase attempt cap (default 5) then burn |
| Disclosure | Expired/missing/burned secrets return **404** with no hint |

## Tech stack

Java 21 · Spring Boot 3.4 · Spring Web · Data JPA · Security · Validation · PostgreSQL (prod) / H2 (local) · Bucket4j · springdoc-openapi · Docker

## Quick start

### Prerequisites

- JDK 21
- Maven 3.9+
- Docker (optional)

### Run locally (H2)

```bash
mvn spring-boot:run
```

The local profile uses an embedded H2 database and a development-only master key in `application.yml`. **Do not use that key in production.**

### Run with PostgreSQL (Docker Compose)

```bash
mvn -DskipTests package
docker compose up --build
```

Set a strong master key in the environment:

```bash
export SECRETDROP_MASTER_KEY="$(openssl rand -base64 32)"
```

Compose wires `SECRETDROP_MASTER_KEY` for the app service; override it before any real deployment.

### Configuration

| Variable | Description |
|----------|-------------|
| `SECRETDROP_MASTER_KEY` | Required in **prod**; seeds AES key material |
| `DATABASE_URL` | JDBC URL (default `jdbc:postgresql://localhost:5432/secretdrop`) |
| `DATABASE_USER` / `DATABASE_PASSWORD` | Database credentials |
| `SPRING_PROFILES_ACTIVE` | `local` (default) or `prod` |

## Example usage

Create a one-view secret:

```bash
curl -s -X POST http://localhost:8080/api/secrets \
  -H 'Content-Type: application/json' \
  -d '{"content":"super-secret-password","maxViews":1,"expiryMinutes":30}' | jq
```

Reveal (returns content, then burns on last view):

```bash
TOKEN="paste-access-token-from-create-response"
curl -s "http://localhost:8080/api/secrets/${TOKEN}/reveal" | jq
```

Second reveal returns **404**:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://localhost:8080/api/secrets/${TOKEN}/reveal"
```

Check status without revealing:

```bash
curl -s "http://localhost:8080/api/secrets/${TOKEN}/status" | jq
```

Delete early with the delete token:

```bash
DELETE_TOKEN="paste-delete-token-from-create-response"
curl -s -X DELETE "http://localhost:8080/api/secrets/${TOKEN}" \
  -H "X-Delete-Token: ${DELETE_TOKEN}"
```

## Project structure

```
src/main/java/com/secretdrop/
├── audit/          # Audit entities, repository, controller
├── config/         # Security, OpenAPI, configuration properties
├── crypto/         # AES-GCM encryption and token utilities
├── ratelimit/      # Bucket4j per-IP limiter
├── secret/         # Core domain — entity, service, controller, cleanup job
└── common/         # API response wrappers, exception handler, client IP helper
```

## What I learned

- **AES-GCM** needs a unique IV per encryption; reuse breaks confidentiality and integrity.
- **PBKDF2** stretches low-entropy passphrases into proper key material when combined with a server master secret.
- **Hashing ≠ encryption** — store token hashes for lookup; never store plaintext tokens or secrets.
- **Secure random tokens** beat predictable IDs for unguessable links.
- **Pessimistic locking** (or versioning) makes burn-after-read safe under concurrent reveals.
- **Bucket4j** offers a simple in-memory throttle; production might need a shared store.
- **`@Scheduled` cleanup** catches expired secrets that were never viewed.

## Development

```bash
mvn verify          # unit + integration tests
mvn spring-boot:run # local profile on port 8080
```

## License

[MIT License](LICENSE). Developed by Dumidu Lakshan.