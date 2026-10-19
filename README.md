# SentinelOps

Diagnóstico de incidentes con evidencias. Recibe logs y métricas, detecta anomalías,
agrupa los eventos relacionados en incidentes y propone causas candidatas que apuntan
a eventos concretos. Mide si sus diagnósticos aciertan contra un dataset con incidentes
conocidos.

> **Estado: versión base (semana 0).** Ingesta segura, detector por umbral, correlación y
> diagnóstico mínimos con pruebas. Las cifras de evaluación se publicarán en la semana 4;
> hasta entonces este README no afirma ninguna precisión.

## Arranque rápido

```bash
# Sin Docker: pruebas y demo
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                   # unitarias, integración (SQLite) y humo de evaluación
python -m sentinelops.worker --demo      # pipeline completo sobre datos sintéticos

# Con Docker: API + PostgreSQL
cp .env.example .env                      # cambia POSTGRES_PASSWORD
docker compose up --build -d
docker compose exec api python scripts/create_api_key.py --name demo --scopes events:write
# Swagger UI: http://127.0.0.1:8000/docs
```

Enviar eventos:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H "X-API-Key: so_..." -H "Content-Type: application/json" \
  -d '{"events":[{"event_id":"checkout-1","service":"checkout","kind":"http_error",
       "severity":"error","occurred_at":"2026-10-17T10:00:01Z",
       "attributes":{"http.status_code":503,"latency_ms":1840}}]}'
```

## Arquitectura

Monolito modular con arquitectura hexagonal: el dominio no importa FastAPI ni SQLAlchemy
(lo verifica `import-linter` en CI). La API solo valida y persiste; el análisis corre en
un worker por ventanas.

```
src/sentinelops/
├── domain/        entidades inmutables, objetos valor, puertos (Protocol)
├── detection/     detectores (Strategy), funciones puras
├── correlation/   agrupación de anomalías en incidentes
├── diagnosis/     reglas de hipótesis con evidencias
├── application/   casos de uso: ingest, analyze
├── ingestion/     generador sintético y redacción de secretos
├── persistence/   modelos y repositorios SQLAlchemy
├── api/           FastAPI: rutas, esquemas, auth, errores, middleware
├── bootstrap.py   composición de dependencias
└── worker.py      análisis por ventanas
```

El diseño completo (requisitos, diagramas, seguridad, escalabilidad y plan semanal) está
en el documento de arquitectura. Las decisiones se registran en `docs/adr/`.

## Seguridad implementada

| Control | Dónde |
| --- | --- |
| API key por cliente, guardada como SHA-256, con scopes (401/403) | `api/auth.py` |
| Esquema estricto: campos desconocidos y fechas sin zona → 422 | `api/schemas.py` |
| Límite de 500 eventos y de tamaño de cuerpo → 413 | `api/schemas.py`, `api/middleware.py` |
| Rechazo de marcas de tiempo futuras (> 5 min) o antiguas (> 7 días) | `application/ingest.py` |
| Redacción de secretos antes de persistir | `ingestion/redaction.py` |
| Ingesta idempotente por `event_id` | `persistence/repositories.py` |
| Errores RFC 9457 sin trazas ni valores de entrada | `api/errors.py` |
| Cabeceras de seguridad y `X-Request-ID` | `api/middleware.py` |
| Contenedor sin root, multi-stage, sistema de archivos de solo lectura | `Dockerfile`, `compose.yaml` |

## Calidad

`ruff`, `mypy --strict`, `bandit`, `pip-audit`, `gitleaks` e `import-linter` en CI.

## Limitaciones conocidas

- Datos sintéticos: más limpios que los reales.
- La latencia anómala se detecta, pero aún no hay regla de diagnóstico para saturación (semana 3).
- Las pruebas de integración usan SQLite; PostgreSQL real con testcontainers llega en la semana 1.
- Un solo inquilino; sin rotación automática de claves.
