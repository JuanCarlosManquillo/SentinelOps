# ADR 0002 — PostgreSQL como único almacén en la v1

**Estado:** aceptada · 2026-10-17

## Contexto
Hace falta guardar eventos, anomalías, incidentes e hipótesis con consultas por servicio y tiempo.

## Decisión
PostgreSQL 16 con índices `(service, occurred_at)`, JSONB para atributos y particionado diario
cuando el volumen lo justifique. Sin almacén de series temporales dedicado en la v1.

## Consecuencias
+ Una sola tecnología de datos; transacciones para guardar análisis y checkpoint juntos.
− Con alta cardinalidad de métricas habrá que evaluar TimescaleDB u otro backend.
