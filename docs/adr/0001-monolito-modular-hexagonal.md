# ADR 0001 — Monolito modular con arquitectura hexagonal

**Estado:** aceptada · 2026-10-17

## Contexto
Un único desarrollador con menos de 10 horas semanales. Hay que poder explicar y operar todo.

## Decisión
Un repositorio, un paquete Python, dos procesos (API y worker). Dominio aislado mediante
puertos (`Protocol`) y adaptadores. Nada de microservicios.

## Consecuencias
+ Menos operación; pruebas del dominio sin base de datos.
+ El límite entre módulos se verifica con `import-linter`.
− Escalar partes por separado exige más adelante una cola (ver sección de escalabilidad).
