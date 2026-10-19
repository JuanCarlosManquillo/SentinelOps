# ADR 0004 — Diagnóstico determinista por reglas antes de cualquier LLM

**Estado:** aceptada · 2026-10-17

## Decisión
Las hipótesis las producen reglas deterministas; toda hipótesis exige al menos una evidencia
(el dominio lo impone). Un LLM local solo podrá redactar explicaciones, desactivado por defecto,
cuando el flujo determinista esté evaluado.

## Consecuencias
+ Resultados reproducibles y medibles.
− Cobertura de causas limitada a las reglas escritas.
