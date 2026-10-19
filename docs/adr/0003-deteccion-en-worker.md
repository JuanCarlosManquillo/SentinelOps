# ADR 0003 — Detección en un worker separado de la API

**Estado:** aceptada · 2026-10-17

## Contexto
Si la detección corre dentro de `POST /events`, la latencia de ingesta depende del cálculo.

## Decisión
La API solo valida y persiste. Un worker procesa ventanas de 1 minuto desde un checkpoint
persistente; las anomalías tienen clave idempotente `(service, detector, signal, window_start)`.

## Consecuencias
+ Ingesta rápida y predecible; worker reiniciable sin duplicados.
− El diagnóstico llega con el retraso de una ventana.
