# ADR 0006 — Detectores estadísticos sobre la ventana (sin baseline histórico en v1)

**Estado:** aceptada · 2026-10-27

## Decisión
Los detectores estadísticos (z-score robusto con MAD y EWMA) implementan el mismo puerto
`Detector` y operan **dentro de cada ventana**: comparan los eventos de la ventana entre sí,
sin guardar una línea base histórica por servicio. Siguen siendo funciones puras y sin estado,
igual que el detector por umbral.

- **Z-score robusto (MAD):** marca un servicio cuando algunas latencias están muy por encima
  de su propia mediana, medidas en desviaciones robustas (MAD). Detecta valores atípicos.
- **EWMA:** sobre las latencias en orden de tiempo, marca cuando el nivel suavizado de la
  segunda mitad de la ventana sube por un factor respecto a la primera. Detecta tendencia.

## Consecuencias
+ No hace falta fijar un umbral absoluto (p. ej. 1000 ms): cada detector se adapta a los datos.
+ Encaja sin cambios en el puerto `Detector` ni en el worker; siguen siendo puros y testeables.
− No detectan cambios lentos entre ventanas (una degradación de días). Un baseline persistente
  por servicio queda como mejora futura.
