# ADR 0005 — API keys con scopes en lugar de OAuth en la v1

**Estado:** aceptada · 2026-10-17

## Decisión
Claves aleatorias de 256 bits con prefijo `so_`, guardadas como SHA-256, con scopes
(`events:write`, `deployments:write`, `incidents:read`, `incidents:write`) y revocables.

## Consecuencias
+ Simple y suficiente para integraciones máquina a máquina.
− Sin rotación automática ni identidad de usuario final; OAuth/OIDC si se añade un panel multiusuario.
