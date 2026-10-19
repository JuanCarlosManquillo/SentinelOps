"""Errores de dominio. La capa API los traduce a HTTP en un unico manejador."""

from __future__ import annotations


class DomainError(Exception):
    """Base de todos los errores de dominio."""


class InvalidValue(DomainError):
    """Un objeto valor recibió un dato fuera de su rango."""


class InvalidTransition(DomainError):
    def __init__(self, current: str, target: str) -> None:
        super().__init__(f"transición no permitida: {current} → {target}")
        self.current = current
        self.target = target


class EventRejected(DomainError):
    """Un evento no supera las reglas de ingesta (p. ej., marca de tiempo futura)."""
