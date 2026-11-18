from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

Evento = dict[str, Any]

_AUSENTE = object()


class ErrorEvento(ValueError):
    pass


def cargar_eventos(ruta: Path) -> list[Evento]:
    texto = ruta.read_text(encoding="utf-8")
    if ruta.suffix.lower() == ".jsonl":
        eventos = []
        for numero, linea in enumerate(texto.splitlines(), start=1):
            if not linea.strip():
                continue
            try:
                eventos.append(json.loads(linea))
            except json.JSONDecodeError as exc:
                raise ErrorEvento(f"{ruta}:{numero}: JSON inválido ({exc.msg})") from exc
        return _validar_lista(eventos, ruta)
    try:
        contenido = json.loads(texto)
    except json.JSONDecodeError as exc:
        raise ErrorEvento(f"{ruta}: JSON inválido ({exc.msg})") from exc
    if isinstance(contenido, dict):
        contenido = [contenido]
    return _validar_lista(contenido, ruta)


def cargar_directorio(directorio: Path) -> list[Evento]:
    eventos: list[Evento] = []
    for ruta in sorted(directorio.rglob("*")):
        if ruta.suffix.lower() in {".json", ".jsonl"} and ruta.is_file():
            eventos.extend(cargar_eventos(ruta))
    return eventos


def _validar_lista(contenido: Any, ruta: Path) -> list[Evento]:
    if not isinstance(contenido, list):
        raise ErrorEvento(f"{ruta}: se esperaba una lista de eventos")
    for indice, evento in enumerate(contenido):
        if not isinstance(evento, dict):
            raise ErrorEvento(f"{ruta}: el evento {indice} no es un objeto JSON")
    return contenido


def obtener_campo(evento: Evento, campo: str) -> Any:
    """Resuelve una ruta con puntos (`data.audit.exe`) dentro del evento.

    Devuelve `None` tanto cuando el campo existe con valor nulo como cuando no
    existe; usar `existe_campo` para distinguir ambos casos.
    """
    actual: Any = evento
    for parte in campo.split("."):
        if isinstance(actual, dict):
            actual = actual.get(parte, _AUSENTE)
        else:
            return None
        if actual is _AUSENTE:
            return None
    return actual


def existe_campo(evento: Evento, campo: str) -> bool:
    actual: Any = evento
    for parte in campo.split("."):
        if not isinstance(actual, dict) or parte not in actual:
            return False
        actual = actual[parte]
    return True


def valores_planos(evento: Evento) -> Iterable[str]:
    pila: list[Any] = [evento]
    while pila:
        actual = pila.pop()
        if isinstance(actual, dict):
            pila.extend(actual.values())
        elif isinstance(actual, list):
            pila.extend(actual)
        elif actual is not None:
            yield str(actual)


def marca_tiempo(evento: Evento) -> datetime:
    bruto = evento.get("timestamp")
    if not isinstance(bruto, str):
        raise ErrorEvento("el evento no tiene un campo `timestamp` de texto")
    texto = bruto[:-1] + "+00:00" if bruto.endswith("Z") else bruto
    try:
        instante = datetime.fromisoformat(texto)
    except ValueError as exc:
        raise ErrorEvento(f"timestamp no reconocido: {bruto!r}") from exc
    if instante.tzinfo is None:
        instante = instante.replace(tzinfo=UTC)
    return instante
