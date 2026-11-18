from __future__ import annotations

import copy
import re
from typing import Any

from detectionlab.eventos import Evento

_RE_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2}){2,}$")
_RE_ARG = re.compile(r"^a(\d+)$")

CAMPO_CMDLINE = "cmdline"


def enriquecer(evento: Evento) -> Evento:
    """Devuelve una copia del evento con los argumentos de auditd listos para evaluar.

    auditd codifica en hexadecimal cualquier argumento con espacios o comillas,
    y Wazuh los deja tal cual en `data.audit.execve.aN`. Aquí se decodifican y
    se arma `data.audit.execve.cmdline` con la línea de comando completa, que
    es lo que las reglas usan para buscar patrones.
    """
    data = evento.get("data")
    if not isinstance(data, dict):
        return evento
    audit = data.get("audit")
    if not isinstance(audit, dict):
        return evento
    execve = audit.get("execve")
    if not isinstance(execve, dict):
        return evento

    copia = copy.deepcopy(evento)
    execve_copia: dict[str, Any] = copia["data"]["audit"]["execve"]
    argumentos: list[tuple[int, str]] = []
    for clave, valor in execve_copia.items():
        coincidencia = _RE_ARG.match(clave)
        if coincidencia is None or not isinstance(valor, str):
            continue
        decodificado = _decodificar(valor)
        execve_copia[clave] = decodificado
        argumentos.append((int(coincidencia.group(1)), decodificado))
    if CAMPO_CMDLINE not in execve_copia:
        execve_copia[CAMPO_CMDLINE] = " ".join(
            valor for _, valor in sorted(argumentos, key=lambda par: par[0])
        )
    return copia


def _decodificar(valor: str) -> str:
    """auditd solo codifica argumentos con espacios, comillas o bytes fuera de 0x21-0x7E.

    Si el texto decodificado no contiene ninguno de esos caracteres, el valor
    original era un argumento legítimo que solo parece hexadecimal (`4444`,
    `5432`, `deadbeef`) y se deja tal cual.
    """
    if not _RE_HEX.match(valor):
        return valor
    try:
        texto = bytes.fromhex(valor).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return valor
    if not all(caracter.isprintable() or caracter in "\t\n" for caracter in texto):
        return valor
    if _necesitaba_codificacion(texto):
        return texto
    return valor


def _necesitaba_codificacion(texto: str) -> bool:
    if any(caracter == " " or not (0x21 <= ord(caracter) <= 0x7E) for caracter in texto):
        return True
    return '"' in texto and any(caracter.isalnum() for caracter in texto)
