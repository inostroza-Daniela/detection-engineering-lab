from __future__ import annotations

from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection

from detectionlab.reglas import Coleccion, Regla, cargar_reglas


def cargar_reglas_desde_texto(yaml: str, carpeta: Path) -> Coleccion:
    for indice, documento in enumerate(yaml.split("\n---\n")):
        (carpeta / f"regla_{indice}.yml").write_text(documento, encoding="utf-8")
    return cargar_reglas(carpeta)


ENCABEZADO = """
title: Regla de prueba
id: 00000000-0000-4000-8000-000000000001
name: prueba
logsource:
  product: linux
  service: auditd
"""


def regla_desde(detection: str, encabezado: str = ENCABEZADO) -> Regla:
    sigma = SigmaCollection.from_yaml(encabezado + "detection:\n" + detection).rules[0]
    return Regla(sigma=sigma, ruta=Path("prueba.yml"))


def coleccion_desde(yaml: str, resolver: bool = True) -> Coleccion:
    sigma = SigmaCollection.from_yaml(yaml, resolve_references=resolver)
    reglas = [Regla(sigma=r, ruta=Path(f"{r.name}.yml")) for r in sigma.rules]
    reglas.sort(key=lambda r: (r.es_correlacion, r.nombre))
    return Coleccion(reglas)


def evento_auditd(instante: str = "2026-11-10T08:00:00.000-0300", **audit: Any) -> dict[str, Any]:
    return {
        "timestamp": instante,
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.10.21"},
        "decoder": {"name": "auditd"},
        "rule": {"id": "80792", "groups": ["audit", "audit_command"]},
        "data": {"audit": audit},
        "full_log": "type=SYSCALL ...",
    }


def evento_sshd(instante: str, ip: str, exito: bool, usuario: str = "dani") -> dict[str, Any]:
    grupos = ["syslog", "sshd", "authentication_success" if exito else "authentication_failed"]
    return {
        "timestamp": instante,
        "agent": {"id": "003", "name": "bastion-01", "ip": "10.0.1.5"},
        "decoder": {"name": "sshd"},
        "rule": {"id": "5715" if exito else "5716", "groups": grupos},
        "data": {"srcip": ip, "srcport": "50000", "dstuser": usuario},
        "full_log": "sshd: ...",
    }
