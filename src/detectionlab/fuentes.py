from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from detectionlab.eventos import Evento, obtener_campo

Filtro = Callable[[Evento], bool]


@dataclass(frozen=True)
class FuenteLog:
    nombre: str
    descripcion: str
    filtro: Filtro


def _decoder(*nombres: str) -> Filtro:
    permitidos = frozenset(nombres)

    def filtro(evento: Evento) -> bool:
        nombre = obtener_campo(evento, "decoder.name")
        return isinstance(nombre, str) and nombre in permitidos

    return filtro


def _suricata(tipo_evento: str) -> Filtro:
    def filtro(evento: Evento) -> bool:
        return bool(
            obtener_campo(evento, "decoder.name") == "json"
            and obtener_campo(evento, "data.event_type") == tipo_evento
        )

    return filtro


# Clave: (product, category, service) tal como aparece en el `logsource` Sigma.
# Cada entrada dice qué eventos del formato Wazuh pertenecen a esa fuente.
FUENTES: dict[tuple[str, str, str], FuenteLog] = {
    ("linux", "", "sshd"): FuenteLog(
        "sshd",
        "Eventos de sshd decodificados desde /var/log/auth.log",
        _decoder("sshd"),
    ),
    ("linux", "", "auditd"): FuenteLog(
        "auditd",
        "Registros de auditd (SYSCALL, EXECVE, PATH) agrupados por Wazuh",
        _decoder("auditd"),
    ),
    ("linux", "", "sudo"): FuenteLog(
        "sudo",
        "Eventos de sudo decodificados desde /var/log/auth.log",
        _decoder("sudo"),
    ),
    ("linux", "", "auth"): FuenteLog(
        "auth",
        "Todo /var/log/auth.log: sshd, sudo, su y PAM",
        _decoder("sshd", "sudo", "su", "pam_unix", "pam"),
    ),
    ("linux", "dns_query", ""): FuenteLog(
        "suricata_dns",
        "Consultas DNS de Suricata (eve.json, event_type=dns)",
        _suricata("dns"),
    ),
    ("linux", "network_connection", ""): FuenteLog(
        "suricata_flow",
        "Flujos de red de Suricata (eve.json, event_type=flow)",
        _suricata("flow"),
    ),
}


class ErrorFuente(ValueError):
    pass


def fuente_de(logsource: dict[str, str]) -> FuenteLog:
    clave = (
        logsource.get("product", ""),
        logsource.get("category", ""),
        logsource.get("service", ""),
    )
    try:
        return FUENTES[clave]
    except KeyError:
        descripcion = ", ".join(f"{k}={v}" for k, v in logsource.items()) or "(vacío)"
        raise ErrorFuente(f"logsource sin fuente conocida: {descripcion}") from None
