from __future__ import annotations

from dataclasses import dataclass

VERSION_ATTACK = "16"


@dataclass(frozen=True)
class Tactica:
    tag: str
    navigator: str
    nombre: str
    orden: int


@dataclass(frozen=True)
class Tecnica:
    id: str
    nombre: str
    tacticas: tuple[str, ...]

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    @property
    def padre(self) -> str:
        return self.id.split(".")[0]


TACTICAS: dict[str, Tactica] = {
    tactica.tag: tactica
    for tactica in (
        Tactica("reconnaissance", "reconnaissance", "Reconocimiento", 1),
        Tactica("resource_development", "resource-development", "Desarrollo de recursos", 2),
        Tactica("initial_access", "initial-access", "Acceso inicial", 3),
        Tactica("execution", "execution", "Ejecución", 4),
        Tactica("persistence", "persistence", "Persistencia", 5),
        Tactica("privilege_escalation", "privilege-escalation", "Escalamiento de privilegios", 6),
        Tactica("defense_evasion", "defense-evasion", "Evasión de defensas", 7),
        Tactica("credential_access", "credential-access", "Acceso a credenciales", 8),
        Tactica("discovery", "discovery", "Descubrimiento", 9),
        Tactica("lateral_movement", "lateral-movement", "Movimiento lateral", 10),
        Tactica("collection", "collection", "Recolección", 11),
        Tactica("command_and_control", "command-and-control", "Comando y control", 12),
        Tactica("exfiltration", "exfiltration", "Exfiltración", 13),
        Tactica("impact", "impact", "Impacto", 14),
    )
}

# Subconjunto de ATT&CK Enterprise v16 con las técnicas que usan las reglas.
# El repo corre sin red, por eso el catálogo va embebido y no se descarga.
TECNICAS: dict[str, Tecnica] = {
    tecnica.id: tecnica
    for tecnica in (
        Tecnica("T1110", "Brute Force", ("credential_access",)),
        Tecnica("T1110.001", "Brute Force: Password Guessing", ("credential_access",)),
        Tecnica(
            "T1078",
            "Valid Accounts",
            ("defense_evasion", "persistence", "privilege_escalation", "initial_access"),
        ),
        Tecnica("T1021", "Remote Services", ("lateral_movement",)),
        Tecnica("T1021.004", "Remote Services: SSH", ("lateral_movement",)),
        Tecnica("T1136", "Create Account", ("persistence",)),
        Tecnica("T1136.001", "Create Account: Local Account", ("persistence",)),
        Tecnica("T1098", "Account Manipulation", ("persistence", "privilege_escalation")),
        Tecnica(
            "T1548",
            "Abuse Elevation Control Mechanism",
            ("privilege_escalation", "defense_evasion"),
        ),
        Tecnica(
            "T1548.003",
            "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
            ("privilege_escalation", "defense_evasion"),
        ),
        Tecnica("T1003", "OS Credential Dumping", ("credential_access",)),
        Tecnica(
            "T1003.008",
            "OS Credential Dumping: /etc/passwd and /etc/shadow",
            ("credential_access",),
        ),
        Tecnica(
            "T1053",
            "Scheduled Task/Job",
            ("execution", "persistence", "privilege_escalation"),
        ),
        Tecnica(
            "T1053.003",
            "Scheduled Task/Job: Cron",
            ("execution", "persistence", "privilege_escalation"),
        ),
        Tecnica(
            "T1543",
            "Create or Modify System Process",
            ("persistence", "privilege_escalation"),
        ),
        Tecnica(
            "T1543.002",
            "Create or Modify System Process: Systemd Service",
            ("persistence", "privilege_escalation"),
        ),
        Tecnica("T1505", "Server Software Component", ("persistence",)),
        Tecnica("T1505.003", "Server Software Component: Web Shell", ("persistence",)),
        Tecnica("T1059", "Command and Scripting Interpreter", ("execution",)),
        Tecnica("T1059.004", "Command and Scripting Interpreter: Unix Shell", ("execution",)),
        Tecnica("T1105", "Ingress Tool Transfer", ("command_and_control",)),
        Tecnica("T1095", "Non-Application Layer Protocol", ("command_and_control",)),
        Tecnica("T1070", "Indicator Removal", ("defense_evasion",)),
        Tecnica(
            "T1070.002",
            "Indicator Removal: Clear Linux or Mac System Logs",
            ("defense_evasion",),
        ),
        Tecnica("T1070.003", "Indicator Removal: Clear Command History", ("defense_evasion",)),
        Tecnica("T1048", "Exfiltration Over Alternative Protocol", ("exfiltration",)),
        Tecnica(
            "T1048.003",
            "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
            ("exfiltration",),
        ),
        Tecnica("T1071", "Application Layer Protocol", ("command_and_control",)),
        Tecnica("T1071.004", "Application Layer Protocol: DNS", ("command_and_control",)),
        Tecnica("T1046", "Network Service Discovery", ("discovery",)),
        Tecnica("T1552", "Unsecured Credentials", ("credential_access",)),
        Tecnica("T1552.003", "Unsecured Credentials: Bash History", ("credential_access",)),
    )
}


def tecnica(identificador: str) -> Tecnica:
    try:
        return TECNICAS[identificador.upper()]
    except KeyError:
        raise KeyError(f"técnica fuera del catálogo embebido: {identificador}") from None
