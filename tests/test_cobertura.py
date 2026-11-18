from __future__ import annotations

import pytest

from ayudas import coleccion_desde
from detectionlab.attack import TECNICAS, tecnica
from detectionlab.cobertura import calcular, capa_navigator
from detectionlab.reglas import Coleccion


def test_cobertura_del_repo(coleccion: Coleccion) -> None:
    cobertura = calcular(coleccion)
    assert cobertura.total_tecnicas >= 12
    assert cobertura.total_tacticas >= 7
    nombres = {c.tactica.tag for c in cobertura.tacticas}
    assert {"credential_access", "persistence", "defense_evasion", "execution"} <= nombres
    resumen = cobertura.resumen()
    assert all(fila["reglas"] >= 1 for fila in resumen)
    t1110 = cobertura.tecnicas["T1110.001"]
    assert "ssh_fuerza_bruta" in t1110.reglas


def test_capa_navigator(coleccion: Coleccion) -> None:
    capa = capa_navigator(calcular(coleccion))
    assert capa["domain"] == "enterprise-attack"
    assert capa["versions"]["layer"] == "4.5"
    ids = {(t["techniqueID"], t["tactic"]) for t in capa["techniques"]}
    assert ("T1110.001", "credential-access") in ids
    assert ("T1070.003", "defense-evasion") in ids
    for item in capa["techniques"]:
        assert item["score"] >= 1
        assert item["color"].startswith("#")
        assert item["comment"]


def test_catalogo_consistente() -> None:
    for identificador, tec in TECNICAS.items():
        assert tec.id == identificador
        assert tec.tacticas
        if "." in identificador:
            assert tec.padre in TECNICAS
            assert tec.nombre.startswith(TECNICAS[tec.padre].nombre)
    assert tecnica("t1046").url == "https://attack.mitre.org/techniques/T1046/"
    assert tecnica("T1110.001").url == "https://attack.mitre.org/techniques/T1110/001/"
    with pytest.raises(KeyError):
        tecnica("T9999")


def test_tecnica_fuera_del_catalogo_es_error() -> None:
    yaml = """
title: X
id: 00000000-0000-4000-8000-0000000000aa
name: x
tags: [attack.execution, attack.t9999]
logsource: {product: linux, service: auditd}
detection:
  sel: {a: b}
  condition: sel
"""
    with pytest.raises(KeyError, match="T9999"):
        calcular(coleccion_desde(yaml))
