from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from ayudas import coleccion_desde, evento_sshd
from detectionlab.correlacion import ErrorCorrelacion, correlacionar
from detectionlab.motor import evaluar

_ZONA = timezone(timedelta(hours=-3))
_INICIO = datetime(2026, 11, 10, 8, 0, tzinfo=_ZONA)

_BASE = """
title: Fallo
id: 00000000-0000-4000-8000-000000000001
name: fallo
logsource: {product: linux, service: sshd}
detection:
  sel:
    rule.groups|contains: 'authentication_failed'
  condition: sel
---
title: Exito
id: 00000000-0000-4000-8000-000000000002
name: exito
logsource: {product: linux, service: sshd}
detection:
  sel:
    rule.groups|contains: 'authentication_success'
  condition: sel
"""


def _ts(segundos: float) -> str:
    instante = _INICIO + timedelta(seconds=segundos)
    return instante.strftime("%Y-%m-%dT%H:%M:%S.000%z")


def _fallos(
    cantidad: int, cada: float, ip: str = "203.0.113.45", desde: float = 0
) -> list[dict[str, Any]]:
    return [evento_sshd(_ts(desde + i * cada), ip, exito=False) for i in range(cantidad)]


class TestEventCount:
    YAML = (
        _BASE
        + """
---
title: Ráfaga
id: 00000000-0000-4000-8000-000000000003
name: rafaga
correlation:
  type: event_count
  rules: [fallo]
  group-by: [data.srcip]
  timespan: 1m
  condition:
    gte: 5
"""
    )

    def test_dispara_al_alcanzar_el_umbral_y_reinicia(self) -> None:
        resultado = evaluar(coleccion_desde(self.YAML), _fallos(12, 5))
        rafagas = resultado.por_regla()["rafaga"]
        assert len(rafagas) == 2
        assert rafagas[0].cuenta == 5
        assert rafagas[0].grupo == {"data.srcip": "203.0.113.45"}
        assert rafagas[0].instante == _INICIO + timedelta(seconds=20)
        assert [d.regla.nombre for d in rafagas[0].origen] == ["fallo"] * 5

    def test_no_dispara_fuera_de_la_ventana(self) -> None:
        resultado = evaluar(coleccion_desde(self.YAML), _fallos(8, 20))
        assert "rafaga" not in resultado.nombres_disparados()

    def test_agrupa_por_origen(self) -> None:
        eventos = _fallos(3, 1, ip="10.0.0.1") + _fallos(3, 1, ip="10.0.0.2")
        resultado = evaluar(coleccion_desde(self.YAML), eventos)
        assert "rafaga" not in resultado.nombres_disparados()

    def test_eventos_desordenados_se_ordenan(self) -> None:
        eventos = list(reversed(_fallos(5, 5)))
        resultado = evaluar(coleccion_desde(self.YAML), eventos)
        assert len(resultado.por_regla()["rafaga"]) == 1


class TestValueCount:
    YAML = (
        _BASE
        + """
---
title: Usuarios distintos
id: 00000000-0000-4000-8000-000000000004
name: usuarios_distintos
correlation:
  type: value_count
  rules: [fallo]
  group-by: [data.srcip]
  timespan: 1m
  condition:
    field: data.dstuser
    gte: 3
"""
    )

    def test_cuenta_valores_distintos(self) -> None:
        eventos = [
            evento_sshd(_ts(i), "203.0.113.45", exito=False, usuario=usuario)
            for i, usuario in enumerate(["root", "root", "admin", "root", "pi"])
        ]
        resultado = evaluar(coleccion_desde(self.YAML), eventos)
        disparos = resultado.por_regla()["usuarios_distintos"]
        assert len(disparos) == 1
        assert disparos[0].cuenta == 3

    def test_mismo_valor_repetido_no_dispara(self) -> None:
        resultado = evaluar(coleccion_desde(self.YAML), _fallos(10, 1))
        assert "usuarios_distintos" not in resultado.nombres_disparados()


class TestTemporal:
    ORDENADO = (
        _BASE
        + """
---
title: Exito tras fallo
id: 00000000-0000-4000-8000-000000000005
name: exito_tras_fallo
correlation:
  type: temporal_ordered
  rules: [fallo, exito]
  group-by: [data.srcip]
  timespan: 2m
"""
    )
    SIN_ORDEN = ORDENADO.replace("temporal_ordered", "temporal").replace(
        "exito_tras_fallo", "fallo_y_exito"
    )

    def test_ordenado_respeta_secuencia_y_ventana(self) -> None:
        coleccion = coleccion_desde(self.ORDENADO)
        bien = [*_fallos(1, 1), evento_sshd(_ts(30), "203.0.113.45", exito=True)]
        assert "exito_tras_fallo" in evaluar(coleccion, bien).nombres_disparados()
        invertido = [evento_sshd(_ts(0), "203.0.113.45", exito=True), *_fallos(1, 1, desde=30)]
        assert "exito_tras_fallo" not in evaluar(coleccion, invertido).nombres_disparados()
        tarde = [*_fallos(1, 1), evento_sshd(_ts(200), "203.0.113.45", exito=True)]
        assert "exito_tras_fallo" not in evaluar(coleccion, tarde).nombres_disparados()
        otra_ip = [*_fallos(1, 1), evento_sshd(_ts(30), "10.0.0.9", exito=True)]
        assert "exito_tras_fallo" not in evaluar(coleccion, otra_ip).nombres_disparados()

    def test_sin_orden_acepta_cualquier_secuencia(self) -> None:
        coleccion = coleccion_desde(self.SIN_ORDEN)
        invertido = [evento_sshd(_ts(0), "203.0.113.45", exito=True), *_fallos(1, 1, desde=30)]
        disparos = evaluar(coleccion, invertido).por_regla()["fallo_y_exito"]
        assert len(disparos) == 1
        assert [d.regla.nombre for d in disparos[0].origen] == ["exito", "fallo"]

    def test_correlacion_sobre_correlacion(self) -> None:
        yaml = (
            TestEventCount.YAML
            + """
---
title: Exito tras ráfaga
id: 00000000-0000-4000-8000-000000000006
name: exito_tras_rafaga
correlation:
  type: temporal_ordered
  rules: [rafaga, exito]
  group-by: [data.srcip]
  timespan: 5m
"""
        )
        eventos = [*_fallos(6, 5), evento_sshd(_ts(120), "203.0.113.45", exito=True)]
        resultado = evaluar(coleccion_desde(yaml), eventos)
        disparos = resultado.por_regla()["exito_tras_rafaga"]
        assert len(disparos) == 1
        assert [d.regla.nombre for d in disparos[0].origen] == ["rafaga", "exito"]


class TestAliasYUmbrales:
    def test_alias_une_campos_distintos(self) -> None:
        yaml = (
            _BASE.replace("data.srcip", "data.srcip")
            + """
---
title: Con alias
id: 00000000-0000-4000-8000-000000000007
name: con_alias
correlation:
  type: temporal
  rules: [fallo, exito]
  group-by: [origen]
  timespan: 2m
  aliases:
    origen:
      fallo: data.srcip
      exito: data.srcport
"""
        )
        fallo = evento_sshd(_ts(0), "50000", exito=False)
        exito = evento_sshd(_ts(10), "1.1.1.1", exito=True)
        resultado = evaluar(coleccion_desde(yaml), [fallo, exito])
        disparos = resultado.por_regla()["con_alias"]
        assert len(disparos) == 1
        assert disparos[0].grupo == {"origen": "50000"}

    def test_umbral_descendente_usa_ventanas_fijas(self) -> None:
        yaml = TestEventCount.YAML.replace("gte: 5", "lt: 3")
        resultado = evaluar(coleccion_desde(yaml), _fallos(2, 5) + _fallos(6, 5, desde=100))
        disparos = resultado.por_regla()["rafaga"]
        assert [d.cuenta for d in disparos] == [2]

    def test_detecciones_sin_valor_de_grupo_se_descartan(self) -> None:
        eventos = _fallos(6, 5)
        for evento in eventos[:3]:
            del evento["data"]["srcip"]
        resultado = evaluar(coleccion_desde(TestEventCount.YAML), eventos)
        assert "rafaga" not in resultado.nombres_disparados()
        assert len(resultado.por_regla()["fallo"]) == 6

    def test_regla_base_no_se_puede_correlacionar(self) -> None:
        coleccion = coleccion_desde(_BASE)
        with pytest.raises(ErrorCorrelacion):
            correlacionar(coleccion.por_nombre("fallo"), [])
