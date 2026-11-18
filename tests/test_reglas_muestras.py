from __future__ import annotations

from pathlib import Path

import pytest

from conftest import RUTA_MUESTRAS, nombres_de_reglas
from detectionlab.eventos import cargar_eventos
from detectionlab.motor import evaluar
from detectionlab.muestras import ARCHIVO_NEGATIVOS, ARCHIVO_POSITIVOS, ESCENARIOS, generar
from detectionlab.reglas import Coleccion

REGLAS = nombres_de_reglas()


@pytest.mark.parametrize("nombre", REGLAS)
def test_positivos_disparan_la_regla(coleccion: Coleccion, nombre: str) -> None:
    eventos = cargar_eventos(RUTA_MUESTRAS / nombre / ARCHIVO_POSITIVOS)
    resultado = evaluar(coleccion, eventos)
    detecciones = resultado.por_regla().get(nombre, [])
    assert detecciones, f"{nombre}: ninguna de las {len(eventos)} muestras positivas disparó"
    if not coleccion.por_nombre(nombre).es_correlacion:
        assert len(detecciones) == len(eventos), (
            f"{nombre}: solo {len(detecciones)} de {len(eventos)} positivos dispararon"
        )


@pytest.mark.parametrize("nombre", REGLAS)
def test_negativos_no_disparan_la_regla(coleccion: Coleccion, nombre: str) -> None:
    eventos = cargar_eventos(RUTA_MUESTRAS / nombre / ARCHIVO_NEGATIVOS)
    resultado = evaluar(coleccion, eventos)
    detecciones = resultado.por_regla().get(nombre, [])
    assert not detecciones, (
        f"{nombre}: {len(detecciones)} muestra(s) negativa(s) dispararon: "
        + ", ".join(d.evento.get("id", "?") for d in detecciones)
    )


def test_hay_un_escenario_por_regla() -> None:
    assert sorted(escenario.regla for escenario in ESCENARIOS) == REGLAS


def test_muestras_son_reproducibles(tmp_path: Path) -> None:
    generar(tmp_path)
    for nombre in REGLAS:
        for archivo in (ARCHIVO_POSITIVOS, ARCHIVO_NEGATIVOS):
            esperado = RUTA_MUESTRAS / nombre / archivo
            generado = tmp_path / nombre / archivo
            assert esperado.read_text(encoding="utf-8") == generado.read_text(encoding="utf-8"), (
                f"{nombre}/{archivo} difiere de lo generado con la semilla fija; "
                "ejecuta `detectionlab samples` y revisa el diff"
            )


def test_otra_semilla_cambia_las_muestras(tmp_path: Path) -> None:
    generar(tmp_path, semilla=1)
    original = RUTA_MUESTRAS / "ssh_fuerza_bruta" / ARCHIVO_POSITIVOS
    generado = tmp_path / "ssh_fuerza_bruta" / ARCHIVO_POSITIVOS
    assert original.read_text(encoding="utf-8") != generado.read_text(encoding="utf-8")
