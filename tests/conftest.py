from __future__ import annotations

from pathlib import Path

import pytest

from detectionlab.reglas import Coleccion, cargar_reglas

RAIZ = Path(__file__).resolve().parents[1]
RUTA_REGLAS = RAIZ / "rules"
RUTA_MUESTRAS = RAIZ / "samples"
RUTA_DOCS = RAIZ / "docs" / "reglas"


@pytest.fixture(scope="session")
def raiz() -> Path:
    return RAIZ


@pytest.fixture(scope="session")
def coleccion() -> Coleccion:
    return cargar_reglas(RUTA_REGLAS)


def nombres_de_reglas() -> list[str]:
    return sorted(ruta.stem for ruta in RUTA_REGLAS.rglob("*.yml"))
