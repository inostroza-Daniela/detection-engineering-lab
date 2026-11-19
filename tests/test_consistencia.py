from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest

from conftest import RUTA_DOCS, RUTA_MUESTRAS, RUTA_REGLAS, nombres_de_reglas
from detectionlab.attack import TACTICAS, TECNICAS
from detectionlab.fuentes import fuente_de
from detectionlab.muestras import ARCHIVO_NEGATIVOS, ARCHIVO_POSITIVOS
from detectionlab.reglas import Coleccion, validar

REGLAS = nombres_de_reglas()


def test_pysigma_y_metadatos_no_reportan_problemas(coleccion: Coleccion) -> None:
    hallazgos = validar(coleccion)
    assert not hallazgos, "\n".join(str(h) for h in hallazgos)


def test_cantidad_de_reglas(coleccion: Coleccion) -> None:
    assert len(coleccion) == len(REGLAS)
    assert len(coleccion.base) == 13
    assert len(coleccion.correlaciones) == 3


@pytest.mark.parametrize("nombre", REGLAS)
def test_regla_tiene_doc_muestras_y_mapeo(coleccion: Coleccion, nombre: str) -> None:
    regla = coleccion.por_nombre(nombre)
    doc = RUTA_DOCS / f"{nombre}.md"
    assert doc.is_file(), f"falta docs/reglas/{nombre}.md"
    texto = doc.read_text(encoding="utf-8")
    assert regla.id in texto, f"la doc de {nombre} no menciona su UUID {regla.id}"
    for tecnica in regla.tecnicas:
        assert tecnica in texto, f"la doc de {nombre} no menciona la técnica {tecnica}"
    for seccion in ("## Qué detecta", "## Lógica", "## Falsos positivos", "## Cómo probarla"):
        assert seccion in texto, f"la doc de {nombre} no tiene la sección '{seccion}'"

    for archivo in (ARCHIVO_POSITIVOS, ARCHIVO_NEGATIVOS):
        ruta = RUTA_MUESTRAS / nombre / archivo
        assert ruta.is_file(), f"falta samples/{nombre}/{archivo}"
        assert ruta.read_text(encoding="utf-8").strip(), f"samples/{nombre}/{archivo} está vacío"

    assert regla.tecnicas, f"{nombre} no tiene técnica ATT&CK"
    assert regla.tacticas, f"{nombre} no tiene táctica ATT&CK"
    for tecnica in regla.tecnicas:
        assert tecnica in TECNICAS
        assert any(t in TECNICAS[tecnica].tacticas for t in regla.tacticas), (
            f"{nombre}: ninguna táctica declarada corresponde a {tecnica}"
        )
    for tactica in regla.tacticas:
        assert tactica in TACTICAS


@pytest.mark.parametrize("nombre", REGLAS)
def test_identidad_estable(coleccion: Coleccion, nombre: str) -> None:
    regla = coleccion.por_nombre(nombre)
    assert uuid.UUID(regla.id).version == 4
    assert regla.nombre == nombre == regla.ruta.stem
    assert regla.ruta.parent.name in TACTICAS, f"{nombre} no está en una carpeta de táctica"
    assert regla.ruta.parent.name in regla.tacticas, (
        f"{nombre} está en {regla.ruta.parent.name} pero no declara esa táctica"
    )
    assert regla.nivel in {"informational", "low", "medium", "high", "critical"}
    assert regla.sigma.author == "Daniela Inostroza"
    assert regla.sigma.license == "DRL-1.1"


def test_ids_y_nombres_son_unicos(coleccion: Coleccion) -> None:
    ids = [regla.id for regla in coleccion]
    nombres = [regla.nombre for regla in coleccion]
    assert len(set(ids)) == len(ids)
    assert len(set(nombres)) == len(nombres)


def test_toda_regla_base_tiene_fuente_conocida(coleccion: Coleccion) -> None:
    for regla in coleccion.base:
        fuente_de(regla.logsource)


def test_correlaciones_referencian_reglas_existentes(coleccion: Coleccion) -> None:
    nombres = {regla.nombre for regla in coleccion}
    for regla in coleccion.correlaciones:
        assert regla.reglas_referenciadas
        assert set(regla.reglas_referenciadas) <= nombres


def test_no_hay_muestras_ni_docs_huerfanas() -> None:
    carpetas = sorted(p.name for p in RUTA_MUESTRAS.iterdir() if p.is_dir())
    assert carpetas == REGLAS
    docs = sorted(p.stem for p in RUTA_DOCS.glob("*.md") if p.stem != "README")
    assert docs == REGLAS


def test_archivos_de_reglas_usan_valores_en_espanol() -> None:
    patron_ingles = re.compile(r"\b(detects|detected|attacker|suspicious)\b", re.IGNORECASE)
    for ruta in RUTA_REGLAS.rglob("*.yml"):
        texto = ruta.read_text(encoding="utf-8")
        assert not patron_ingles.search(texto), f"{ruta.name} tiene descripciones en inglés"


def test_las_muestras_tienen_la_forma_de_wazuh() -> None:
    for ruta in RUTA_MUESTRAS.rglob("*.jsonl"):
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            evento = json.loads(linea)
            assert set(evento) >= {
                "timestamp",
                "agent",
                "rule",
                "data",
                "decoder",
                "full_log",
                "location",
            }
            assert set(evento["agent"]) == {"id", "name", "ip"}
            assert {"id", "level", "description", "groups"} <= set(evento["rule"])


def test_readme_enlaza_cada_regla(raiz: Path) -> None:
    readme = (raiz / "README.md").read_text(encoding="utf-8")
    for nombre in REGLAS:
        assert nombre in readme, f"README no menciona la regla {nombre}"
