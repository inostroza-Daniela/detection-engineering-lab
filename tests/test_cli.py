from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from conftest import RUTA_MUESTRAS, RUTA_REGLAS
from detectionlab import __version__
from detectionlab.cli import main


def _correr(*args: str) -> tuple[int, str]:
    salida = io.StringIO()
    codigo = main(list(args), salida=salida)
    return codigo, salida.getvalue()


def test_sin_comando_muestra_ayuda() -> None:
    codigo, texto = _correr()
    assert codigo == 2
    assert "validate" in texto and "report" in texto


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as salida:
        main(["--version"])
    assert salida.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_validate_ok() -> None:
    codigo, texto = _correr("validate", "--reglas", str(RUTA_REGLAS))
    assert codigo == 0
    assert "todas las reglas son válidas" in texto


def test_validate_detecta_problemas(tmp_path: Path) -> None:
    (tmp_path / "rota.yml").write_text(
        "title: Rota\nid: 00000000-0000-4000-8000-0000000000bb\nname: rota\n"
        "logsource: {product: linux, service: auditd}\n"
        "detection:\n  sel: {a: b}\n  condition: sel and nada\n",
        encoding="utf-8",
    )
    codigo, texto = _correr("validate", "--reglas", str(tmp_path))
    assert codigo == 1
    assert "problema(s)" in texto
    assert "falta `level`" in texto or "level" in texto


def test_validate_detecta_tactica_incoherente(tmp_path: Path) -> None:
    (tmp_path / "incoherente.yml").write_text(
        "title: Incoherente\nid: 00000000-0000-4000-8000-0000000000cc\nname: incoherente\n"
        "description: x\nreferences: [https://example.org]\nfalsepositives: [ninguno]\n"
        "level: low\ntags: [attack.persistence, attack.t1046]\n"
        "logsource: {product: linux, service: auditd}\n"
        "detection:\n  sel: {a: b}\n  condition: sel\n",
        encoding="utf-8",
    )
    codigo, texto = _correr("validate", "--reglas", str(tmp_path))
    assert codigo == 1
    assert "ninguna táctica declarada corresponde a la técnica T1046" in texto


def test_validate_sin_reglas_es_error(tmp_path: Path) -> None:
    codigo, texto = _correr("validate", "--reglas", str(tmp_path))
    assert codigo == 2
    assert texto.startswith("error:")


def test_run_tabla_y_solo_disparos() -> None:
    muestras = RUTA_MUESTRAS / "reverse_shell" / "positivos.jsonl"
    codigo, texto = _correr("run", "--reglas", str(RUTA_REGLAS), str(muestras))
    assert codigo == 0
    assert "eventos evaluados: 9" in texto
    assert "reverse_shell" in texto
    assert "persistencia_cron" in texto
    _, filtrado = _correr("run", "--reglas", str(RUTA_REGLAS), "--solo-disparos", str(muestras))
    assert "persistencia_cron" not in filtrado


def test_run_json_incluye_origen_de_correlaciones() -> None:
    carpeta = RUTA_MUESTRAS / "ssh_login_exitoso_tras_rafaga"
    codigo, texto = _correr("run", "--reglas", str(RUTA_REGLAS), "--json", str(carpeta))
    assert codigo == 0
    salida = json.loads(texto)
    assert salida["eventos_evaluados"] > 0
    correlacionadas = [
        d for d in salida["detecciones"] if d["regla"] == "ssh_login_exitoso_tras_rafaga"
    ]
    assert len(correlacionadas) == 1
    assert correlacionadas[0]["grupo"] == {"data.srcip": "203.0.113.45"}
    assert [o["regla"] for o in correlacionadas[0]["origen"]] == [
        "ssh_fuerza_bruta",
        "ssh_login_exitoso",
    ]


def test_run_con_archivo_inexistente() -> None:
    codigo, texto = _correr("run", "--reglas", str(RUTA_REGLAS), "no-existe.jsonl")
    assert codigo == 2
    assert texto.startswith("error:")


def test_coverage_tabla_json_y_navigator(tmp_path: Path) -> None:
    capa = tmp_path / "capa" / "navigator.json"
    codigo, texto = _correr("coverage", "--reglas", str(RUTA_REGLAS), "--navigator", str(capa))
    assert codigo == 0
    assert "tácticas" in texto and "Persistencia" in texto
    assert json.loads(capa.read_text(encoding="utf-8"))["techniques"]
    codigo, texto = _correr("coverage", "--reglas", str(RUTA_REGLAS), "--json")
    assert codigo == 0
    assert json.loads(texto)["tecnicas"] >= 12


def test_report_escribe_el_sitio(tmp_path: Path) -> None:
    salida = tmp_path / "site"
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="10" failures="1" errors="0" skipped="2"/></testsuites>',
        encoding="utf-8",
    )
    codigo, texto = _correr(
        "report",
        "--reglas",
        str(RUTA_REGLAS),
        "--muestras",
        str(RUTA_MUESTRAS),
        "--docs",
        str(RUTA_REGLAS.parent / "docs" / "reglas"),
        "--junit",
        str(junit),
        "--salida",
        str(salida),
    )
    assert codigo == 0, texto
    for nombre in (
        "index.html",
        "informe.json",
        "informe.md",
        "attack-navigator.json",
        ".nojekyll",
    ):
        assert (salida / nombre).is_file()
    informe = json.loads((salida / "informe.json").read_text(encoding="utf-8"))
    assert informe["tests"] == {
        "total": 10,
        "pasados": 7,
        "fallidos": 1,
        "errores": 0,
        "omitidos": 2,
        "disponible": True,
    }
    assert all(r["estado"] == "ok" for r in informe["reglas"])
    html = (salida / "index.html").read_text(encoding="utf-8")
    assert '<html lang="es">' in html
    assert "reverse_shell" in html and "7/10" in html


def test_report_marca_reglas_sin_muestras(tmp_path: Path) -> None:
    codigo, texto = _correr(
        "report",
        "--reglas",
        str(RUTA_REGLAS),
        "--muestras",
        str(tmp_path / "vacio"),
        "--docs",
        str(tmp_path / "vacio"),
        "--salida",
        str(tmp_path / "site"),
    )
    assert codigo == 1
    assert "reglas sin validar con muestras" in texto
    assert "sin muestras" in (tmp_path / "site" / "informe.md").read_text(encoding="utf-8")


def test_samples_regenera_en_otra_carpeta(tmp_path: Path) -> None:
    codigo, texto = _correr("samples", "--salida", str(tmp_path))
    assert codigo == 0
    assert "escenarios escritos" in texto
    assert (tmp_path / "reverse_shell" / "positivos.jsonl").is_file()
