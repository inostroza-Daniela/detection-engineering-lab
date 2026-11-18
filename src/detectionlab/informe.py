from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from detectionlab import __version__
from detectionlab.attack import TACTICAS
from detectionlab.cobertura import Cobertura, calcular, capa_navigator
from detectionlab.eventos import cargar_eventos
from detectionlab.motor import evaluar
from detectionlab.muestras import ARCHIVO_NEGATIVOS, ARCHIVO_POSITIVOS
from detectionlab.reglas import Coleccion, Regla

REPO = "https://github.com/inostroza-Daniela/detection-engineering-lab"
NIVEL_ORDEN = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
NIVEL_NOMBRE = {
    "critical": "crítico",
    "high": "alto",
    "medium": "medio",
    "low": "bajo",
    "informational": "informativo",
}


@dataclass(frozen=True)
class ResultadoRegla:
    nombre: str
    id: str
    titulo: str
    nivel: str
    correlacion: bool
    tacticas: list[str]
    tecnicas: list[str]
    positivos: int
    negativos: int
    detecciones_positivos: int
    detecciones_negativos: int
    documentada: bool

    @property
    def estado(self) -> str:
        if self.positivos == 0 or self.negativos == 0:
            return "sin_muestras"
        if self.detecciones_positivos > 0 and self.detecciones_negativos == 0:
            return "ok"
        return "falla"


@dataclass(frozen=True)
class ResumenTests:
    total: int = 0
    pasados: int = 0
    fallidos: int = 0
    errores: int = 0
    omitidos: int = 0
    disponible: bool = False


@dataclass
class Informe:
    generado: str
    version: str
    cobertura: Cobertura
    reglas: list[ResultadoRegla]
    tests: ResumenTests

    @property
    def metricas(self) -> dict[str, int]:
        return {
            "reglas": len(self.reglas),
            "reglas_base": sum(1 for r in self.reglas if not r.correlacion),
            "correlaciones": sum(1 for r in self.reglas if r.correlacion),
            "tecnicas": self.cobertura.total_tecnicas,
            "tacticas": self.cobertura.total_tacticas,
            "tacticas_total": len(TACTICAS),
            "muestras_ok": sum(1 for r in self.reglas if r.estado == "ok"),
            "eventos_muestra": sum(r.positivos + r.negativos for r in self.reglas),
            "tests": self.tests.total,
            "tests_pasados": self.tests.pasados,
        }


def construir(
    coleccion: Coleccion,
    muestras: Path,
    docs: Path,
    junit: Path | None = None,
) -> Informe:
    resultados = [_evaluar_regla(coleccion, regla, muestras, docs) for regla in coleccion]
    resultados.sort(key=lambda r: (NIVEL_ORDEN.get(r.nivel, 9), r.nombre))
    return Informe(
        generado=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        cobertura=calcular(coleccion),
        reglas=resultados,
        tests=leer_junit(junit) if junit is not None else ResumenTests(),
    )


def _evaluar_regla(
    coleccion: Coleccion, regla: Regla, muestras: Path, docs: Path
) -> ResultadoRegla:
    carpeta = muestras / regla.nombre
    positivos = _cargar_si_existe(carpeta / ARCHIVO_POSITIVOS)
    negativos = _cargar_si_existe(carpeta / ARCHIVO_NEGATIVOS)
    detecciones_pos = len(evaluar(coleccion, positivos).por_regla().get(regla.nombre, []))
    detecciones_neg = len(evaluar(coleccion, negativos).por_regla().get(regla.nombre, []))
    return ResultadoRegla(
        nombre=regla.nombre,
        id=regla.id,
        titulo=regla.titulo,
        nivel=regla.nivel,
        correlacion=regla.es_correlacion,
        tacticas=regla.tacticas,
        tecnicas=regla.tecnicas,
        positivos=len(positivos),
        negativos=len(negativos),
        detecciones_positivos=detecciones_pos,
        detecciones_negativos=detecciones_neg,
        documentada=(docs / f"{regla.nombre}.md").is_file(),
    )


def _cargar_si_existe(ruta: Path) -> list[dict[str, Any]]:
    return cargar_eventos(ruta) if ruta.is_file() else []


def leer_junit(ruta: Path) -> ResumenTests:
    if not ruta.is_file():
        return ResumenTests()
    raiz = ET.parse(ruta).getroot()
    suites = [raiz] if raiz.tag == "testsuite" else list(raiz.iter("testsuite"))
    total = pasados = fallidos = errores = omitidos = 0
    for suite in suites:
        t = int(suite.get("tests", "0"))
        f = int(suite.get("failures", "0"))
        e = int(suite.get("errors", "0"))
        s = int(suite.get("skipped", "0"))
        total += t
        fallidos += f
        errores += e
        omitidos += s
        pasados += t - f - e - s
    return ResumenTests(total, pasados, fallidos, errores, omitidos, disponible=True)


def escribir(informe: Informe, destino: Path) -> list[Path]:
    destino.mkdir(parents=True, exist_ok=True)
    salidas = {
        "informe.json": json.dumps(a_json(informe), ensure_ascii=False, indent=2),
        "informe.md": a_markdown(informe),
        "index.html": a_html(informe),
        "attack-navigator.json": json.dumps(
            capa_navigator(informe.cobertura), ensure_ascii=False, indent=2
        ),
        ".nojekyll": "",
    }
    rutas = []
    for nombre, contenido in salidas.items():
        ruta = destino / nombre
        ruta.write_text(contenido, encoding="utf-8", newline="\n")
        rutas.append(ruta)
    return rutas


def a_json(informe: Informe) -> dict[str, Any]:
    return {
        "generado": informe.generado,
        "version": informe.version,
        "metricas": informe.metricas,
        "tests": asdict(informe.tests),
        "tacticas": informe.cobertura.resumen(),
        "tecnicas": [
            {
                "id": c.tecnica.id,
                "nombre": c.tecnica.nombre,
                "tacticas": list(c.tecnica.tacticas),
                "reglas": list(c.reglas),
            }
            for c in informe.cobertura.tecnicas.values()
        ],
        "reglas": [{**asdict(r), "estado": r.estado} for r in informe.reglas],
    }


def a_markdown(informe: Informe) -> str:
    m = informe.metricas
    lineas = [
        "# Informe de cobertura",
        "",
        f"Generado: {informe.generado} · detectionlab {informe.version}",
        "",
        "## Métricas",
        "",
        "| Métrica | Valor |",
        "|---|---|",
        f"| Reglas | {m['reglas']} ({m['reglas_base']} base, {m['correlaciones']} correlaciones) |",
        f"| Técnicas ATT&CK | {m['tecnicas']} |",
        f"| Tácticas ATT&CK | {m['tacticas']} de {m['tacticas_total']} |",
        f"| Reglas validadas con muestras | {m['muestras_ok']} de {m['reglas']} |",
        f"| Eventos de muestra | {m['eventos_muestra']} |",
    ]
    if informe.tests.disponible:
        lineas.append(
            f"| Tests pytest | {informe.tests.pasados} de {informe.tests.total} pasados |"
        )
    lineas += [
        "",
        "## Cobertura por táctica",
        "",
        "| Táctica | Técnicas | Reglas |",
        "|---|---|---|",
    ]
    for fila in informe.cobertura.resumen():
        lineas.append(f"| {fila['nombre']} | {fila['tecnicas']} | {fila['reglas']} |")
    lineas += [
        "",
        "## Reglas",
        "",
        "| Regla | Nivel | Técnicas | Muestras (+/-) | Estado |",
        "|---|---|---|---|---|",
    ]
    for r in informe.reglas:
        lineas.append(
            f"| `{r.nombre}` | {NIVEL_NOMBRE.get(r.nivel, r.nivel)} | {', '.join(r.tecnicas)} "
            f"| {r.positivos}/{r.negativos} | {_estado_texto(r.estado)} |"
        )
    return "\n".join(lineas) + "\n"


def _estado_texto(estado: str) -> str:
    return {"ok": "OK", "falla": "FALLA", "sin_muestras": "sin muestras"}.get(estado, estado)


def a_html(informe: Informe) -> str:
    m = informe.metricas
    e = html.escape
    estilos = (resources.files("detectionlab") / "recursos" / "estilos.css").read_text("utf-8")
    tarjetas = [
        (
            "Reglas",
            str(m["reglas"]),
            f"{m['reglas_base']} base · {m['correlaciones']} correlaciones",
        ),
        ("Técnicas ATT&CK", str(m["tecnicas"]), "incluye subtécnicas"),
        ("Tácticas", f"{m['tacticas']}/{m['tacticas_total']}", "Enterprise, plataforma Linux"),
        (
            "Muestras validadas",
            f"{m['muestras_ok']}/{m['reglas']}",
            f"{m['eventos_muestra']} eventos",
        ),
    ]
    if informe.tests.disponible:
        tarjetas.append(
            (
                "Tests pytest",
                f"{informe.tests.pasados}/{informe.tests.total}",
                "última ejecución de CI",
            )
        )
    tarjetas_html = "".join(
        f'<div class="tarjeta"><span class="valor">{e(v)}</span>'
        f'<span class="titulo">{e(t)}</span><span class="detalle">{e(d)}</span></div>'
        for t, v, d in tarjetas
    )

    cubiertas = {c.tactica.tag: c for c in informe.cobertura.tacticas}
    columnas = []
    for tag, tactica in sorted(TACTICAS.items(), key=lambda par: par[1].orden):
        cobertura = cubiertas.get(tag)
        celdas = ""
        if cobertura is not None:
            for item in cobertura.tecnicas:
                cantidad = len(item.reglas)
                clase = "n3" if cantidad >= 3 else f"n{cantidad}"
                plural = "s" if cantidad != 1 else ""
                nombre_corto = item.tecnica.nombre.split(": ")[-1]
                celdas += (
                    f'<a class="tecnica {clase}" href="{e(item.tecnica.url)}" '
                    f'title="{e(", ".join(item.reglas))}">'
                    f'<span class="id">{e(item.tecnica.id)}</span>'
                    f'<span class="nombre">{e(nombre_corto)}</span>'
                    f'<span class="cuenta">{cantidad} regla{plural}</span></a>'
                )
        vacia = " vacia" if cobertura is None else ""
        cuerpo = celdas or '<p class="sin">sin reglas</p>'
        columnas.append(
            f'<div class="tactica{vacia}"><h3>{e(tactica.nombre)}'
            f"<small>{e(tactica.navigator)}</small></h3>{cuerpo}</div>"
        )

    filas = ""
    for r in informe.reglas:
        tecnicas = " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t.replace(".", "/")}/">{e(t)}</a>'
            for t in r.tecnicas
        )
        doc = (
            f'<a href="{REPO}/blob/main/docs/reglas/{e(r.nombre)}.md">doc</a>'
            if r.documentada
            else "—"
        )
        tipo = "correlación" if r.correlacion else "base"
        nivel = e(NIVEL_NOMBRE.get(r.nivel, r.nivel))
        filas += (
            f"<tr><td><code>{e(r.nombre)}</code><br>"
            f'<span class="titulo-regla">{e(r.titulo)}</span></td>'
            f'<td><span class="nivel {e(r.nivel)}">{nivel}</span></td>'
            f"<td>{e(tipo)}</td><td>{tecnicas}</td>"
            f"<td>{r.positivos} / {r.negativos}</td>"
            f'<td><span class="estado {e(r.estado)}">{e(_estado_texto(r.estado))}</span></td>'
            f"<td>{doc}</td></tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>detection-engineering-lab · cobertura ATT&amp;CK</title>
<style>
{estilos}
</style>
</head>
<body>
<header>
<h1>detection-engineering-lab</h1>
<p>Reglas Sigma para Linux mapeadas a MITRE ATT&amp;CK,
validadas contra logs de muestra en formato Wazuh.</p>
</header>
<main>
<section class="tarjetas">{tarjetas_html}</section>
<h2>Matriz ATT&amp;CK (Enterprise · Linux)</h2>
<p class="leyenda">Reglas por técnica:
<span style="background:var(--n1)"></span>1
<span style="background:var(--n2)"></span>2
<span style="background:var(--n3)"></span>3 o más ·
<a href="attack-navigator.json">capa para ATT&amp;CK Navigator</a></p>
<section class="matriz">{"".join(columnas)}</section>
<h2>Reglas</h2>
<table>
<thead><tr><th>Regla</th><th>Nivel</th><th>Tipo</th><th>Técnicas</th>
<th>Muestras + / −</th><th>Estado</th><th>Doc</th></tr></thead>
<tbody>{filas}</tbody>
</table>
<p><a href="informe.json">informe.json</a> · <a href="informe.md">informe.md</a></p>
</main>
<footer>Generado {e(informe.generado)} con detectionlab {e(informe.version)} ·
<a href="{REPO}">repositorio</a></footer>
</body>
</html>
"""
