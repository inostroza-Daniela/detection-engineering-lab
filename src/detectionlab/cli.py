from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from detectionlab import __version__, cobertura, informe, muestras, reglas
from detectionlab.correlacion import Deteccion
from detectionlab.eventos import ErrorEvento, cargar_directorio, cargar_eventos
from detectionlab.fuentes import ErrorFuente
from detectionlab.matcher import ErrorMatcher
from detectionlab.motor import ErrorMotor, Resultado, evaluar


def _raiz() -> Path:
    """Raíz del repo si el paquete está instalado en modo editable; si no, el directorio actual."""
    candidata = Path(__file__).resolve().parents[2]
    if (candidata / "rules").is_dir():
        return candidata
    return Path.cwd()


RAIZ = _raiz()
REGLAS_POR_DEFECTO = RAIZ / "rules"
MUESTRAS_POR_DEFECTO = RAIZ / "samples"
DOCS_POR_DEFECTO = RAIZ / "docs" / "reglas"
SITIO_POR_DEFECTO = RAIZ / "site"

ErroresConocidos = (
    reglas.ErrorReglas,
    ErrorEvento,
    ErrorFuente,
    ErrorMatcher,
    ErrorMotor,
    KeyError,
    OSError,
)


def main(argv: Sequence[str] | None = None, salida: TextIO | None = None) -> int:
    salida = salida or sys.stdout
    parser = _parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help(salida)
        return 2
    try:
        codigo: int = args.func(args, salida)
    except ErroresConocidos as exc:
        print(f"error: {_mensaje(exc)}", file=salida)
        return 2
    return codigo


def _mensaje(exc: BaseException) -> str:
    if isinstance(exc, KeyError) and exc.args:
        return str(exc.args[0])
    return str(exc)


_TEXTOS_ARGPARSE = {
    "usage: ": "uso: ",
    "positional arguments": "argumentos",
    "options": "opciones",
    "show this help message and exit": "muestra esta ayuda y sale",
    "show program's version number and exit": "muestra la versión y sale",
    "the following arguments are required: %s": "faltan argumentos obligatorios: %s",
    "unrecognized arguments: %s": "argumentos no reconocidos: %s",
    "invalid choice: %(value)r (choose from %(choices)s)": (
        "opción inválida: %(value)r (elige entre %(choices)s)"
    ),
    "argument %(argument_name)s: %(message)s": "argumento %(argument_name)s: %(message)s",
    "expected one argument": "se esperaba un argumento",
    "expected at least one argument": "se esperaba al menos un argumento",
}


def _traducir(texto: str) -> str:
    return _TEXTOS_ARGPARSE.get(texto, texto)


argparse._ = _traducir  # type: ignore[attr-defined]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detectionlab",
        description="Laboratorio de ingeniería de detección: reglas Sigma para Linux "
        "evaluadas sobre eventos JSON compatibles con Wazuh.",
    )
    parser.add_argument("--version", action="version", version=f"detectionlab {__version__}")
    sub = parser.add_subparsers(dest="comando", metavar="comando")

    p_validate = sub.add_parser("validate", help="valida la sintaxis y los metadatos de las reglas")
    _arg_reglas(p_validate)
    p_validate.set_defaults(func=cmd_validate)

    p_run = sub.add_parser("run", help="evalúa las reglas contra archivos o carpetas de eventos")
    _arg_reglas(p_run)
    p_run.add_argument(
        "eventos",
        nargs="+",
        type=Path,
        help="archivos .json/.jsonl o carpetas con eventos",
    )
    p_run.add_argument("--json", action="store_true", help="salida en JSON en vez de tabla")
    p_run.add_argument(
        "--solo-disparos",
        action="store_true",
        help="muestra solo las reglas que dispararon",
    )
    p_run.set_defaults(func=cmd_run)

    p_cov = sub.add_parser("coverage", help="resumen de cobertura ATT&CK y capa para Navigator")
    _arg_reglas(p_cov)
    p_cov.add_argument(
        "--navigator",
        type=Path,
        metavar="ARCHIVO",
        help="escribe la capa de ATT&CK Navigator en este archivo JSON",
    )
    p_cov.add_argument("--json", action="store_true", help="resumen en JSON en vez de tabla")
    p_cov.set_defaults(func=cmd_coverage)

    p_report = sub.add_parser("report", help="genera el informe (HTML, Markdown y JSON) del sitio")
    _arg_reglas(p_report)
    p_report.add_argument(
        "--muestras", type=Path, default=MUESTRAS_POR_DEFECTO, help="carpeta con las muestras"
    )
    p_report.add_argument(
        "--docs", type=Path, default=DOCS_POR_DEFECTO, help="carpeta con la documentación de reglas"
    )
    p_report.add_argument(
        "--junit", type=Path, help="archivo JUnit XML de pytest para incluir el estado de los tests"
    )
    p_report.add_argument(
        "--salida", type=Path, default=SITIO_POR_DEFECTO, help="carpeta donde escribir el sitio"
    )
    p_report.set_defaults(func=cmd_report)

    p_samples = sub.add_parser("samples", help="regenera las muestras de logs con la semilla fija")
    p_samples.add_argument(
        "--salida", type=Path, default=MUESTRAS_POR_DEFECTO, help="carpeta destino de las muestras"
    )
    p_samples.add_argument("--semilla", type=int, default=muestras.SEMILLA)
    p_samples.set_defaults(func=cmd_samples)
    return parser


def _arg_reglas(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reglas",
        type=Path,
        default=REGLAS_POR_DEFECTO,
        help="carpeta con las reglas Sigma (por defecto: rules/)",
    )


def cmd_validate(args: argparse.Namespace, salida: TextIO) -> int:
    coleccion = reglas.cargar_reglas(args.reglas)
    hallazgos = reglas.validar(coleccion)
    print(f"{len(coleccion)} reglas cargadas desde {args.reglas}", file=salida)
    for hallazgo in hallazgos:
        print(f"  - {hallazgo}", file=salida)
    if hallazgos:
        print(f"{len(hallazgos)} problema(s) encontrado(s)", file=salida)
        return 1
    print("todas las reglas son válidas", file=salida)
    return 0


def cmd_run(args: argparse.Namespace, salida: TextIO) -> int:
    coleccion = reglas.cargar_reglas(args.reglas)
    eventos = []
    for ruta in args.eventos:
        if ruta.is_dir():
            eventos.extend(cargar_directorio(ruta))
        else:
            eventos.extend(cargar_eventos(ruta))
    resultado = evaluar(coleccion, eventos)
    if args.json:
        json.dump(_resultado_a_json(resultado), salida, ensure_ascii=False, indent=2)
        print(file=salida)
    else:
        _imprimir_tabla_run(coleccion, resultado, salida, solo_disparos=args.solo_disparos)
    return 0


def _resultado_a_json(resultado: Resultado) -> dict[str, Any]:
    return {
        "eventos_evaluados": resultado.eventos_evaluados,
        "detecciones": [_deteccion_a_json(d) for d in resultado.detecciones],
    }


def _deteccion_a_json(deteccion: Deteccion) -> dict[str, Any]:
    salida: dict[str, Any] = {
        "regla": deteccion.regla.nombre,
        "id": deteccion.regla.id,
        "titulo": deteccion.regla.titulo,
        "nivel": deteccion.regla.nivel,
        "instante": deteccion.instante.isoformat(),
        "agente": (deteccion.evento.get("agent") or {}).get("name"),
        "evento_id": deteccion.evento.get("id"),
    }
    if deteccion.regla.es_correlacion:
        salida["grupo"] = deteccion.grupo
        salida["cuenta"] = deteccion.cuenta
        salida["origen"] = [
            {"regla": origen.regla.nombre, "instante": origen.instante.isoformat()}
            for origen in deteccion.origen
        ]
    return salida


def _imprimir_tabla_run(
    coleccion: reglas.Coleccion, resultado: Resultado, salida: TextIO, solo_disparos: bool
) -> None:
    por_regla = resultado.por_regla()
    filas = []
    for regla in coleccion:
        detecciones = por_regla.get(regla.nombre, [])
        if solo_disparos and not detecciones:
            continue
        ultimo = detecciones[-1].instante.strftime("%Y-%m-%d %H:%M:%S") if detecciones else "-"
        filas.append((regla.nombre, regla.nivel, str(len(detecciones)), ultimo))
    print(f"eventos evaluados: {resultado.eventos_evaluados}", file=salida)
    print(
        f"reglas con disparos: {len(resultado.nombres_disparados())} de {len(coleccion)}",
        file=salida,
    )
    print(file=salida)
    _tabla(("regla", "nivel", "disparos", "ultimo"), filas, salida)


def cmd_coverage(args: argparse.Namespace, salida: TextIO) -> int:
    coleccion = reglas.cargar_reglas(args.reglas)
    resultado = cobertura.calcular(coleccion)
    if args.navigator is not None:
        args.navigator.parent.mkdir(parents=True, exist_ok=True)
        args.navigator.write_text(
            json.dumps(cobertura.capa_navigator(resultado), ensure_ascii=False, indent=2),
            encoding="utf-8",
            newline="\n",
        )
        print(f"capa de ATT&CK Navigator escrita en {args.navigator}", file=salida)
    if args.json:
        json.dump(
            {
                "reglas": len(coleccion),
                "tecnicas": resultado.total_tecnicas,
                "tacticas": resultado.total_tacticas,
                "por_tactica": resultado.resumen(),
            },
            salida,
            ensure_ascii=False,
            indent=2,
        )
        print(file=salida)
        return 0
    print(
        f"{len(coleccion)} reglas · {resultado.total_tecnicas} técnicas · "
        f"{resultado.total_tacticas} tácticas",
        file=salida,
    )
    print(file=salida)
    filas = [
        (fila["nombre"], str(fila["tecnicas"]), str(fila["reglas"])) for fila in resultado.resumen()
    ]
    _tabla(("tactica", "tecnicas", "reglas"), filas, salida)
    return 0


def cmd_report(args: argparse.Namespace, salida: TextIO) -> int:
    coleccion = reglas.cargar_reglas(args.reglas)
    resultado = informe.construir(coleccion, args.muestras, args.docs, args.junit)
    rutas = informe.escribir(resultado, args.salida)
    for ruta in rutas:
        print(f"escrito {ruta}", file=salida)
    fallas = [r.nombre for r in resultado.reglas if r.estado != "ok"]
    if fallas:
        print(f"reglas sin validar con muestras: {', '.join(fallas)}", file=salida)
        return 1
    return 0


def cmd_samples(args: argparse.Namespace, salida: TextIO) -> int:
    conteos = muestras.generar(args.salida, args.semilla)
    filas = [(nombre, str(pos), str(neg)) for nombre, (pos, neg) in conteos.items()]
    _tabla(("regla", "positivos", "negativos"), filas, salida)
    print(f"{len(conteos)} escenarios escritos en {args.salida}", file=salida)
    return 0


def _tabla(encabezados: Sequence[str], filas: Sequence[Sequence[str]], salida: TextIO) -> None:
    anchos = [len(h) for h in encabezados]
    for fila in filas:
        for i, celda in enumerate(fila):
            anchos[i] = max(anchos[i], len(celda))
    linea = "  ".join(h.ljust(anchos[i]) for i, h in enumerate(encabezados))
    print(linea.rstrip(), file=salida)
    print("  ".join("-" * ancho for ancho in anchos), file=salida)
    for fila in filas:
        print(
            "  ".join(celda.ljust(anchos[i]) for i, celda in enumerate(fila)).rstrip(), file=salida
        )
