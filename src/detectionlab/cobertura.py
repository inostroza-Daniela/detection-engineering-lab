from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from detectionlab.attack import TACTICAS, TECNICAS, VERSION_ATTACK, Tactica, Tecnica
from detectionlab.reglas import Coleccion, Regla


@dataclass(frozen=True)
class CoberturaTecnica:
    tecnica: Tecnica
    reglas: tuple[str, ...]


@dataclass(frozen=True)
class CoberturaTactica:
    tactica: Tactica
    tecnicas: tuple[CoberturaTecnica, ...]
    reglas: tuple[str, ...]


@dataclass
class Cobertura:
    tacticas: list[CoberturaTactica] = field(default_factory=list)
    tecnicas: dict[str, CoberturaTecnica] = field(default_factory=dict)
    reglas: list[Regla] = field(default_factory=list)

    @property
    def total_tecnicas(self) -> int:
        return len(self.tecnicas)

    @property
    def total_tacticas(self) -> int:
        return len(self.tacticas)

    def resumen(self) -> list[dict[str, Any]]:
        return [
            {
                "tactica": cobertura.tactica.tag,
                "nombre": cobertura.tactica.nombre,
                "tecnicas": len(cobertura.tecnicas),
                "reglas": len(cobertura.reglas),
            }
            for cobertura in self.tacticas
        ]


def calcular(coleccion: Coleccion) -> Cobertura:
    reglas_por_tecnica: dict[str, set[str]] = {}
    reglas_por_tactica: dict[str, set[str]] = {}
    pares: set[tuple[str, str]] = set()
    for regla in coleccion:
        for identificador in regla.tecnicas:
            if identificador not in TECNICAS:
                raise KeyError(
                    f"{regla.nombre}: técnica {identificador} no está en el catálogo embebido"
                )
            reglas_por_tecnica.setdefault(identificador, set()).add(regla.nombre)
        for tactica in regla.tacticas:
            if tactica not in TACTICAS:
                raise KeyError(f"{regla.nombre}: táctica desconocida {tactica}")
            reglas_por_tactica.setdefault(tactica, set()).add(regla.nombre)
            for identificador in regla.tecnicas:
                if tactica in TECNICAS[identificador].tacticas:
                    pares.add((tactica, identificador))

    tecnicas = {
        identificador: CoberturaTecnica(TECNICAS[identificador], tuple(sorted(nombres)))
        for identificador, nombres in sorted(reglas_por_tecnica.items())
    }
    tacticas = []
    for tag, definicion in sorted(TACTICAS.items(), key=lambda par: par[1].orden):
        if tag not in reglas_por_tactica:
            continue
        propias = tuple(
            cobertura
            for identificador, cobertura in tecnicas.items()
            if (tag, identificador) in pares
        )
        tacticas.append(
            CoberturaTactica(definicion, propias, tuple(sorted(reglas_por_tactica[tag])))
        )
    return Cobertura(tacticas=tacticas, tecnicas=tecnicas, reglas=list(coleccion))


def capa_navigator(
    cobertura: Cobertura, nombre: str = "detection-engineering-lab"
) -> dict[str, Any]:
    tecnicas = []
    for cobertura_tactica in cobertura.tacticas:
        tactica = cobertura_tactica.tactica.tag
        for item in cobertura_tactica.tecnicas:
            identificador = item.tecnica.id
            tecnicas.append(
                {
                    "techniqueID": identificador,
                    "tactic": TACTICAS[tactica].navigator,
                    "score": len(item.reglas),
                    "color": _color(len(item.reglas)),
                    "comment": ", ".join(item.reglas),
                    "enabled": True,
                    "showSubtechniques": "." in identificador,
                }
            )
    return {
        "name": nombre,
        "versions": {"attack": VERSION_ATTACK, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Técnicas cubiertas por las reglas Sigma del laboratorio (Linux).",
        "filters": {"platforms": ["Linux"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": tecnicas,
        "gradient": {"colors": ["#ffe6cc", "#ff8c00"], "minValue": 1, "maxValue": 3},
        "legendItems": [
            {"label": "1 regla", "color": "#ffe6cc"},
            {"label": "2 reglas", "color": "#ffb366"},
            {"label": "3 o más reglas", "color": "#ff8c00"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _color(cantidad: int) -> str:
    if cantidad >= 3:
        return "#ff8c00"
    if cantidad == 2:
        return "#ffb366"
    return "#ffe6cc"
