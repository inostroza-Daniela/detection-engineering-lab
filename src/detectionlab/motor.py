from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from graphlib import CycleError, TopologicalSorter

from sigma.rule import SigmaRule

from detectionlab.correlacion import Deteccion, correlacionar
from detectionlab.eventos import Evento, marca_tiempo
from detectionlab.fuentes import FuenteLog, fuente_de
from detectionlab.matcher import coincide
from detectionlab.normalizar import enriquecer
from detectionlab.reglas import Coleccion, Regla


class ErrorMotor(ValueError):
    pass


@dataclass
class Resultado:
    detecciones: list[Deteccion] = field(default_factory=list)
    eventos_evaluados: int = 0

    def por_regla(self) -> dict[str, list[Deteccion]]:
        agrupado: dict[str, list[Deteccion]] = {}
        for deteccion in self.detecciones:
            agrupado.setdefault(deteccion.regla.nombre, []).append(deteccion)
        return agrupado

    def nombres_disparados(self) -> set[str]:
        return {deteccion.regla.nombre for deteccion in self.detecciones}


def ordenar_reglas(coleccion: Coleccion) -> list[Regla]:
    """Reglas base primero; las correlaciones después de las reglas que referencian."""
    grafo: dict[str, set[str]] = {regla.nombre: set() for regla in coleccion}
    for regla in coleccion.correlaciones:
        for referencia in regla.reglas_referenciadas:
            if referencia not in grafo:
                raise ErrorMotor(f"{regla.nombre} referencia una regla inexistente: {referencia}")
            grafo[regla.nombre].add(referencia)
    try:
        orden = list(TopologicalSorter(grafo).static_order())
    except CycleError as exc:
        raise ErrorMotor(f"ciclo entre reglas de correlación: {exc.args[1]}") from exc
    return [coleccion.por_nombre(nombre) for nombre in orden]


def evaluar(coleccion: Coleccion, eventos_crudos: Sequence[Evento]) -> Resultado:
    eventos = [enriquecer(evento) for evento in eventos_crudos]
    resultado = Resultado(eventos_evaluados=len(eventos))
    detecciones_por_regla: dict[str, list[Deteccion]] = {}
    fuentes = _resolver_fuentes(coleccion)

    for regla in ordenar_reglas(coleccion):
        if isinstance(regla.sigma, SigmaRule):
            fuente = fuentes[regla.nombre]
            propias = [
                Deteccion(regla=regla, instante=marca_tiempo(evento), evento=evento)
                for evento in eventos
                if fuente.filtro(evento) and coincide(regla.sigma, evento)
            ]
        else:
            entrada = _entrada_correlacion(regla, detecciones_por_regla)
            propias = correlacionar(regla, entrada)
        detecciones_por_regla[regla.nombre] = propias
        resultado.detecciones.extend(propias)

    resultado.detecciones.sort(key=lambda d: (d.instante, d.regla.nombre))
    return resultado


def _resolver_fuentes(coleccion: Coleccion) -> dict[str, FuenteLog]:
    return {regla.nombre: fuente_de(regla.logsource) for regla in coleccion.base}


def _entrada_correlacion(
    regla: Regla, detecciones_por_regla: dict[str, list[Deteccion]]
) -> Iterable[Deteccion]:
    for referencia in regla.reglas_referenciadas:
        yield from detecciones_por_regla.get(referencia, [])
