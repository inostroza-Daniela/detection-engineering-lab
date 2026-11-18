from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)

from detectionlab.eventos import Evento, obtener_campo
from detectionlab.reglas import Regla

Grupo = tuple[tuple[str, Any], ...]


class ErrorCorrelacion(ValueError):
    pass


@dataclass(frozen=True)
class Deteccion:
    regla: Regla
    instante: datetime
    evento: Evento
    grupo: dict[str, Any] = field(default_factory=dict)
    cuenta: int = 1
    origen: tuple[Deteccion, ...] = ()

    def valor(self, campo: str) -> Any:
        if campo in self.grupo:
            return self.grupo[campo]
        return obtener_campo(self.evento, campo)


def correlacionar(regla: Regla, detecciones: Iterable[Deteccion]) -> list[Deteccion]:
    sigma = regla.sigma
    if not isinstance(sigma, SigmaCorrelationRule):
        raise ErrorCorrelacion(f"{regla.nombre} no es una regla de correlación")
    referencias = [str(ref.reference) for ref in sigma.rules or []]
    condicion = _condicion(regla)
    ventana = timedelta(seconds=sigma.timespan.seconds)
    grupos = _agrupar(sigma, referencias, detecciones)

    resultados: list[Deteccion] = []
    for grupo, lista in grupos.items():
        lista.sort(key=lambda d: d.instante)
        if sigma.type == SigmaCorrelationType.EVENT_COUNT:
            resultados.extend(_contar(regla, grupo, lista, ventana, campo=None))
        elif sigma.type == SigmaCorrelationType.VALUE_COUNT:
            campo = condicion.fieldref
            if not isinstance(campo, str):
                raise ErrorCorrelacion(f"{regla.nombre}: value_count requiere un solo `field`")
            resultados.extend(_contar(regla, grupo, lista, ventana, campo=campo))
        elif sigma.type == SigmaCorrelationType.TEMPORAL:
            resultados.extend(_temporal(regla, grupo, lista, ventana, referencias, ordenado=False))
        elif sigma.type == SigmaCorrelationType.TEMPORAL_ORDERED:
            resultados.extend(_temporal(regla, grupo, lista, ventana, referencias, ordenado=True))
        else:
            raise ErrorCorrelacion(
                f"{regla.nombre}: tipo de correlación no soportado: {sigma.type.name.lower()}"
            )
    resultados.sort(key=lambda d: d.instante)
    return resultados


def _agrupar(
    sigma: SigmaCorrelationRule,
    referencias: Sequence[str],
    detecciones: Iterable[Deteccion],
) -> dict[Grupo, list[Deteccion]]:
    campos_por_regla = _campos_por_regla(sigma, referencias)
    grupos: dict[Grupo, list[Deteccion]] = defaultdict(list)
    for deteccion in detecciones:
        nombre = deteccion.regla.nombre
        if nombre not in campos_por_regla:
            continue
        valores = [(alias, deteccion.valor(campo)) for alias, campo in campos_por_regla[nombre]]
        if any(valor is None for _, valor in valores):
            continue
        clave = tuple((alias, _normalizar(valor)) for alias, valor in valores)
        grupos[clave].append(deteccion)
    return grupos


def _campos_por_regla(
    sigma: SigmaCorrelationRule, referencias: Sequence[str]
) -> dict[str, list[tuple[str, str]]]:
    alias_por_campo = {
        alias: {str(ref.reference): campo for ref, campo in definicion.mapping.items()}
        for alias, definicion in sigma.aliases.aliases.items()
    }
    resultado: dict[str, list[tuple[str, str]]] = {}
    for referencia in referencias:
        campos = []
        for campo_grupo in sigma.group_by or []:
            campo = alias_por_campo.get(campo_grupo, {}).get(referencia, campo_grupo)
            campos.append((campo_grupo, campo))
        resultado[referencia] = campos
    return resultado


def _normalizar(valor: Any) -> Any:
    if isinstance(valor, str):
        return valor.lower()
    if isinstance(valor, list | dict):
        return repr(valor)
    return valor


def _condicion(regla: Regla) -> SigmaCorrelationCondition:
    sigma = regla.sigma
    assert isinstance(sigma, SigmaCorrelationRule)
    if not isinstance(sigma.condition, SigmaCorrelationCondition):
        raise ErrorCorrelacion(f"{regla.nombre}: condición de correlación no soportada")
    return sigma.condition


def _cumple(regla: Regla, cuenta: int) -> bool:
    condicion = _condicion(regla)
    operador = condicion.op
    umbral = condicion.count
    comparaciones = {
        SigmaCorrelationConditionOperator.LT: cuenta < umbral,
        SigmaCorrelationConditionOperator.LTE: cuenta <= umbral,
        SigmaCorrelationConditionOperator.GT: cuenta > umbral,
        SigmaCorrelationConditionOperator.GTE: cuenta >= umbral,
        SigmaCorrelationConditionOperator.EQ: cuenta == umbral,
        SigmaCorrelationConditionOperator.NEQ: cuenta != umbral,
    }
    try:
        return comparaciones[operador]
    except KeyError:
        raise ErrorCorrelacion(f"{regla.nombre}: operador no soportado: {operador}") from None


def _umbral_ascendente(regla: Regla) -> bool:
    return _condicion(regla).op in (
        SigmaCorrelationConditionOperator.GT,
        SigmaCorrelationConditionOperator.GTE,
    )


def _contar(
    regla: Regla,
    grupo: Grupo,
    lista: list[Deteccion],
    ventana: timedelta,
    campo: str | None,
) -> list[Deteccion]:
    """Ventana deslizante para umbrales `gt`/`gte`; ventanas fijas para el resto.

    Con un umbral ascendente la alerta se emite en cuanto se alcanza y la
    ventana se reinicia, así una ráfaga larga produce una sola detección y no
    una por cada evento adicional.
    """
    if _umbral_ascendente(regla):
        return _contar_deslizante(regla, grupo, lista, ventana, campo)
    return _contar_fijo(regla, grupo, lista, ventana, campo)


def _contar_deslizante(
    regla: Regla,
    grupo: Grupo,
    lista: list[Deteccion],
    ventana: timedelta,
    campo: str | None,
) -> list[Deteccion]:
    resultados: list[Deteccion] = []
    pendientes: deque[Deteccion] = deque()
    for deteccion in lista:
        pendientes.append(deteccion)
        limite = deteccion.instante - ventana
        while pendientes and pendientes[0].instante < limite:
            pendientes.popleft()
        cuenta = _cuenta(pendientes, campo)
        if _cumple(regla, cuenta):
            resultados.append(_emitir(regla, grupo, list(pendientes), cuenta))
            pendientes.clear()
    return resultados


def _contar_fijo(
    regla: Regla,
    grupo: Grupo,
    lista: list[Deteccion],
    ventana: timedelta,
    campo: str | None,
) -> list[Deteccion]:
    resultados: list[Deteccion] = []
    bloque: list[Deteccion] = []
    inicio: datetime | None = None
    for deteccion in lista:
        if inicio is not None and deteccion.instante - inicio >= ventana:
            cuenta = _cuenta(bloque, campo)
            if _cumple(regla, cuenta):
                resultados.append(_emitir(regla, grupo, bloque, cuenta))
            bloque = []
            inicio = None
        if inicio is None:
            inicio = deteccion.instante
        bloque.append(deteccion)
    if bloque:
        cuenta = _cuenta(bloque, campo)
        if _cumple(regla, cuenta):
            resultados.append(_emitir(regla, grupo, bloque, cuenta))
    return resultados


def _cuenta(detecciones: Iterable[Deteccion], campo: str | None) -> int:
    if campo is None:
        return sum(1 for _ in detecciones)
    return len({_normalizar(d.valor(campo)) for d in detecciones})


def _temporal(
    regla: Regla,
    grupo: Grupo,
    lista: list[Deteccion],
    ventana: timedelta,
    referencias: Sequence[str],
    ordenado: bool,
) -> list[Deteccion]:
    resultados: list[Deteccion] = []
    vistos: dict[str, Deteccion] = {}
    for deteccion in lista:
        nombre = deteccion.regla.nombre
        for visto in list(vistos):
            if deteccion.instante - vistos[visto].instante > ventana:
                del vistos[visto]
        if ordenado:
            posicion = referencias.index(nombre)
            if posicion == 0:
                vistos = {nombre: deteccion}
                continue
            if any(previo not in vistos for previo in referencias[:posicion]):
                continue
            vistos[nombre] = deteccion
        else:
            vistos[nombre] = deteccion
        if all(referencia in vistos for referencia in referencias):
            origen = sorted(vistos.values(), key=lambda d: d.instante)
            resultados.append(_emitir(regla, grupo, origen, len(origen)))
            vistos = {}
    return resultados


def _emitir(regla: Regla, grupo: Grupo, origen: list[Deteccion], cuenta: int) -> Deteccion:
    ultimo = origen[-1]
    return Deteccion(
        regla=regla,
        instante=ultimo.instante,
        evento=ultimo.evento,
        grupo=dict(grupo),
        cuenta=cuenta,
        origen=tuple(origen),
    )
