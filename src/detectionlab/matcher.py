from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaType,
    SpecialChars,
)

from detectionlab.eventos import Evento, existe_campo, obtener_campo, valores_planos


class ErrorMatcher(ValueError):
    pass


def coincide(regla: SigmaRule, evento: Evento) -> bool:
    """Evalúa la sección `detection` de una regla contra un evento.

    pySigma entrega la condición ya parseada como un árbol booleano con los
    modificadores aplicados; aquí solo se recorre ese árbol y se comparan
    los valores con el evento. Si la regla declara varias condiciones, basta
    con que una se cumpla.
    """
    return any(evaluar(condicion.parsed, evento) for condicion in regla.detection.parsed_condition)


def evaluar(nodo: ConditionItem | Any, evento: Evento) -> bool:
    if isinstance(nodo, ConditionAND):
        return all(evaluar(hijo, evento) for hijo in nodo.args)
    if isinstance(nodo, ConditionOR):
        return any(evaluar(hijo, evento) for hijo in nodo.args)
    if isinstance(nodo, ConditionNOT):
        return not evaluar(nodo.args[0], evento)
    if isinstance(nodo, ConditionFieldEqualsValueExpression):
        return _comparar_campo(nodo.field, nodo.value, evento)
    if isinstance(nodo, ConditionValueExpression):
        return _buscar_texto_libre(nodo.value, evento)
    raise ErrorMatcher(f"nodo de condición no soportado: {type(nodo).__name__}")


_TIPOS_VALOR_SOPORTADOS: tuple[type[SigmaType], ...] = (
    SigmaExists,
    SigmaNull,
    SigmaFieldReference,
    SigmaRegularExpression,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaBool,
    SigmaString,
)


def revisar_soporte(regla: SigmaRule) -> list[str]:
    """Recorre la condición parseada y lista lo que el motor no sabría evaluar.

    Devuelve un mensaje por cada nodo o tipo de valor fuera del alcance del
    matcher, de modo que `validar` pueda avisar en tiempo de validación en
    lugar de fallar recién al evaluar un evento. Una lista vacía significa que
    la regla es evaluable por completo.
    """
    problemas: list[str] = []
    for condicion in regla.detection.parsed_condition:
        _revisar_nodo(condicion.parsed, problemas)
    return problemas


def _revisar_nodo(nodo: ConditionItem | Any, problemas: list[str]) -> None:
    if isinstance(nodo, ConditionAND | ConditionOR):
        for hijo in nodo.args:
            _revisar_nodo(hijo, problemas)
        return
    if isinstance(nodo, ConditionNOT):
        _revisar_nodo(nodo.args[0], problemas)
        return
    if isinstance(nodo, ConditionFieldEqualsValueExpression | ConditionValueExpression):
        _revisar_valor(nodo.value, problemas)
        return
    problemas.append(f"nodo de condición no soportado: {type(nodo).__name__}")


def _revisar_valor(valor: SigmaType, problemas: list[str]) -> None:
    if isinstance(valor, SigmaExpansion):
        for interno in valor.values:
            _revisar_valor(interno, problemas)
        return
    if isinstance(valor, SigmaString):
        if any(isinstance(parte, Placeholder) for parte in valor.s):
            problemas.append(f"placeholder sin expandir: %{_nombre_placeholder(valor)}%")
        return
    if not isinstance(valor, _TIPOS_VALOR_SOPORTADOS):
        problemas.append(f"tipo de valor Sigma no soportado: {type(valor).__name__}")


def _nombre_placeholder(valor: SigmaString) -> str:
    for parte in valor.s:
        if isinstance(parte, Placeholder):
            return parte.name
    return "?"


def _comparar_campo(campo: str, esperado: SigmaType, evento: Evento) -> bool:
    if isinstance(esperado, SigmaExists):
        return existe_campo(evento, campo) == bool(esperado.exists)
    observado = obtener_campo(evento, campo)
    if isinstance(esperado, SigmaNull):
        return observado is None
    if isinstance(esperado, SigmaExpansion):
        return any(_comparar_campo(campo, valor, evento) for valor in esperado.values)
    if isinstance(esperado, SigmaFieldReference):
        referencia = obtener_campo(evento, esperado.field)
        return observado is not None and _iguales(observado, referencia)
    if observado is None:
        return False
    candidatos = observado if isinstance(observado, list) else [observado]
    return any(_comparar_valor(candidato, esperado) for candidato in candidatos)


def _comparar_valor(observado: Any, esperado: SigmaType) -> bool:
    if isinstance(esperado, SigmaRegularExpression):
        return _regex(esperado).search(str(observado)) is not None
    if isinstance(esperado, SigmaCIDRExpression):
        return _en_red(observado, esperado)
    if isinstance(esperado, SigmaCompareExpression):
        return _comparar_numero(observado, esperado)
    if isinstance(esperado, SigmaNumber):
        numero = _a_numero(observado)
        return numero is not None and numero == esperado.number
    if isinstance(esperado, SigmaBool):
        return _a_booleano(observado) == esperado.boolean
    if isinstance(esperado, SigmaString):
        return _patron_texto(esperado).fullmatch(str(observado)) is not None
    raise ErrorMatcher(f"tipo de valor Sigma no soportado: {type(esperado).__name__}")


def _buscar_texto_libre(valor: SigmaType, evento: Evento) -> bool:
    if isinstance(valor, SigmaString):
        patron = _patron_texto(valor, contiene=True)
        return any(patron.fullmatch(texto) for texto in valores_planos(evento))
    if isinstance(valor, SigmaRegularExpression):
        patron = _regex(valor)
        return any(patron.search(texto) for texto in valores_planos(evento))
    return any(_comparar_valor(texto, valor) for texto in valores_planos(evento))


def _patron_texto(valor: SigmaString, contiene: bool = False) -> re.Pattern[str]:
    partes = [_parte_a_regex(parte) for parte in valor.s]
    cuerpo = "".join(partes)
    if contiene:
        cuerpo = f".*{cuerpo}.*"
    banderas = re.DOTALL
    if not isinstance(valor, SigmaCasedString):
        banderas |= re.IGNORECASE
    return _compilar(cuerpo, banderas)


def _parte_a_regex(parte: str | SpecialChars | Placeholder) -> str:
    if parte is SpecialChars.WILDCARD_MULTI:
        return ".*"
    if parte is SpecialChars.WILDCARD_SINGLE:
        return "."
    if isinstance(parte, Placeholder):
        raise ErrorMatcher(f"placeholder sin expandir en la regla: %{parte.name}%")
    return re.escape(parte)


def _regex(valor: SigmaRegularExpression) -> re.Pattern[str]:
    banderas = 0
    if SigmaRegularExpressionFlag.IGNORECASE in valor.flags:
        banderas |= re.IGNORECASE
    if SigmaRegularExpressionFlag.MULTILINE in valor.flags:
        banderas |= re.MULTILINE
    if SigmaRegularExpressionFlag.DOTALL in valor.flags:
        banderas |= re.DOTALL
    return _compilar(str(valor.regexp), banderas)


@lru_cache(maxsize=1024)
def _compilar(patron: str, banderas: int) -> re.Pattern[str]:
    try:
        return re.compile(patron, banderas)
    except re.error as exc:
        raise ErrorMatcher(f"expresión regular inválida {patron!r}: {exc}") from exc


def _en_red(observado: Any, esperado: SigmaCIDRExpression) -> bool:
    try:
        direccion = ipaddress.ip_address(str(observado))
    except ValueError:
        return False
    red = ipaddress.ip_network(esperado.cidr, strict=False)
    return direccion.version == red.version and direccion in red


def _comparar_numero(observado: Any, esperado: SigmaCompareExpression) -> bool:
    numero = _a_numero(observado)
    if numero is None:
        return False
    limite = esperado.number.number
    operadores = SigmaCompareExpression.CompareOperators
    if esperado.op == operadores.LT:
        return numero < limite
    if esperado.op == operadores.LTE:
        return numero <= limite
    if esperado.op == operadores.GT:
        return numero > limite
    if esperado.op == operadores.GTE:
        return numero >= limite
    if esperado.op == operadores.NEQ:
        return numero != limite
    raise ErrorMatcher(f"operador de comparación no soportado: {esperado.op}")


def _a_numero(valor: Any) -> int | float | None:
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int | float):
        return valor
    if isinstance(valor, str):
        texto = valor.strip()
        try:
            return int(texto)
        except ValueError:
            try:
                return float(texto)
            except ValueError:
                return None
    return None


def _a_booleano(valor: Any) -> bool | None:
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, str):
        texto = valor.strip().lower()
        if texto in {"true", "yes", "1"}:
            return True
        if texto in {"false", "no", "0"}:
            return False
    if isinstance(valor, int):
        return bool(valor)
    return None


def _iguales(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    return bool(a == b)
