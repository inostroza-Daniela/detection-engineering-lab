from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core.condition import (
    AllOfThemConditionValidator,
    DanglingConditionValidator,
    DanglingDetectionValidator,
    ThemConditionWithSingleDetectionValidator,
)
from sigma.validators.core.metadata import (
    DuplicateReferencesValidator,
    DuplicateTitleValidator,
    IdentifierExistenceValidator,
    IdentifierUniquenessValidator,
)
from sigma.validators.core.modifiers import InvalidModifierCombinationsValidator
from sigma.validators.core.tags import DuplicateTagValidator, TagFormatValidator
from sigma.validators.core.values import (
    ControlCharacterValidator,
    DoubleWildcardValidator,
    EscapedWildcardValidator,
    NumberAsStringValidator,
    WildcardsInsteadOfModifiersValidator,
)

from detectionlab.attack import TACTICAS, TECNICAS

ReglaSigma = SigmaRule | SigmaCorrelationRule

NIVELES = ("informational", "low", "medium", "high", "critical")

_RE_TECNICA = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
_RE_TACTICA = re.compile(r"^attack\.[a-z_]+$")

VALIDADORES_SIGMA = (
    AllOfThemConditionValidator,
    DanglingConditionValidator,
    DanglingDetectionValidator,
    ThemConditionWithSingleDetectionValidator,
    DuplicateReferencesValidator,
    DuplicateTitleValidator,
    IdentifierExistenceValidator,
    IdentifierUniquenessValidator,
    InvalidModifierCombinationsValidator,
    DuplicateTagValidator,
    TagFormatValidator,
    ControlCharacterValidator,
    DoubleWildcardValidator,
    EscapedWildcardValidator,
    NumberAsStringValidator,
    WildcardsInsteadOfModifiersValidator,
)


class ErrorReglas(ValueError):
    pass


@dataclass(frozen=True)
class Regla:
    sigma: ReglaSigma
    ruta: Path

    @property
    def id(self) -> str:
        return str(self.sigma.id) if self.sigma.id is not None else ""

    @property
    def nombre(self) -> str:
        return self.sigma.name or self.ruta.stem

    @property
    def titulo(self) -> str:
        return self.sigma.title

    @property
    def nivel(self) -> str:
        return self.sigma.level.name.lower() if self.sigma.level is not None else ""

    @property
    def tags(self) -> list[str]:
        return [str(tag) for tag in self.sigma.tags]

    @property
    def tecnicas(self) -> list[str]:
        return [tag.removeprefix("attack.").upper() for tag in self.tags if _RE_TECNICA.match(tag)]

    @property
    def tacticas(self) -> list[str]:
        return [
            tag.removeprefix("attack.")
            for tag in self.tags
            if _RE_TACTICA.match(tag) and not _RE_TECNICA.match(tag)
        ]

    @property
    def es_correlacion(self) -> bool:
        return isinstance(self.sigma, SigmaCorrelationRule)

    @property
    def referencias(self) -> list[str]:
        return list(self.sigma.references)

    @property
    def falsos_positivos(self) -> list[str]:
        return list(self.sigma.falsepositives)

    @property
    def logsource(self) -> dict[str, str]:
        if isinstance(self.sigma, SigmaRule):
            fuente = self.sigma.logsource
            return {
                clave: valor
                for clave, valor in (
                    ("product", fuente.product),
                    ("category", fuente.category),
                    ("service", fuente.service),
                )
                if valor
            }
        return {}

    @property
    def reglas_referenciadas(self) -> list[str]:
        if isinstance(self.sigma, SigmaCorrelationRule):
            return [str(ref.reference) for ref in self.sigma.rules or []]
        return []


@dataclass(frozen=True)
class Hallazgo:
    regla: str
    ruta: Path
    mensaje: str

    def __str__(self) -> str:
        return f"{self.ruta.name} [{self.regla}]: {self.mensaje}"


@dataclass
class Coleccion:
    reglas: list[Regla] = field(default_factory=list)

    def __iter__(self) -> Iterator[Regla]:
        return iter(self.reglas)

    def __len__(self) -> int:
        return len(self.reglas)

    def por_nombre(self, nombre: str) -> Regla:
        for regla in self.reglas:
            if regla.nombre == nombre or regla.id == nombre:
                return regla
        raise KeyError(nombre)

    @property
    def base(self) -> list[Regla]:
        return [regla for regla in self.reglas if not regla.es_correlacion]

    @property
    def correlaciones(self) -> list[Regla]:
        return [regla for regla in self.reglas if regla.es_correlacion]


def cargar_reglas(directorio: Path) -> Coleccion:
    rutas = sorted(directorio.rglob("*.yml"))
    if not rutas:
        raise ErrorReglas(f"no hay reglas .yml en {directorio} (indica la carpeta con --reglas)")
    try:
        coleccion = SigmaCollection.load_ruleset([str(ruta) for ruta in rutas], collect_errors=True)
    except SigmaError as exc:
        raise ErrorReglas(f"no se pudo cargar el conjunto de reglas: {exc}") from exc
    reglas = []
    for sigma in coleccion.rules:
        origen = sigma.source.path if sigma.source is not None else directorio
        reglas.append(Regla(sigma=sigma, ruta=Path(origen)))
    reglas.sort(key=lambda regla: (regla.es_correlacion, regla.nombre))
    return Coleccion(reglas)


def validar(coleccion: Coleccion) -> list[Hallazgo]:
    hallazgos: list[Hallazgo] = []
    for regla in coleccion:
        for error in regla.sigma.errors:
            hallazgos.append(Hallazgo(regla.nombre, regla.ruta, f"pySigma: {error}"))
        hallazgos.extend(_validar_metadatos(regla))

    validador = SigmaValidator(VALIDADORES_SIGMA)
    reglas_base = [regla.sigma for regla in coleccion.base if isinstance(regla.sigma, SigmaRule)]
    for problema in validador.validate_rules(iter(reglas_base)):
        for sigma in problema.rules:
            ruta = Path(sigma.source.path) if sigma.source is not None else Path()
            nombre = sigma.name or ruta.stem
            hallazgos.append(Hallazgo(nombre, ruta, f"{type(problema).__name__}: {problema}"))
    return hallazgos


def _validar_metadatos(regla: Regla) -> list[Hallazgo]:
    problemas: list[str] = []
    if regla.sigma.id is None:
        problemas.append("falta el campo `id` (UUID estable)")
    if not regla.sigma.name:
        problemas.append("falta el campo `name`, necesario para referenciar la regla")
    elif regla.sigma.name != regla.ruta.stem:
        problemas.append(f"`name` ({regla.sigma.name}) no coincide con el nombre del archivo")
    if regla.nivel not in NIVELES:
        problemas.append("`level` ausente o fuera de los valores permitidos")
    if not regla.tecnicas:
        problemas.append("sin técnica ATT&CK en `tags` (attack.tXXXX)")
    for tecnica in regla.tecnicas:
        if tecnica not in TECNICAS:
            problemas.append(f"técnica {tecnica} no está en el catálogo embebido de ATT&CK")
    if not regla.tacticas:
        problemas.append("sin táctica ATT&CK en `tags` (attack.<tactica>)")
    for tactica in regla.tacticas:
        if tactica not in TACTICAS:
            problemas.append(f"táctica desconocida: {tactica}")
    for tecnica in regla.tecnicas:
        if tecnica in TECNICAS and not any(
            tactica in TECNICAS[tecnica].tacticas for tactica in regla.tacticas
        ):
            problemas.append(f"ninguna táctica declarada corresponde a la técnica {tecnica}")
    if not regla.falsos_positivos:
        problemas.append("falta `falsepositives`")
    if not regla.referencias:
        problemas.append("falta `references`")
    if not regla.es_correlacion and not regla.logsource:
        problemas.append("falta `logsource`")
    if not regla.sigma.description:
        problemas.append("falta `description`")
    return [Hallazgo(regla.nombre, regla.ruta, problema) for problema in problemas]
