# Arquitectura

```
rules/linux/<tactica>/*.yml      reglas Sigma (base y correlaciones)
samples/<regla>/{positivos,negativos}.jsonl
src/detectionlab/
  reglas.py       carga con pySigma, validación sintáctica y de metadatos
  fuentes.py      logsource Sigma -> filtro sobre eventos Wazuh
  normalizar.py   decodifica argumentos hex de auditd y arma cmdline
  matcher.py      evalúa el árbol de condición de pySigma contra un evento
  correlacion.py  event_count, value_count, temporal, temporal_ordered
  motor.py        orquesta: ordena reglas, enruta eventos, correlaciona
  cobertura.py    matriz ATT&CK y capa para Navigator
  informe.py      sitio estático (HTML, Markdown, JSON)
  muestras.py     generador reproducible de logs de muestra
  cli.py          validate, run, coverage, report, samples
docs/reglas/<regla>.md           una ficha por regla
site/                            salida de `detectionlab report` (se genera en CI)
```

## Flujo de evaluación

1. `reglas.cargar_reglas` lee todos los `.yml` con `SigmaCollection.load_ruleset`. pySigma parsea el YAML, aplica los modificadores (`contains`, `re`, `cidr`...) y resuelve las referencias entre correlaciones y reglas base.
2. `motor.ordenar_reglas` hace un orden topológico: una correlación siempre se evalúa después de las reglas que referencia, aunque esté definida antes. Un ciclo es un error.
3. Cada evento pasa por `normalizar.enriquecer` una sola vez.
4. Para cada regla base, `fuentes.fuente_de(logsource)` filtra los eventos que le corresponden y `matcher.coincide` evalúa la condición.
5. Para cada correlación, `correlacion.correlacionar` recibe las detecciones de las reglas referenciadas, las agrupa por `group-by` (con `aliases` si los hay) y aplica la ventana.
6. El resultado es una lista de `Deteccion` con la regla, el instante, el evento y, en las correlaciones, el grupo, la cuenta y las detecciones de origen.

## Por qué el matcher se apoya en pySigma

pySigma es el parser de referencia del formato: entiende la gramática de `condition`, los modificadores, los comodines y las correlaciones. Lo que **no** trae es un backend que evalúe reglas contra eventos en memoria; sus backends convierten reglas a consultas de otros sistemas (Splunk, Elastic, Wazuh...).

Reimplementar el parser habría duplicado código que ya está probado y que evoluciona con la especificación. El matcher del repo recorre el árbol que entrega `rule.detection.parsed_condition` (`ConditionAND`, `ConditionOR`, `ConditionNOT`, `ConditionFieldEqualsValueExpression`, `ConditionValueExpression`) y solo implementa la comparación de valores:

| Tipo de valor pySigma | Comparación |
|---|---|
| `SigmaString` | comodines `*` y `?` convertidos a regex, sin distinguir mayúsculas |
| `SigmaCasedString` | igual, distinguiendo mayúsculas |
| `SigmaRegularExpression` | `re.search` con las banderas `i`, `m`, `s` |
| `SigmaNumber`, `SigmaBool` | igualdad con conversión desde texto |
| `SigmaCompareExpression` | `lt`, `lte`, `gt`, `gte`, `neq` |
| `SigmaCIDRExpression` | `ipaddress` |
| `SigmaNull`, `SigmaExists`, `SigmaFieldReference`, `SigmaExpansion` | ausencia, existencia, referencia a otro campo, expansiones como `windash` |

Los campos con lista (`rule.groups`) coinciden si algún elemento cumple. Las palabras clave sin campo se buscan en todos los valores del evento.

### Alcance de `windash`

`windash` cubre la convención de banderas de línea de comando en Windows, donde `-flag` y `/flag` son equivalentes: pySigma expande el valor a variantes con guion normal, los guiones Unicode (`–`, `—`, `―`) y la barra, y el matcher recorre esas variantes con un OR. Por eso `cmdline|windash|contains: '-foo'` dispara tanto con `-foo` como con `/foo`.

Lo que `windash` **no** hace es normalizar el separador de rutas `\` ↔ `/`: solo transforma el guion de la bandera, no la barra invertida de una ruta. Un valor sin guion, como `C:\Windows\System32\cmd.exe`, no genera variantes adicionales y se compara tal cual; eso es el comportamiento definido por pySigma, no una omisión del motor.

Las correlaciones sí se implementan completas porque pySigma solo las parsea. La semántica elegida para `event_count` y `value_count` es ventana deslizante con reinicio para umbrales `gt`/`gte` (una ráfaga larga genera pocas alertas) y ventanas fijas para el resto de operadores.

## Validación

`detectionlab validate` combina tres capas:

1. Errores de parseo de pySigma (`collect_errors=True`).
2. Validadores de pySigma seleccionados en `reglas.VALIDADORES_SIGMA`: condiciones colgantes, identificadores duplicados, modificadores incompatibles, comodines mal escapados, números como texto. No se usa `ATTACKTagValidator` porque descarga el catálogo de MITRE desde internet y el repo corre sin red.
3. Metadatos propios: UUID, `name` igual al archivo, nivel, táctica y técnica presentes y dentro del catálogo embebido (`attack.py`), coherencia técnica ↔ táctica, `falsepositives`, `references`, `logsource`.
4. Soporte del motor: `matcher.revisar_soporte` recorre la condición parseada y avisa si una regla usa un tipo de valor o un placeholder sin expandir que el matcher no sabría evaluar, de modo que el fallo aparece en `validate` y no recién al correr la regla contra un evento.

`tests/test_consistencia.py` corre esa misma validación y suma lo que solo tiene sentido en este repo: ficha, muestras, carpeta igual a la táctica.
