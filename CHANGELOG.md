# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado semántico.

## [0.1.0] - 2026-11-18

### Agregado

- 13 reglas Sigma base y 3 correlaciones para Linux, organizadas por táctica ATT&CK, con UUID estable.
- Motor de evaluación sobre eventos JSON compatibles con Wazuh: carga y validación con pySigma, matcher propio sobre el árbol de condición, correlaciones `event_count`, `value_count`, `temporal` y `temporal_ordered`.
- Decodificación de argumentos hexadecimales de auditd y campo derivado `data.audit.execve.cmdline`.
- CLI `detectionlab` con `validate`, `run`, `coverage`, `report` y `samples`.
- Generador reproducible de muestras (semilla fija) con positivos y negativos por regla.
- Sitio estático con matriz ATT&CK, tabla de reglas, métricas y capa para ATT&CK Navigator.
- Suite pytest con tests parametrizados por regla, del matcher, de correlaciones, del CLI y de consistencia.
- CI en Ubuntu, macOS (arm64) y Windows × Python 3.11/3.12; despliegue a GitHub Pages.
