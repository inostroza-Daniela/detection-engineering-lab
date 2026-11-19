# Contribuir

## Preparar el entorno

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
```

## Agregar una regla

1. Crear `rules/linux/<tactica>/<nombre>.yml` con `id` (UUID v4 nuevo), `name` igual al nombre del archivo, `author`, `license: DRL-1.1`, `level`, `tags` con táctica y técnica, `falsepositives` y `references`. Los valores van en español; las claves del formato Sigma quedan en inglés.
2. Si la técnica no está en `src/detectionlab/attack.py`, agregarla al catálogo embebido.
3. Agregar un escenario en `src/detectionlab/muestras.py` (positivos y negativos) y regenerar con `detectionlab samples`.
4. Escribir la ficha `docs/reglas/<nombre>.md` con las secciones "Qué detecta", "Lógica", "Falsos positivos" y "Cómo probarla", mencionando el UUID y las técnicas.
5. Correr `pytest`. `tests/test_consistencia.py` avisa de todo lo que falte.

## Antes de abrir un PR

```bash
ruff check . && ruff format --check . && mypy && pytest --cov
```

El CI corre lo mismo en Ubuntu, macOS (arm64) y Windows con Python 3.11 y 3.12. Nada en el repo debe depender del sistema operativo: rutas con `pathlib`, archivos abiertos con `encoding="utf-8"`, sin binarios externos.

## Convenciones

- Español en todo lo que escribe una persona: documentación, mensajes del CLI, nombres de reglas y de tests.
- Los IDs de regla son estables; una regla que cambia de lógica conserva su UUID y lo anota en `CHANGELOG.md`.
- Commits en español, en imperativo, sin líneas de atribución.
- Las reglas y fichas que aportes quedan bajo la Detection Rule License 1.1 con tu nombre en `author`; el código, bajo MIT.
