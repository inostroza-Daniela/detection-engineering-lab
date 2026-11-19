# Fichas de reglas

Una ficha por regla, con el mismo nombre que el archivo YAML en `rules/linux/`. Cada ficha tiene el UUID estable, la técnica ATT&CK, la lógica, los falsos positivos conocidos y cómo probarla.

El test `tests/test_consistencia.py` falla si una regla no tiene ficha, si la ficha no menciona el UUID o las técnicas, o si falta alguna de las secciones obligatorias.

Las reglas y estas fichas se publican bajo la [Detection Rule License 1.1](../../LICENSE.Detection.Rules.md): el campo `author` de cada regla debe conservarse al redistribuirla o al mostrar sus detecciones.
