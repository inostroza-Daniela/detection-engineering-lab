# Webshell: proceso de sistema lanzado por el servidor web

| | |
|---|---|
| ID | `5a4684f6-32e6-4f40-97b9-c4fb456459b7` |
| Nombre | `webshell_proceso_hijo_servidor_web` |
| Nivel | alto |
| Tácticas | Persistencia, Ejecución |
| Técnicas | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell · [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell |
| Fuente | auditd (`-S execve`) |

## Qué detecta

La cuenta bajo la que corre el servidor web (`www-data`, `apache`, `nginx`, `http`, o sus UIDs 33 y 48) ejecuta una shell, un intérprete, una herramienta de red o un comando de reconocimiento (`id`, `whoami`, `uname`, `hostname`). Un servidor web sirve contenido; cuando empieza a lanzar `sh -c id`, lo más probable es que alguien subió un `cmd.php`.

## Técnica ATT&CK

T1505.003 describe la webshell como componente persistente; T1059.004 el medio por el que ejecuta comandos. Se etiquetan ambas porque la regla ve el segundo efecto del primero.

## Lógica

- `selection_usuario_web`: `data.audit.uid` en la lista de usuarios web. Se incluyen los UID numéricos (como los entrega auditd sin enriquecer) y los nombres (formato `ENRICHED`).
- `selection_proceso`: `data.audit.exe` termina en alguno de los binarios vigilados. Es una regex y no una lista porque auditd resuelve `exe` desde `/proc/<pid>/exe`: `python3` aparece como `/usr/bin/python3.12` y `nc` como `/usr/bin/nc.openbsd`.
- `filter_php_cli`: `php` se excluye porque php-fpm y los workers de colas lo lanzan todo el tiempo.

A diferencia de Sysmon, auditd no entrega el proceso padre con su ruta; por eso la regla se apoya en el UID y no en `ParentImage`. El `auid` igual a `4294967295` (sin sesión de login) refuerza la señal pero no se exige, para no perder webshells lanzadas desde un contenedor donde el auid sí está definido.

## Falsos positivos conocidos

- Aplicaciones que invocan comandos del sistema de forma legítima: conversión de imágenes (`convert` no está en la lista), backups, wrappers de git. Si una app concreta lanza `sh -c`, acotar por `data.audit.cwd` o por el comando.
- Tareas cron ejecutadas como `www-data`.

## Cómo probarla

```bash
detectionlab run samples/webshell_proceso_hijo_servidor_web/positivos.jsonl --solo-disparos
pytest -k webshell
```

Los positivos incluyen `/usr/bin/python3.12` y `/usr/bin/nc.openbsd`. Los negativos tienen `php artisan queue:work` como www-data, `bash -c id` como usuario normal, `nginx -s reload` como root, `convert` como www-data e `id -u` como root.
