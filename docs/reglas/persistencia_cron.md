# Persistencia mediante cron

| | |
|---|---|
| ID | `c060f6fb-c45e-4827-806f-166691d83958` |
| Nombre | `persistencia_cron` |
| Nivel | medio |
| Táctica | Persistencia |
| Técnica | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron |
| Fuente | auditd (watch `-p wa` sobre los directorios de cron) |

## Qué detecta

Escrituras exitosas en `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/` y `/var/spool/cron/`. Cron es la persistencia más barata en Linux: no requiere root para el crontab propio y sobrevive a reinicios.

## Técnica ATT&CK

T1053.003. Se detecta la creación o modificación de la tarea, no su ejecución; cuando la tarea corra, otras reglas (`descarga_y_ejecucion`, `reverse_shell`) deberían ver el payload.

## Lógica

- `selection`: `data.audit.file.name` empieza por alguna de las rutas de cron y `data.audit.success: yes`.
- `filter_paquetes`: `dpkg`, `rpm`, `dnf`, `yum` y `apt-get` quedan fuera porque muchos paquetes instalan sus propias tareas.

`crontab` no está filtrado a propósito: `(crontab -l; echo "* * * * * ...") | crontab -` es exactamente lo que hace un atacante, y pasa por el mismo binario que un administrador. El costo es que `crontab -e` de cualquier usuario dispara en nivel medio; si en un entorno eso es frecuente, se acota por usuario o se baja a nivel bajo y se deja que una correlación lo suba.

## Falsos positivos conocidos

- Instalación de paquetes por gestores no listados (snap, pip con scripts post-instalación).
- Despliegues que registran tareas programadas legítimas; acotar por `auid` de la cuenta de despliegue o por ventana de cambio.

## Cómo probarla

```bash
detectionlab run samples/persistencia_cron/positivos.jsonl --solo-disparos
pytest -k persistencia_cron
```

Los negativos incluyen `dpkg` y `apt-get` escribiendo tareas, una edición de `/etc/cron.allow` (fuera de las rutas vigiladas), un intento fallido y `rsyslogd` escribiendo `/var/log/cron.log`.
