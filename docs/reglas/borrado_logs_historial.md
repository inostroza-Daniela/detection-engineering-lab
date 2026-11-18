# Borrado de logs o del historial de comandos

| | |
|---|---|
| ID | `5c70de3c-2734-4b96-84ec-239f70c97400` |
| Nombre | `borrado_logs_historial` |
| Nivel | alto |
| Táctica | Evasión de defensas |
| Técnicas | [T1070.002](https://attack.mitre.org/techniques/T1070/002/) Clear Linux or Mac System Logs · [T1070.003](https://attack.mitre.org/techniques/T1070/003/) Clear Command History |
| Fuente | auditd (watch sobre `/var/log` y `-S execve`) |

## Qué detecta

- Escritura, truncado o borrado de logs del sistema (`auth.log`, `secure`, `syslog`, `messages`, `wtmp`, `btmp`, `lastlog`, `/var/log/audit/`, `/var/log/journal/`) por un proceso que no es un servicio de logging.
- `rm`, `shred`, `truncate`, `unlink` o `ln` con `/var/log/` o `_history` en la línea de comando.
- Comandos de limpieza de historial: `history -c`, `unset HISTFILE`, `HISTFILE=/dev/null`, `HISTSIZE=0`, `set +o history`.
- Borrado o reemplazo del archivo de historial (`.bash_history`, `.zsh_history`, `.python_history`, `.mysql_history`, `.psql_history`).

## Técnica ATT&CK

T1070.002 para los logs del sistema, T1070.003 para el historial. Son las dos cosas que un atacante hace antes de irse; verlas juntas en la misma sesión es casi una confirmación de intrusión.

## Lógica

- `selection_logs` y no `filter_servicios`: la escritura en un log la hizo algo distinto a `rsyslogd`, `syslog-ng`, `logrotate`, `auditd`, `sshd` y `sshd-session` (OpenSSH 9.8+ escribe `wtmp` desde ahí), `login`, `sudo`, `su`, `cron`, systemd y los compresores de rotación.
- `selection_comando_historial`: patrones en `data.audit.execve.cmdline`. Dentro de una shell interactiva `history -c` es un builtin y no genera `execve`; la regla lo ve cuando viene por `bash -c`, por script o por una webshell, que es el caso que importa.
- `selection_archivo_historial`: watch sobre `*_history` escrito por una herramienta de borrado.
- `selection_borrado_cmd`: `rm`, `shred`, `truncate` o `unlink` con `/var/log/` o `_history` en la línea de comando.
- `selection_enlace_historial`: `ln` con `_history` en la línea (`ln -sf /dev/null ~/.bash_history`). `ln` va aparte para que `ln -s /var/log/nginx /srv/logs` no dispare.

## Falsos positivos conocidos

- Rotación de logs con herramientas no listadas en `filter_servicios` (por ejemplo `journalctl --vacuum`, scripts propios). Sumarlas al filtro.
- Limpieza de disco que elimina logs antiguos (`rm /var/log/nginx/*.gz`). Acotar `selection_borrado_cmd` por ruta o por ventana de mantenimiento.

## Cómo probarla

```bash
detectionlab run samples/borrado_logs_historial/positivos.jsonl --solo-disparos
pytest -k borrado_logs
```

Los negativos incluyen `rsyslogd`, `logrotate`, `sshd` y `sshd-session` (escriben `wtmp`), `gzip` rotando, `less` y `grep` sobre logs, `cat ~/.bash_history`, `rm -rf /var/tmp/...` y `ln -s /var/log/nginx /srv/logs`.
