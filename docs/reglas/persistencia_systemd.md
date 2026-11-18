# Persistencia mediante unidad systemd

| | |
|---|---|
| ID | `0bd028cb-d6d3-4bce-9ae5-74d0cdf61f68` |
| Nombre | `persistencia_systemd` |
| Nivel | medio |
| Táctica | Persistencia |
| Técnica | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Create or Modify System Process: Systemd Service |
| Fuente | auditd (watch `-p wa` sobre los directorios de unidades) |

## Qué detecta

Creación o modificación de unidades `.service`, `.timer`, `.socket` o `.path` en los directorios de systemd del sistema (`/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/`, `/run/systemd/system/`) o de usuario (`~/.config/systemd/user/`, `~/.local/share/systemd/user/`, `/etc/systemd/user/`, `/usr/lib/systemd/user/`), hecha por algo distinto a un gestor de paquetes o `systemctl`.

## Técnica ATT&CK

T1543.002. Una unidad nueva con `ExecStart=` apuntando a un binario en `/tmp` o `/dev/shm` es un servicio malicioso con nombre inocente (`kworker.service`, `update-checker.service`).

## Lógica

- `selection_sistema` o `selection_usuario`: la ruta pertenece a un directorio de unidades.
- `selection_unidad`: termina en `.service`, `.timer`, `.socket` o `.path` y la escritura fue exitosa.
- `filter_herramientas`: gestores de paquetes, `snapd` y `systemctl`. `systemctl enable` crea symlinks en `*.wants/` que terminan en `.service`; se excluyen porque la unidad original ya disparó al crearse.

Los drop-ins (`*.service.d/override.conf`) no están cubiertos en esta versión; es una vía de persistencia válida (`ExecStartPre=`) que queda anotada como ampliación.

## Falsos positivos conocidos

- Instalación manual de software que registra su propio servicio (binarios descargados, instaladores `.run`).
- Herramientas de configuración que despliegan unidades; acotar por `auid`.

## Cómo probarla

```bash
detectionlab run samples/persistencia_systemd/positivos.jsonl --solo-disparos
pytest -k persistencia_systemd
```

Los negativos tienen `dpkg` instalando `nginx.service`, el symlink de `systemctl enable`, `journald.conf` (no es unidad), una unidad `.mount` de snapd y un intento fallido.
