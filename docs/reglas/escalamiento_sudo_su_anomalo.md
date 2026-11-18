# Escalamiento anómalo con sudo o su

| | |
|---|---|
| ID | `636965d1-130a-4890-b42c-11678501d5a7` |
| Nombre | `escalamiento_sudo_su_anomalo` |
| Nivel | medio |
| Táctica | Escalamiento de privilegios |
| Técnica | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Abuse Elevation Control Mechanism: Sudo and Sudo Caching |
| Fuente | auth (`/var/log/auth.log`: decoders `sudo` y `su`) |

## Qué detecta

Cuatro situaciones alrededor de sudo y su:

- `sudo` usado para abrir una shell como root (`sudo /bin/bash`, `sudo su -`, `sudo -i`).
- `sudo` rechazado: usuario fuera de sudoers, comando no permitido o tres claves incorrectas.
- `su` fallido.
- `su` a root ejecutado por una cuenta de servicio (`www-data`, `postgres`, `nobody`...), que nunca debería tener motivo para hacerlo.

## Técnica ATT&CK

T1548.003. El atacante que ya tiene una cuenta intenta subir a root por la vía más directa; los rechazos revelan la intención aunque fallen.

## Lógica

La regla usa `logsource.service: auth` porque mezcla dos decoders. Cada selección fija `decoder.name` para no cruzar campos:

- `selection_sudo_shell`: `data.dstuser: root` y `data.command` coincide con `(^|/)(bash|sh|dash|zsh|ksh|su)( |$)`. El patrón exige el nombre completo del binario, así `/usr/bin/ssh` o `bashful` no entran.
- `selection_sudo_rechazado`: `full_log` contiene los textos que sudo escribe al rechazar.
- `selection_su_fallido`: `rule.groups` con `authentication_failed`.
- `selection_su_desde_servicio`: `dstuser: root` y `srcuser` en la lista de cuentas de servicio.
- `filter_automatizacion`: cuentas con prefijo `svc-` quedan fuera. Es un ejemplo de convención; cada entorno ajusta este filtro.

## Falsos positivos conocidos

- Administradores que abren shell root con `sudo -i` o `sudo su`. En un equipo chico puede acotarse a usuarios concretos; en uno grande es mejor bajar `selection_sudo_shell` a nivel bajo y dejar el resto en medio.
- Cuentas de servicio con sudo legítimo cuyo nombre no sigue el prefijo del filtro.

## Cómo probarla

```bash
detectionlab run samples/escalamiento_sudo_su_anomalo/positivos.jsonl --solo-disparos
pytest -k sudo_su
```

Los negativos tienen `sudo apt update`, `sudo systemctl`, `sudo ssh`, un binario llamado `bashful`, un `su` exitoso de un humano y una cuenta `svc-backup` filtrada.
