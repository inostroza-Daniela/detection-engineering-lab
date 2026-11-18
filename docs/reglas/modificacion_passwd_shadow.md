# Acceso a /etc/shadow o modificación directa de /etc/passwd

| | |
|---|---|
| ID | `b0ba4bb6-e170-4b63-8cd5-28b3e489f635` |
| Nombre | `modificacion_passwd_shadow` |
| Nivel | alto |
| Tácticas | Acceso a credenciales, Persistencia |
| Técnicas | [T1003.008](https://attack.mitre.org/techniques/T1003/008/) OS Credential Dumping: /etc/passwd and /etc/shadow · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| Fuente | auditd (watch `-p rwa` sobre shadow y gshadow, `-p wa` sobre passwd y group) |

## Qué detecta

Dos cosas con el mismo origen:

- **Lectura o escritura de `/etc/shadow` y `/etc/gshadow`** por un proceso que no es parte de la autenticación ni de la administración de cuentas: `cat`, un editor, una shell, un script. Es el volcado de hashes para crackearlos offline, y también el intento fallido (`success=no`) de un usuario sin privilegios, que delata una webshell o una cuenta comprometida probando suerte.
- **Escritura exitosa en `/etc/passwd` y `/etc/group`** por un proceso que no es una herramienta de cuentas: inserción de un usuario con UID 0, cambio de shell o de grupo a mano.

## Técnica ATT&CK

T1003.008 por el acceso a los archivos de credenciales; T1098 porque el objetivo habitual de la escritura es manipular cuentas para persistir. La lectura de `/etc/passwd` no se vigila: la hace cada `ls -l` y no tiene valor como señal.

## Lógica

- `selection_shadow`: `data.audit.file.name` empieza por `/etc/shadow` o `/etc/gshadow`, con o sin éxito.
- `selection_passwd`: empieza por `/etc/passwd` o `/etc/group` y `data.audit.success: yes`.
- `filter_herramientas`: binarios que escriben estos archivos de forma legítima (`useradd`, `passwd`, `chage`, `vipw`, `gpasswd`...).
- `filter_autenticacion`: procesos que leen shadow para autenticar: `sshd` y `sshd-session` (OpenSSH 9.8+), `unix_chkpwd`, `sudo`, `su`, `login`, `cron`, `systemd-logind`.

Con un watch `-p rwa` auditd no distingue en sus campos si el acceso fue lectura o escritura (el número de syscall cambia entre arquitecturas y no se usa), por eso ambos filtros se aplican a las dos selecciones.

## Falsos positivos conocidos

- Herramientas de configuración (Ansible `user`, Puppet) que escriben directamente estos archivos. Sumar su binario al filtro o acotar por `auid`.
- Servicios con módulos PAM propios que leen shadow: gestores de pantalla (gdm, sddm), dovecot, samba, vsftpd. Cada entorno agrega los suyos a `filter_autenticacion`.
- Mantenimiento planificado con editor. Debería ser excepcional.

## Cómo probarla

```bash
detectionlab run samples/modificacion_passwd_shadow/positivos.jsonl --solo-disparos
pytest -k passwd_shadow
```

Los positivos incluyen `cat /etc/shadow` por www-data (con y sin éxito), `python3.12` leyendo gshadow y escrituras por `vim`, `bash`, `sed` y `nano`. Los negativos son `passwd`, `useradd`, `chage`, `groupadd`, `vipw`, `sshd-session`, `unix_chkpwd` y `sudo` leyendo shadow, un intento fallido de `vim` sobre `/etc/group` y una escritura en `/etc/pam.d/passwd`, que comparte prefijo de nombre pero no de ruta.
