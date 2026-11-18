# Formato de eventos

El motor evalúa eventos JSON con la forma de las alertas de Wazuh (`/var/log/alerts/alerts.json`). La decisión es deliberada: el repo `incident-response-lab` va a levantar un Wazuh real y sus alertas tienen que entrar aquí sin conversión.

## Envoltorio común

```json
{
  "timestamp": "2026-11-10T08:00:00.000-0300",
  "rule": {"id": "5716", "level": 5, "description": "sshd: authentication failed.", "groups": ["syslog", "sshd", "authentication_failed"]},
  "agent": {"id": "001", "name": "web-01", "ip": "10.0.10.21"},
  "manager": {"name": "wazuh-manager"},
  "id": "1762772400.000001",
  "full_log": "Nov 10 08:00:00 web-01 sshd[1234]: Failed password for dani from 203.0.113.45 port 51234 ssh2",
  "decoder": {"name": "sshd"},
  "data": {"srcip": "203.0.113.45", "srcport": "51234", "dstuser": "dani"},
  "location": "/var/log/auth.log"
}
```

| Campo | Uso en el motor |
|---|---|
| `timestamp` | Marca de tiempo para las correlaciones. Acepta el formato de Wazuh (`-0300`), ISO 8601 con `Z` y sin zona (se asume UTC). |
| `decoder.name` | Decide a qué `logsource` Sigma pertenece el evento (ver tabla siguiente). |
| `rule.groups` | Lista; los modificadores `contains` coinciden si algún elemento cumple. |
| `data.*` | Campos decodificados. Las reglas los referencian con notación de puntos (`data.audit.exe`). |
| `full_log` | Línea cruda; algunas reglas buscan texto ahí (`sudo: user NOT in sudoers`). |

## Enrutamiento por `logsource`

| `logsource` Sigma | Fuente | Filtro sobre el evento |
|---|---|---|
| `product: linux, service: sshd` | sshd | `decoder.name == sshd` |
| `product: linux, service: sudo` | sudo | `decoder.name == sudo` |
| `product: linux, service: auth` | auth | `decoder.name` en `sshd`, `sudo`, `su`, `pam_unix`, `pam` |
| `product: linux, service: auditd` | auditd | `decoder.name == auditd` |
| `product: linux, category: dns_query` | Suricata DNS | `decoder.name == json` y `data.event_type == dns` |
| `product: linux, category: network_connection` | Suricata flow | `decoder.name == json` y `data.event_type == flow` |

Un `logsource` que no esté en esta tabla hace fallar la carga de reglas con un error explícito; la tabla vive en `src/detectionlab/fuentes.py`.

## Campos por fuente

### sshd (`decoder.name: sshd`)

`data.srcip`, `data.srcport`, `data.dstuser` (usuario válido) o `data.srcuser` (usuario inexistente). Los grupos relevantes son `authentication_failed`, `invalid_login` y `authentication_success`.

### sudo y su (`decoder.name: sudo` / `su`)

sudo: `data.srcuser`, `data.tty`, `data.pwd`, `data.dstuser`, `data.command`. Los rechazos solo aparecen en `full_log`.
su: `data.srcuser`, `data.dstuser`; el grupo `authentication_failed` marca los fallos.

### auditd (`decoder.name: auditd`)

Wazuh agrupa los registros SYSCALL, EXECVE, CWD y PATH de un mismo evento bajo `data.audit.*`:

| Campo | Contenido |
|---|---|
| `data.audit.type` | `SYSCALL` |
| `data.audit.syscall` | Número de syscall. **No se usa en las reglas**: cambia entre x86_64 y arm64. |
| `data.audit.success` | `yes` / `no` |
| `data.audit.auid`, `uid`, `euid` | Numéricos (`1000`, `33`, `4294967295` = sin sesión) o nombres si auditd corre con `log_format = ENRICHED` |
| `data.audit.exe` | Ruta del binario |
| `data.audit.command` | `comm`, el nombre corto del proceso |
| `data.audit.cwd` | Directorio de trabajo |
| `data.audit.key` | Llave `-k` de la regla de auditd |
| `data.audit.file.name` | Ruta tocada (registro PATH) |
| `data.audit.execve.a0..aN` | Argumentos del `execve` |

### Suricata (`decoder.name: json`, `location: /var/log/suricata/eve.json`)

El decoder JSON de Wazuh aplana `eve.json` bajo `data`: `data.event_type`, `data.src_ip`, `data.dest_ip`, `data.dest_port`, `data.proto`, `data.dns.{type,rrname,rrtype}`, `data.flow.{pkts_toserver,pkts_toclient,state,reason}`.

## Enriquecimiento que hace el motor

auditd codifica en hexadecimal cualquier argumento que contenga espacios o comillas, y Wazuh lo deja tal cual. Un `bash -c "bash -i >& /dev/tcp/..."` llega así:

```json
"execve": {"a0": "bash", "a1": "-c", "a2": "62617368202D69203E26202F6465762F7463702F..."}
```

Antes de evaluar, el motor (`src/detectionlab/normalizar.py`) hace dos cosas sobre una copia del evento:

1. Decodifica los `aN` que son hexadecimal puro y decodifican a texto imprimible. `deadbeef` o `1234` se dejan como están.
2. Agrega `data.audit.execve.cmdline` con los argumentos unidos por espacio.

Las reglas buscan en `cmdline`, que es el equivalente al `CommandLine` de Sysmon. Es el único campo que no viene de Wazuh; el evento original no se modifica.

## Logs reales

Para evaluar alertas de un Wazuh real:

```bash
detectionlab run /var/ossec/logs/alerts/alerts.json
```

El archivo puede ser una lista JSON, un objeto o JSON Lines. Los eventos que no pertenecen a ninguna fuente conocida simplemente no se evalúan.
