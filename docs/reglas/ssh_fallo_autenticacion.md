# Fallo de autenticación SSH

| | |
|---|---|
| ID | `b55ef7f2-b295-405d-9a11-c2830d22bf74` |
| Nombre | `ssh_fallo_autenticacion` |
| Nivel | informativo (regla base) |
| Táctica | Acceso a credenciales |
| Técnica | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing |
| Fuente | sshd (`/var/log/auth.log` decodificado por Wazuh) |

## Qué detecta

Cada intento fallido de autenticación en sshd: clave incorrecta, llave pública rechazada o usuario inexistente. No es una alerta por sí sola; existe para que `ssh_fuerza_bruta` cuente los fallos por IP y `ssh_login_exitoso_tras_rafaga` los encadene con un acceso exitoso.

## Técnica ATT&CK

T1110.001. Un fallo aislado es ruido; la técnica se materializa cuando los fallos se acumulan, y eso lo resuelven las correlaciones que dependen de esta regla.

## Lógica

- `rule.groups` contiene `authentication_failed` o `invalid_login` (reglas 5716, 5760 y 5710 de Wazuh).
- Se excluye `data.srcip` en `127.0.0.0/8` y `::1/128`: los fallos desde localhost suelen venir de pruebas o de agentes de monitoreo.

## Falsos positivos conocidos

- Usuarios que escriben mal la clave.
- Automatizaciones con llaves SSH caducadas, que fallan en cada ejecución programada.

## Cómo probarla

```bash
detectionlab run samples/ssh_fallo_autenticacion/positivos.jsonl --solo-disparos
detectionlab run samples/ssh_fallo_autenticacion/negativos.jsonl
pytest -k ssh_fallo_autenticacion
```

Los positivos son tres fallos desde IPs externas; los negativos incluyen un login exitoso, un fallo desde `127.0.0.1`, una desconexión y un evento de sudo.
