# Login SSH exitoso

| | |
|---|---|
| ID | `338ad587-9e74-42ee-9d9a-7c2594a5c33d` |
| Nombre | `ssh_login_exitoso` |
| Nivel | informativo (regla base) |
| Táctica | Movimiento lateral |
| Técnica | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH |
| Fuente | sshd |

## Qué detecta

Toda sesión SSH abierta con éxito (`Accepted password` / `Accepted publickey`). Es la segunda pieza de `ssh_login_exitoso_tras_rafaga`: sin registrar los accesos legítimos no hay forma de saber cuándo una ráfaga de fallos terminó en un login.

## Técnica ATT&CK

T1021.004. SSH es el vector estándar de movimiento lateral en Linux, por eso la regla queda etiquetada aunque por sí sola no indique nada malo.

## Lógica

- `rule.groups` contiene `authentication_success` (regla 5715 de Wazuh).

## Falsos positivos conocidos

- Todos los accesos legítimos. Esta regla no debe generar alertas; su nivel es informativo y el sitio la muestra como regla base.

## Cómo probarla

```bash
detectionlab run samples/ssh_login_exitoso/positivos.jsonl --solo-disparos
pytest -k ssh_login_exitoso
```
