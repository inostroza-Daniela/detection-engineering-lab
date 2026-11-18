# Login SSH exitoso tras ráfaga de fallos

| | |
|---|---|
| ID | `ee3a5b04-0680-4e8b-ac58-9faf9aa7308d` |
| Nombre | `ssh_login_exitoso_tras_rafaga` |
| Nivel | alto |
| Tácticas | Acceso inicial, Acceso a credenciales |
| Técnicas | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing · [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| Tipo | correlación `temporal_ordered` sobre `ssh_fuerza_bruta` y `ssh_login_exitoso` |

## Qué detecta

Una IP que acaba de disparar `ssh_fuerza_bruta` abre una sesión SSH válida dentro de los diez minutos siguientes. Es la diferencia entre "alguien está probando" y "alguien entró": la fuerza bruta funcionó, o el atacante adivinó la clave de una cuenta real.

## Técnica ATT&CK

T1110.001 describe el intento; T1078 describe el resultado, el uso de una cuenta válida obtenida por la fuerza. La regla queda en la táctica de acceso inicial porque es el momento en que el atacante consigue un punto de apoyo.

## Lógica

```yaml
correlation:
  type: temporal_ordered
  rules: [ssh_fuerza_bruta, ssh_login_exitoso]
  group-by: [data.srcip]
  timespan: 10m
```

Es una correlación sobre otra correlación: `ssh_fuerza_bruta` produce una detección con la marca de tiempo del último fallo de la ráfaga, y esta regla exige que después de ella, y no antes, llegue un `ssh_login_exitoso` del mismo `data.srcip`. Un login seguido de una ráfaga (orden inverso) no dispara.

## Falsos positivos conocidos

- Un administrador que se equivoca diez veces y luego entra con la clave correcta. Es raro pero ocurre con gestores de contraseñas mal configurados; la alerta sigue valiendo la revisión.

## Cómo probarla

```bash
detectionlab run samples/ssh_login_exitoso_tras_rafaga --json
pytest -k tras_rafaga
```

Los negativos cubren tres variantes que no deben disparar: login desde otra IP, login 30 minutos después y ráfaga posterior al login.
