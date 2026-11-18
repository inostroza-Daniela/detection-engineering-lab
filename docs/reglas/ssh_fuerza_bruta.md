# Fuerza bruta SSH desde una misma IP

| | |
|---|---|
| ID | `9c191180-315f-4a64-9a4e-e58685d11a46` |
| Nombre | `ssh_fuerza_bruta` |
| Nivel | medio |
| Táctica | Acceso a credenciales |
| Técnica | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing |
| Tipo | correlación `event_count` sobre `ssh_fallo_autenticacion` |

## Qué detecta

Diez o más fallos de autenticación SSH desde la misma IP de origen dentro de dos minutos. Es el patrón de hydra, medusa o cualquier script que recorre un diccionario contra el puerto 22.

## Técnica ATT&CK

T1110.001 (adivinación de contraseñas). El atacante prueba credenciales contra una cuenta o una lista de cuentas; la señal es el volumen por origen, no un fallo concreto.

## Lógica

```yaml
correlation:
  type: event_count
  rules: [ssh_fallo_autenticacion]
  group-by: [data.srcip]
  timespan: 2m
  condition: {gte: 10}
```

El motor usa una ventana deslizante: en cuanto una IP acumula diez fallos en dos minutos emite una detección y reinicia el conteo, así una ráfaga de 200 intentos produce un puñado de alertas y no 190.

El umbral está calibrado para un servidor expuesto a internet. En una red interna, donde nadie debería equivocarse diez veces, conviene bajarlo a 5.

## Falsos positivos conocidos

- Escáneres de vulnerabilidades internos que prueban credenciales por defecto. Excluir sus IPs antes del motor o en un `filter` de la regla base.
- Herramientas de monitoreo con credenciales rotadas sin actualizar, que fallan en bucle.

## Cómo probarla

```bash
detectionlab run samples/ssh_fuerza_bruta/positivos.jsonl --json
pytest -k ssh_fuerza_bruta
```

Los positivos contienen una ráfaga de 25 fallos en 84 segundos desde `203.0.113.45` y otra de exactamente 10 desde `198.51.100.7`. Los negativos tienen seis fallos en dos minutos, doce repartidos en 40 minutos y quince IPs distintas con un fallo cada una: ninguno debe disparar.
