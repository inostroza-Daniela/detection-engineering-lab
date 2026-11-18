# Escaneo de puertos saliente

| | |
|---|---|
| ID | `fd72cbc3-d895-4d43-8841-9f2b9411d91f` |
| Nombre | `escaneo_red_saliente` |
| Nivel | alto |
| Táctica | Descubrimiento |
| Técnica | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| Tipo | correlación `value_count` sobre `conexion_saliente_sin_respuesta` |

## Qué detecta

Un origen interno que intenta conectarse a veinte o más puertos distintos sin respuesta dentro de un minuto. Es lo que produce `nmap` con sus 1.000 puertos por defecto, `masscan`, o un script de descubrimiento lanzado desde un equipo recién comprometido.

## Técnica ATT&CK

T1046. Es la primera cosa que hace un atacante después de conseguir un punto de apoyo: mirar qué más hay en la red.

## Lógica

```yaml
correlation:
  type: value_count
  rules: [conexion_saliente_sin_respuesta]
  group-by: [data.src_ip]
  timespan: 1m
  condition:
    field: data.dest_port
    gte: 20
```

Se cuentan puertos **distintos**, no conexiones: 25 reintentos contra el mismo puerto 5432 (un cliente insistiendo con una base de datos caída) no disparan. El barrido de hosts (un puerto, muchos destinos) queda fuera de esta versión; sería la misma regla con `field: data.dest_ip`.

## Falsos positivos conocidos

- Escáneres de vulnerabilidades autorizados (Nessus, OpenVAS, el propio Wazuh con vulnerability detection). Excluir sus IPs antes del motor o con un `filter` en la regla base.
- Herramientas de inventario que verifican muchos puertos por host.

## Cómo probarla

```bash
detectionlab run samples/escaneo_red_saliente --json
pytest -k escaneo_red
```

Los positivos son 45 puertos en 18 segundos. Los negativos cubren 10 puertos en un minuto, 25 puertos repartidos en diez minutos, 25 veces el mismo puerto y 25 puertos con respuesta (la regla base no dispara).
