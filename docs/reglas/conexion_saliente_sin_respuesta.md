# Conexión TCP saliente sin respuesta

| | |
|---|---|
| ID | `8b8aa783-84f3-4412-86ff-0ef3971bcec2` |
| Nombre | `conexion_saliente_sin_respuesta` |
| Nivel | informativo (regla base) |
| Táctica | Descubrimiento |
| Técnica | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| Fuente | Suricata `eve.json`, `event_type: flow` (categoría Sigma `network_connection`) |

## Qué detecta

Un flujo TCP iniciado desde una dirección interna (RFC 1918) que no recibió ningún paquete de vuelta: `flow.pkts_toclient: 0`. Es un SYN a un puerto cerrado o filtrado. Uno solo no significa nada; esta regla existe para que `escaneo_red_saliente` cuente cuántos puertos distintos prueba un mismo origen.

## Técnica ATT&CK

T1046. El descubrimiento de servicios se ve como muchas de estas conexiones en poco tiempo; la regla base aporta el evento unitario.

## Lógica

- `data.proto: TCP`, `data.flow.pkts_toclient: 0` y `data.src_ip` en `10.0.0.0/8`, `172.16.0.0/12` o `192.168.0.0/16`.

No hay filtro de broadcast: TCP no se usa contra direcciones de broadcast, y filtrar por `.255` excluiría hosts válidos en redes mayores que /24.

Suricata emite el evento `flow` al cerrar el flujo (timeout en este caso), por eso la marca de tiempo es unos segundos posterior al SYN.

## Falsos positivos conocidos

- Servicios caídos que siguen recibiendo conexiones de clientes legítimos. La regla no alerta por sí sola; en la correlación se descartan porque los clientes repiten el mismo puerto.

## Cómo probarla

```bash
detectionlab run samples/conexion_saliente_sin_respuesta/positivos.jsonl --solo-disparos
pytest -k conexion_saliente
```

Los negativos: dos flujos con respuesta, uno UDP y uno desde una IP externa.
