# Exfiltración o túnel por DNS

| | |
|---|---|
| ID | `2c5285ac-3bb6-4c60-a1b7-eac644e3b1cc` |
| Nombre | `exfiltracion_dns` |
| Nivel | alto |
| Tácticas | Exfiltración, Comando y control |
| Técnicas | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) Exfiltration Over Unencrypted Non-C2 Protocol · [T1071.004](https://attack.mitre.org/techniques/T1071/004/) Application Layer Protocol: DNS |
| Fuente | Suricata `eve.json`, `event_type: dns` (categoría Sigma `dns_query`) |

## Qué detecta

Consultas DNS con la forma de un canal encubierto:

- primer label de 40 caracteres o más compuesto solo por caracteres de base32, base64 o hexadecimal;
- consultas de tipo `NULL`, que ningún cliente legítimo hace y que iodine usa para maximizar el ancho de banda;
- consultas `TXT` cuyo primer label son 20 o más caracteres alfanuméricos sin guiones, típico de dnscat2 y de exfiltración casera por trozos.

## Técnica ATT&CK

T1048.003 cuando el objetivo es sacar datos; T1071.004 cuando el DNS es el canal de mando. Desde la red se ven igual, por eso la regla etiqueta las dos.

## Lógica

- `consulta`: `data.dns.type: query`. Las respuestas (`answer`) se ignoran para no contar dos veces.
- `sospechoso_label_largo`: `^[a-z0-9+/=_-]{40,}\.` sin distinguir mayúsculas (`re|i`): Suricata conserva el case del cable e iodine usa base32 en mayúsculas.
- `sospechoso_tipo_null`: `data.dns.rrtype: NULL`
- `sospechoso_txt_codificado`: `rrtype: TXT` y `^[a-z0-9]{20,}\.`, también con `re|i`
- `filter_conocidos`: dominios que usan labels largos de forma legítima (CDNs, listas antispam, PTR inversos, verificaciones SPF).

La regla no calcula entropía ni volumen porque Sigma no lo permite en una regla base. Para detectar exfiltración lenta con labels cortos, la ampliación natural es una correlación `value_count` sobre `data.dns.rrname` por `data.src_ip`, igual que `escaneo_red_saliente` hace con los puertos.

## Falsos positivos conocidos

- CDNs y servicios antispam con labels largos que no estén en el filtro. Se amplía el filtro con los dominios del entorno.
- Servidores de correo que validan SPF/DKIM con muchas consultas TXT; los labels (`_dmarc`, `default._domainkey`) no cumplen el patrón alfanumérico, así que no deberían disparar.

## Cómo probarla

```bash
detectionlab run samples/exfiltracion_dns/positivos.jsonl --solo-disparos
pytest -k exfiltracion_dns
```

Los negativos tienen consultas A normales, un PTR, `_dmarc` TXT, un label largo de cloudfront filtrado y una respuesta (`type: answer`) con label largo.
