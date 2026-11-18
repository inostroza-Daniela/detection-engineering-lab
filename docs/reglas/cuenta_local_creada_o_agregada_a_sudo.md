# Cuenta local creada o agregada a sudo

| | |
|---|---|
| ID | `ea7d86be-f211-40c4-b91b-c502128792e3` |
| Nombre | `cuenta_local_creada_o_agregada_a_sudo` |
| Nivel | alto |
| Tácticas | Persistencia, Escalamiento de privilegios |
| Técnicas | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account · [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation |
| Fuente | auditd |

## Qué detecta

Tres acciones que un atacante encadena para asegurarse el regreso con privilegios:

1. Crear una cuenta local interactiva (`useradd`, `adduser`).
2. Meter a un usuario en `sudo`, `wheel` o `admin` (`usermod -aG`, `gpasswd -a`, `adduser <usuario> sudo`).
3. Escribir en `/etc/sudoers` o `/etc/sudoers.d/` con algo que no sea `visudo`.

## Técnica ATT&CK

T1136.001 cubre la creación de la cuenta; T1098 cubre la manipulación posterior (grupos, sudoers). Como ambas suelen verse juntas y en el mismo minuto, la regla las agrupa y etiqueta las dos técnicas.

## Lógica

- `selection_creacion`: la línea de comando contiene `useradd` o `adduser` como comando. Se busca en `data.audit.execve.cmdline` y no en `exe` porque en Debian `adduser` es un script en perl y `exe` apunta a `/usr/bin/perl`.
- `filter_cuenta_sistema`: `--system` o `-r` indican cuentas de servicio creadas por paquetes; se excluyen.
- `selection_grupo_sudo`: tres regex que ligan el grupo al argumento correcto: `usermod ... -aG|-G|--groups|--append <lista con sudo|wheel|admin>`, `gpasswd -a <usuario> <grupo>` y `adduser <usuario> <grupo>`. Buscar `sudo` suelto en la línea no sirve: casi toda administración pasa por `sudo usermod ...` y dispararía con `sudo usermod -aG docker dani`.
- `selection_sudoers`: escritura exitosa en una ruta que empieza por `/etc/sudoers`.
- `filter_paquetes`: gestores de paquetes y `visudo` quedan fuera.

El campo `cmdline` lo construye el motor a partir de `data.audit.execve.a0..aN`, decodificando los argumentos hexadecimales de auditd (ver `docs/formato-eventos.md`).

## Falsos positivos conocidos

- Aprovisionamiento con Ansible, cloud-init o scripts de onboarding que crean usuarios reales. Acotar por `data.audit.auid` o por ventana de mantenimiento.
- `visudo` ya está filtrado; otros editores de sudoers (Puppet, Chef) habría que sumarlos al filtro.

## Cómo probarla

```bash
detectionlab run samples/cuenta_local_creada_o_agregada_a_sudo/positivos.jsonl --solo-disparos
pytest -k cuenta_local
```

Los negativos incluyen `useradd --system`, `useradd -r`, `usermod -aG docker`, `sudo usermod -aG docker dani`, `usermod -c "Administrador de red"`, `visudo` y `dpkg` escribiendo `/etc/sudoers.d/90-cloud-init-users`.
