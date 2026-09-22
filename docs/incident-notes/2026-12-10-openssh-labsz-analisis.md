# Análisis de captura SSH — host `LabSZ`, 10-dic 06:55 → 11:04 UTC

> Análisis realizado con mini-siem sobre `sample_logs/openssh_real.log`, una
> captura real de `/var/log/auth.log` publicada en el dataset abierto
> [Loghub](https://github.com/logpai/loghub) (OpenSSH). Los atacantes, las IPs y
> los intentos son reales; el host no es un sistema propio.

---

## 1. Resumen ejecutivo

Se analizaron 2000 líneas de registros de acceso remoto SSH del servidor LabSZ,
correspondientes a unas cuatro horas. Se identificaron 524 intentos fallidos,
principalmente contra la cuenta root, ninguno de ellos exitoso, y un acceso
exitoso a la cuenta fztu desde una IP sin intentos previos. La legitimidad de
ese acceso queda pendiente de verificar con el titular de la cuenta. Se
recomienda investigar ese acceso, reforzar la configuración de SSH y mejorar la
detección de intentos de baja frecuencia y el análisis automático de sesiones.

---

## 2. Alcance y datos

| | |
|---|---|
| Fuente | `/var/log/auth.log` de un único host Linux |
| Host | `LabSZ` (2000 de 2000 líneas) |
| Ventana | 2026-12-10 06:55:46 → 11:04:45 UTC (4,1 horas) |
| Líneas | 2000 |
| Eventos normalizados | 2000 (100 % de las líneas produjeron un evento) |
| Herramienta | mini-siem, 8 reglas de detección cargadas |

Limitación de origen: es **un solo host** y **una sola fuente de log**. No hay
firewall, ni netflow, ni logs de aplicación. Todo lo que se afirme más abajo
está limitado a lo que sshd decidió escribir.

---

## 3. Cobertura del parser

| event_type / outcome | eventos | % |
|---|---:|---:|
| `context` / unknown | 874 | 43,7 % |
| `authentication` / failure | 524 | 26,2 % |
| `scan` / unknown | 511 | 25,6 % |
| `warning` / unknown | 85 | 4,2 % |
| `daemon` / unknown *(no reconocido)* | 4 | 0,2 % |
| `authentication` / success | 1 | 0,1 % |
| `session` / success | 1 | 0,1 % |

**Cobertura: 99,8 %.** Las 4 líneas no reconocidas son:

```
Invalid user  0101 from 5.188.10.180          <- doble espacio en el usuario
pam_unix(sshd:session): session opened for user fztu by (uid=0)
pam_unix(sshd:session): session closed for user fztu
fatal: Write failed: Connection reset by peer [preauth]
```

El parser no permite relacionar automáticamente la apertura y el cierre de una
sesión para determinar cuánto duró y si se cerró dentro del período analizado.
Para la cuenta fztu, la revisión manual de los registros sí permite calcular una
duración de 12 minutos y 46 segundos. Estos registros no muestran qué acciones
realizó el usuario durante la sesión; para investigarlo se necesitan registros
adicionales.

---

## 4. Panorama de la actividad

- **30 IPs distintas** aparecen en la captura.
- **24 IPs** intentaron autenticarse y fallaron.
- **5 IPs** sólo tocaron el puerto y se fueron sin intentar credenciales.
- **4 IPs** dispararon el warning de sshd por *reverse DNS* que no coincide.
- **524 intentos fallidos**, **1 exitoso**.

Usuarios más apuntados (sobre los 524 fallos):

| usuario | intentos |
|---|---:|
| `root` | 370 |
| `admin` | 45 |
| `support` | 6 |
| `oracle` | 6 |
| `uucp` | 5 |
| `test` | 5 |

El **27 %** de los fallos fueron contra usuarios que **no existen** en el sistema.

Distribución por IP (las que más fallaron):

| IP | fallos | duración | fallos/min | usuarios distintos |
|---|---:|---:|---:|---:|
| 183.62.140.253 | 286 | 10 min | 27,95 | 10 |
| 187.141.143.180 | 80 | 7 min | 11,06 | 28 |
| 103.99.0.122 | 46 | 113 min | 0,41 | 19 |
| 112.95.230.3 | 26 | 1 min | 26,44 | 3 |
| 5.188.10.180 | 20 | 2 min | 11,01 | 7 |
| 185.190.58.151 | 18 | 6 min | 3,21 | 4 |
| 52.80.34.196 | 5 | 193 min | **0,03** | 3 |

La IP 187.141.143.180 distribuyó 80 intentos entre 28 usuarios, lo que sugiere
una exploración de distintos nombres de cuenta. La IP 183.62.140.253 concentró
286 intentos en 10 usuarios, lo que sugiere una mayor insistencia sobre un grupo
reducido de cuentas. La primera podría estar buscando usuarios válidos y la
segunda intentando adivinar contraseñas para nombres seleccionados. Sin embargo,
estos datos no demuestran que ninguna de las dos conociera las cuentas reales
del sistema.

---

## 5. Hallazgos

### H1 — Intentos fallidos contra root desde múltiples IPs

De los 524 intentos fallidos, 370 apuntaron a la cuenta root desde múltiples
IPs. Este patrón es compatible con intentos automatizados contra un nombre de
cuenta conocido y no demuestra que el ataque estuviera dirigido específicamente
contra LabSZ. Tampoco hay evidencia suficiente para afirmar que las distintas
IPs formaban una campaña coordinada. En la captura no se observa ninguna
autenticación exitosa como root.

### H2 — Atacante de baja tasa: `52.80.34.196`

La IP 52.80.34.196 realizó cinco intentos fallidos separados por
aproximadamente 48 minutos, con apenas 12 segundos de diferencia entre el
intervalo más corto y el más largo. Esta regularidad sugiere un proceso
automatizado. Su baja frecuencia puede evitar alertas basadas en muchos fallos
en poco tiempo, aunque no demuestra que esa fuera la intención. El nombre DNS
indicado sugiere una instancia de AWS en la región china cn-north-1; no
identifica a la persona responsable ni su ubicación física. Si fuera necesario
reportar el abuso al proveedor, habría que aportar la IP y las horas exactas.
Los tres intentos contra matlab podrían proceder de una lista de usuarios
habituales. Su posible relación con el nombre LabSZ es una hipótesis sin
evidencia suficiente.

Evidencia — los cinco intentos, con su hora exacta:

```
07:07:45  Failed password for invalid user test9   from port 36060
07:56:02  Failed password for invalid user test    from port 36060
08:44:27  Failed password for invalid user matlab  from port 46199
09:32:42  Failed password for invalid user matlab  from port 36060
10:21:09  Failed password for invalid user matlab  from port 36060
```

Intervalos entre intentos: **48m17s, 48m25s, 48m15s, 48m27s.**

El *reverse DNS* de la IP es:

```
ec2-52-80-34-196.cn-north-1.compute.amazonaws.com.cn
```

### H3 — El único login exitoso

A las 09:32:20 se registró una autenticación exitosa de la cuenta fztu desde
119.137.62.142. La sesión duró 12 minutos y 46 segundos y terminó de forma
limpia. Esa IP no presentó fallos previos en la captura, pero ninguno de estos
hechos demuestra que el acceso fuera autorizado. No se observa evidencia que lo
conecte con las IPs que realizaron los intentos fallidos. El siguiente intento
de 52.80.34.196 ocurrió 22 segundos después y encaja con su cadencia previa de
aproximadamente 48 minutos, por lo que la cercanía temporal no basta para
relacionarlos. Para determinar si el acceso fue legítimo, falta confirmar la
conexión con el titular de la cuenta, contrastar la IP con sus orígenes
habituales y revisar registros de actividad durante la sesión.

Evidencia:

```
09:32:20  Accepted password for fztu from 119.137.62.142 port 49116 ssh2
09:32:20  session opened for user fztu
09:45:06  Received disconnect from 119.137.62.142: disconnected by user
09:45:06  session closed for user fztu
```

- La IP `119.137.62.142` **no produjo ningún intento fallido** en toda la captura.
- La sesión duró 12 minutos y 46 segundos y terminó de forma limpia.
- Veintidós segundos después de ese login, `52.80.34.196` hizo su cuarto intento.

---

## 6. Veredicto: ¿hubo compromiso?

**Intentos de fuerza bruta:** en la ventana analizada se registraron 524
intentos fallidos desde 24 IPs, sin autenticaciones exitosas observadas desde
esas IPs. No se observa que esos intentos hayan conseguido acceso al servidor
durante el período cubierto.

**Acceso de fztu:** se registró una autenticación exitosa desde una IP distinta,
sin evidencia que la vincule con los intentos anteriores. Su legitimidad queda
pendiente de verificación. Para cerrar este punto, se debe confirmar con el
titular de la cuenta si realizó esa conexión en el horario registrado y
contrastar su respuesta con el origen de conexión y los registros de actividad
de la sesión. Si la evidencia confirma que el acceso no estaba autorizado, se
clasificaría como compromiso.

---

## 7. Qué NO pudo ver este análisis

- **Intentos por debajo de los umbrales:** 14 de las 24 IPs con fallos no
  generaron alertas. Esto muestra una limitación de cobertura: que una actividad
  no active una regla no significa que sea legítima.
- **Falta de detección de secuencias:** el motor no permite detectar
  automáticamente una secuencia de varios fallos seguida de un acceso exitoso
  desde la misma IP.
- **Sesiones sin interpretar automáticamente:** el parser no reconoce las líneas
  de apertura y cierre de sesión indicadas. Es necesario revisarlas manualmente
  para determinar su duración.
- **Actividad posterior al acceso desconocida:** los registros disponibles no
  muestran qué comandos se ejecutaron, qué archivos se modificaron o si se
  elevaron privilegios.
- **Visibilidad limitada:** solo se dispone de registros SSH de un host durante
  unas cuatro horas. No hay registros de otros equipos, firewall o tráfico de
  red para investigar actividad relacionada.
- **Identidad y autorización sin confirmar:** una IP y una autenticación exitosa
  no permiten identificar por sí solas a la persona que accedió ni confirmar que
  tenía autorización.

---

## 8. Recomendaciones

**Sobre el host `LabSZ`**

1. **Verificar el acceso de fztu:** confirmar la conexión con el titular de la
   cuenta y revisar la actividad de esa sesión para determinar si fue autorizada.
2. **Deshabilitar el acceso SSH directo de root** (`PermitRootLogin no`):
   impediría acceder directamente a la cuenta que recibió 370 intentos fallidos;
   antes debe verificarse que exista otra cuenta administrativa con acceso y
   permisos adecuados.
3. **Migrar a autenticación mediante claves y deshabilitar la autenticación por
   contraseña:** reduce la exposición a intentos de adivinar contraseñas;
   primero debe comprobarse que los usuarios autorizados pueden acceder mediante
   sus claves.

**Sobre el SIEM**

4. **Ampliar la detección de intentos de baja frecuencia:** complementar la regla
   existente con ventanas más largas y agrupaciones por IP y usuario para
   mejorar la cobertura de actividad que queda bajo los umbrales actuales.
   (Nota: agrupar por dos campos a la vez no está soportado por el motor actual
   — es un pendiente de desarrollo, no un cambio de configuración.)
5. **Corregir el parser e incorporar reglas de secuencia:** reconocer aperturas y
   cierres de sesión y detectar fallos seguidos de un acceso exitoso para
   facilitar la investigación.

No se recomienda bloquear las IPs observadas. La infraestructura identificada en
H2 es una instancia de nube alquilada, y bloquear direcciones desechables de a
una aporta poco frente a los cambios de configuración de arriba. Limitar la tasa
de intentos en el propio host (por ejemplo con fail2ban) ataca el mismo problema
sin depender de una lista de direcciones.

---

## Anexo A — Alertas generadas

12 alertas, sobre 10 IPs distintas:

| regla | alertas | IPs |
|---|---:|---|
| `ssh-brute-force` (threshold) | 11 | 183.62.140.253 ×2, 103.99.0.122 ×2, 187.141.143.180, 112.95.230.3, 5.188.10.180, 185.190.58.151, 123.235.32.19, 119.4.203.64, 60.2.12.12 |
| `ssh-brute-force-slow` (low_and_slow) | 1 | 52.80.34.196 |

Las otras 6 reglas cargadas no dispararon: `port-scan-detected`,
`ssh-lateral-movement`, `ssh-login-from-blacklisted-ip`, `web-dir-scan`,
`web-dir-scan-slow`, `web-sqli-attempt`. Es el resultado esperado — esta captura
no contiene logs web ni tráfico hacia múltiples hosts.

## Anexo B — Reproducir este análisis

```bash
python -m siem.cli ingest-file sample_logs/openssh_real.log sshd
```
