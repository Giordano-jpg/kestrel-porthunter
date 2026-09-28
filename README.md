# Kestrel PortHunter

Aplicación de escritorio para mantener un **inventario de tu red con nmap**:
qué equipos hay, en qué IP está cada uno *ahora* (aunque DHCP se la cambie), qué puertos tienen
abiertos, a cuántos saltos están, y un **monitor que avisa si alguien te está escaneando**.

Sustituye el flujo de «`nmap -sL` → guardar en .txt → Ctrl+F en el Bloc de notas» por una base de
datos que recuerda cada equipo, su historial de IPs y sus puertos, y que se actualiza sola.

## Arrancar

### Windows (recomendado)

Requisitos: Python 3.10+, [nmap](https://nmap.org/download) y Npcap (se instala con nmap o Wireshark).

```
iniciar.bat          ventana de escritorio: sin navegador y SIN ABRIR NINGÚN PUERTO (recomendado)
iniciar_web.bat      alternativa en el navegador: http://127.0.0.1:8765 (sólo accesible desde este equipo)
```

La primera vez crea el entorno `.venv` e instala las dependencias (y las reinstala si falta alguna).
La ventana usa WebView2, el motor de Edge que ya trae Windows 11. Los errores se guardan en
`data\porthunter.log`.

Los dos **piden permisos de administrador una sola vez**: tu Npcap está en modo
«sólo administradores», así que sin permisos Windows mostraría el aviso de UAC en *cada* escaneo y
al iniciar el monitor. Alternativas:

- `.venv\Scripts\python.exe run.py` (sin permisos) + en *Ajustes* activar «Modo sin privilegios»
  (`--unprivileged`): sin avisos, pero sin MACs, sin ARP y sin `-O`.
- Reinstalar Npcap desmarcando *«Restrict Npcap driver's access to Administrators only»*.

### Linux nativo

```
sudo ./iniciar.sh        # con root: escaneo SYN, ARP, MACs, -O y monitor
./iniciar.sh             # sin root: funciona, pero con connect scan y sin monitor
```

En Linux arranca por defecto en modo navegador (`127.0.0.1:8765`). La ventana de escritorio también
funciona (`./iniciar.sh --desktop`) si instalas `pip install pywebview[qt]` o GTK, aunque las
aplicaciones gráficas suelen dar problemas al ejecutarse como root.

### ¿Y WSL?

Mejor no para esto: WSL2 usa una red NAT virtual, así que no ve tu LAN real (ni ARP ni MACs, y la
distancia en saltos sale mal). Si quieres usarlo igualmente, activa `networkingMode=mirrored` en
`%UserProfile%\.wslconfig`.

## Flujo de trabajo recomendado

1. **Importa tus .txt antiguos** (*Equipos → Importar…*). Reconoce la salida de `nmap -sL`
   (también si la guardaste con `>` en PowerShell, que la escribe en UTF-16), `-oN`, `-oG`, XML y
   listas «IP nombre». Respeta la fecha del escaneo original, así que no pisa datos más nuevos.
2. **Guarda tu red** (*Escanear → Guardar como red*), p. ej. `10.10.0.0/17` con
   «Descubrir activos» cada 30–60 min. Mientras la app esté abierta el inventario se mantiene al día solo.
3. **Marca con ☆ los equipos que conoces**: en el *Panel* verás siempre su IP actual, si responden y
   desde cuándo; y en *Novedades*, cuándo cambian de IP, dejan de responder o abren puertos nuevos.
4. Para **puertos en redes grandes usa «Inteligente»**: primero `-sn` y después puertos sólo de
   los activos.
5. El buscador del *Panel* sustituye al Ctrl+F: nombre, alias, IP actual **o antigua**, MAC,
   fabricante, número de puerto (`3389`) o servicio (`ssh`).

### `-sL` frente a `-sn`

| | `-sL` (lo que hacías) | `-sn` |
|---|---|---|
| Qué hace | Pregunta al DNS el nombre (PTR) de cada IP del rango | Comprueba qué equipos responden (ARP en tu LAN, ping y sondas TCP fuera) |
| Toca los equipos | No | Sí |
| ¿Dice si está encendido? | **No**: puede haber registros DNS viejos | Sí |
| Extra | Nombres de equipos apagados | MAC, fabricante, TTL y distancia |

«Nombres + activos» hace las dos cosas seguidas.

### Por qué «Inteligente» va mucho más rápido en una /17

Una /17 tiene 32.768 IPs. Escanear 1000 puertos en todas implica unos 32 millones de sondas, casi todas
contra IPs vacías que nmap tiene que esperar a que agoten el tiempo. Si hay, digamos, 400 equipos
activos, el descubrimiento (`-sn`) tarda unos minutos y los puertos se escanean sólo en esos 400.

### Distancia (lo que muestra Zenmap)

Se calcula, por orden de preferencia, con: `--traceroute` o `-O` si los usaste; «1 salto» si nmap
vio la MAC (el equipo está en tu misma red); o el TTL de la respuesta (un TTL de 126 es un Windows,
que empieza en 128, a 3 saltos). El TTL también sirve de pista del sistema: ~64 Linux/macOS/Android,
~128 Windows, ~255 equipos de red. Con *Traceroute* ves la ruta completa en la ficha del equipo.

## Monitor: ¿me están escaneando?

Captura con Npcap (como Wireshark) y detecta:

| Alerta | Patrón |
|---|---|
| Escaneo TCP | Un origen envía SYN a ≥15 puertos distintos tuyos en 10 s |
| Firma de nmap | SYN con ventana 1024/2048/3072/4096 y sólo la opción MSS (el `-sS` de nmap) |
| Sigiloso | Paquetes NULL, FIN sin ACK o XMAS, que el tráfico normal nunca genera |
| Escaneo UDP | ≥15 puertos UDP distintos (descontando respuestas a tus DNS, QUIC, etc.) |
| Barrido ARP | Un equipo pregunta por ≥25 IPs en 10 s: así descubre `nmap -sn` en la LAN |
| Barrido ICMP | Pings a muchos equipos distintos |

Además lista los **intentos de conexión entrantes** (quién intenta conectarse a qué puerto), que es lo
que antes buscabas en Wireshark. Cada alerta guarda un **.pcap** con los paquetes del origen (incluidos
los de antes de saltar la alerta) para abrirlo en Wireshark. Si la IP del atacante está en tu
inventario, la alerta muestra el nombre del equipo.

Límites: en una red con switch sólo ves el tráfico dirigido a ti y los broadcast. Por eso los
barridos ARP de otros equipos sí se detectan siempre, pero un escaneo de puertos contra *otro* equipo
no, salvo que captures en un puerto espejo (SPAN) o en el router. Muchas tarjetas Wi-Fi no admiten
el modo promiscuo en Windows.

## Datos

Todo queda en `data/` (no se sube a git):

- `porthunter.db`: inventario (SQLite, se puede abrir con DB Browser for SQLite).
- `scans/job_N_*.xml`: salida XML original de cada escaneo (se abre también con Zenmap).
- `scans/job_N.log`: salida de consola de nmap.
- `captures/*.pcap`: capturas de las alertas.
- `settings.json`: ajustes.
- `porthunter.log`: registro de la app (útil si algo falla en el modo escritorio, que no tiene consola).
- `ui/` y `webview/`: página generada y datos de la ventana de escritorio.

*Exportar TXT* genera un listado IP/nombre/estado parecido a tus .txt, pero con alias y puertos.
*Lista de IPs* sirve para `nmap -iL`.

## Seguridad

En una red privada, cualquier servicio que escuche en `0.0.0.0` (todas las interfaces) es accesible
con `IP:puerto` desde otro equipo de la red. Por eso:

- **Modo escritorio (`iniciar.bat`): no hay servidor ni puerto.** La interfaz llama a Python
  directamente dentro del mismo proceso (puente de pywebview) y la página se carga desde un fichero
  local. Nadie puede conectarse porque no hay nada escuchando. Compruébalo con
  `netstat -ano | findstr LISTENING`: no aparecerá ningún puerto del proceso `pythonw.exe`.
- **Modo navegador (`iniciar_web.bat`):** escucha sólo en `127.0.0.1`, una dirección que no sale
  de tu PC. Otro equipo de la red no puede alcanzarla ni sabiendo tu IP y el puerto
  (`netstat` mostrará `127.0.0.1:8765`, no `0.0.0.0:8765`). Además, todas las acciones exigen una
  cabecera propia y se valida la cabecera `Host`, así que una web maliciosa abierta en tu navegador
  tampoco puede lanzar escaneos (protección frente a CSRF y DNS rebinding). Sólo se expondría a la
  red si arrancas a mano con `--host 0.0.0.0`, y entonces la app lo advierte.
- Los objetivos no pueden empezar por `-` y los argumentos libres no admiten opciones de ficheros
  (`-oN`, `-iL`, `--script` con rutas…).
- Escanea sólo redes en las que tengas autorización.

## Estructura

```
run.py                  arranque (python run.py --help): --desktop / --web
iniciar.bat             Windows, ventana de escritorio (sin puertos)
iniciar_web.bat         Windows, modo navegador
iniciar.sh              Linux
porthunter/
  desktop.py            ventana nativa y puente JS <-> Python (sin servidor HTTP)
  web.py                API Flask + seguridad
  jobs.py               cola de tareas, ejecución de nmap, progreso, programación automática
  nmap_cmd.py           perfiles y construcción de comandos
  nmap_xml.py           parser del XML de nmap (tolera escaneos cancelados)
  inventory.py          identidad de equipos (MAC > DNS > NetBIOS > IP), historial, puertos, novedades
  importer.py           importación de .txt/-oN/-oG/XML
  detector.py           motor de detección de escaneos (independiente de Scapy)
  monitor.py            captura con Scapy/Npcap, alertas y .pcap
  system.py             diagnóstico (nmap, admin, Npcap, WSL, redes locales)
  static/               interfaz (HTML/CSS/JS sin dependencias)
tests/                  pytest
```

## Tests

```
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest
```

`tests/test_monitor.py` usa Scapy de verdad; en Windows sólo se ejecuta con
`PORTHUNTER_SCAPY_TESTS=1` (cargar Npcap puede pedir UAC). En Linux/WSL se ejecuta siempre.
