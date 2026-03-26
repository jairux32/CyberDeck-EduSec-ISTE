# Historial de Versiones — CyberDeck Edu-Sec

## [v2.1] — 2026 (UI Edition) — Versión Final

### Nuevas funcionalidades
- **Splash Screen animado** con efecto typewriter al encender el dispositivo
- **Botones con icono ASCII + etiqueta** en doble nivel con doble borde
- **Animación Matrix Rain** en inactividad (30 s sin tocar)
- **Barra de estado mejorada** con modo activo (color semántico) y canal Wi-Fi
- **Retroalimentación táctil con onda de expansión** al presionar botones
- **Canal fijo en Sniffer** (botón CH:AUTO / CH:FIX para captura de Handshakes WPA2)

### Correcciones de bugs
- **Bug crítico BLE Spam Windows/Android**: pantalla blanca y reinicio del ESP32
  - Causa: payload < 10 bytes causaba stack overflow en el BLE stack del ESP32
  - Fix: función `buildPayload()` con padding mínimo de 10 bytes
  - Fix: `BLEAdvertisementData` asignado en heap estático (`static ... = nullptr`)
  - Fix: `delay(100)` después de `BLEDevice::deinit(true)` al cambiar de target

---

## [v2.0] — 2026

### Nuevas funcionalidades
- **Módulo 10: IDS Blue Team** — detección de ataques Deauth masiva (>5 tramas/2s)
  - Alerta visual con pantalla roja completa
  - Log automático en `/ids_log.txt` con timestamp
  - Channel hopping propio para monitorear todos los canales
- **SmartConfig con timeout 60 s** y cuenta regresiva visible en pantalla
- **CSV completo** — incluye canal y tipo de cifrado (OPEN/WEP/WPA/WPA2/WPA3)
- **PCAP con timestamp** — archivos `/cap_XXXXX.pcap` separados por sesión
- **Log de phishing en SD** — credenciales guardadas en `/phish_log.txt`
- **Contador de víctimas** en Portal Cautivo y Evil Twin (tiempo real)
- **Aviso si Evil Twin no encuentra redes** al escanear
- BLE Spam multitarget: selector táctil iOS / Windows / Android

### Correcciones de bugs
- Bug visual en Deauth: texto "INYECCION ACTIVA" se superponía con "Mapeando objetivos"

---

## [v1.9.2] — 2026 (Base)

### Estado inicial del proyecto
- 9 módulos funcionales: SCAN, SNIFF, SPAM, PHISH, DEAUTH, BLE SPAM, SYNC, EVIL TWIN, NMAP
- Solución colisión bus SPI: búfer RAM con escritura diferida (2000 ms)
- Interfaz Terminal Hacker con fondo negro y paleta neón
- Carcasa PETG blanca impresa en 3D (FreeCAD, diseño Clamshell)
- Alimentación por Micro-USB (5V continuos)
