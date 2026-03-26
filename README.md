# CyberDeck Edu-Sec v2.1 — Suite de Auditoría Inalámbrica Educativa

> **Proyecto de Titulación** — Instituto Superior Tecnológico Universitario España (ISTE), Ambato, Ecuador, 2026

[![Arduino IDE](https://img.shields.io/badge/Arduino%20IDE-2.3+-00979D?logo=arduino)](https://www.arduino.cc/en/software)
[![ESP32](https://img.shields.io/badge/ESP32-2432S028R-E7352C)](https://www.espressif.com/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green)](LICENSE)
[![ISTE](https://img.shields.io/badge/ISTE-Ambato-blue)](https://www.iste.edu.ec/)

---

## ¿Qué es el CyberDeck Edu-Sec?

El CyberDeck Edu-Sec es una herramienta portátil de auditoría inalámbrica y análisis forense diseñada para el laboratorio de ciberseguridad del ISTE. Construida sobre el módulo ESP32-2432S028R (CYD — *Cheap Yellow Display*), integra **10 módulos** ofensivos, forenses y defensivos controlados mediante una pantalla táctil de 2.8" con estética *Terminal Hacker*.

El objetivo es democratizar el acceso al pentesting práctico: un dispositivo de USD 75.50 que reemplaza herramientas comerciales de USD 149–169 (Flipper Zero, WiFi Pineapple).

---

## Módulos del Firmware Suite Edu-Sec v2.1

| # | Módulo | Descripción | Capa OSI |
|---|--------|-------------|----------|
| 1 | **SCAN** | Escáner WiFi con exportación CSV (SSID, BSSID, RSSI, canal, cifrado) | L2 |
| 2 | **SNIFF** | Captura de tráfico PCAP con channel hopping y canal fijo para Handshakes | L2 |
| 3 | **SPAM** | Beacon Spammer — inyección de balizas 802.11 falsas | L2 |
| 4 | **PHISH** | Portal Cautivo con DNS hijacking y log de credenciales en SD | L7 |
| 5 | **DEAUTH** | Desautenticación masiva mediante tramas Deauth (Reason Code 7) | L2 |
| 6 | **BLE SPAM** | DoS visual BLE — seleccionable: iOS / Windows Swift Pair / Android Fast Pair | L2 |
| 7 | **SYNC** | Servidor web de extracción forense (descarga PCAP/CSV sin extraer la SD) | L7 |
| 8 | **EVIL AP** | Evil Twin — clonación automática del AP de mayor RSSI | L7 |
| 9 | **NMAP** | Escáner TCP de puertos 80/443 en red local vía SmartConfig | L3 |
| 10 | **IDS** | Sistema de Detección de Intrusos Blue Team — alerta Deauth masiva en tiempo real | L2 |

---

## Hardware Requerido

| Componente | Especificación | Costo aprox. |
|------------|---------------|--------------|
| Módulo CYD | ESP32-2432S028R (pantalla TFT 320×240, táctil XPT2046) | USD 45 |
| MicroSD | Clase 10, FAT32, hasta 32 GB | USD 15 |
| Cable Micro-USB | 5V, 1A mínimo (alimentación y programación) | USD 2 |
| Carcasa 3D | PETG blanco, diseño Clamshell (archivos STL incluidos) | USD 8.50 |
| Accesorios | Tornillos M3, insertos de latón | USD 5 |
| **Total** | | **USD 75.50** |

---

## Instalación del Firmware

### Requisitos previos

- [Arduino IDE 2.3+](https://www.arduino.cc/en/software)
- Soporte para ESP32 de Espressif (ver paso 1)
- Librerías: **TFT_eSPI** (Bodmer), SD, DNSServer, WebServer, BLEDevice (incluidas con el paquete ESP32)

### Paso 1 — Soporte ESP32 en Arduino IDE

En **Archivo → Preferencias**, agregar en "URLs adicionales":
```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```
En **Herramientas → Placa → Gestor**, instalar `esp32 by Espressif Systems v3.x`.

### Paso 2 — Configurar TFT_eSPI

Copiar el archivo `config/User_Setup.h` a la carpeta de instalación de TFT_eSPI:
```
~/Arduino/libraries/TFT_eSPI/User_Setup.h
```

### Paso 3 — Configurar la placa

En **Herramientas**:
- Placa: `ESP32 Dev Module`
- CPU Frequency: `240 MHz`
- Flash Size: `4MB`
- Upload Speed: `921600`

### Paso 4 — Calibrar el táctil

Ejecutar el ejemplo `Touch_calibrate` de la librería TFT_eSPI y reemplazar los valores en la línea:
```cpp
uint16_t calData[5] = { 264, 3361, 427, 3362, 1 };
```

### Paso 5 — Compilar y cargar

Conectar el CYD vía Micro-USB, seleccionar el puerto en Arduino IDE y presionar **Upload (→)**.

---

## Estructura del Repositorio

```
Proyecto-CyberDeck-EduSec-ISTE/
│
├── src/
│   └── EduSec_v2_1_UI/
│       ├── EduSec_v2_1_UI.ino      # Firmware principal (v2.1 UI Edition)
│       └── User_Setup.h            # ⚠ Copiar a carpeta TFT_eSPI
│
├── config/
│   └── User_Setup.h                # Configuración de pines del CYD
│
├── hardware/
│   ├── CyberDeck_Bisel_Frontal.stl # Pieza 3D — bisel frontal (PETG blanco)
│   ├── CyberDeck_Base_Trasera.stl  # Pieza 3D — base trasera (PETG blanco)
│   └── Pinout_ESP32_CYD.png        # Diagrama de pines del módulo CYD
│
├── docs/
│   ├── Propuesta_Tecnologica_ISTE.docx  # Documento de titulación
│   └── Manual_Usuario_CyberDeck.pdf     # Manual de operación
│
├── samples/
│   └── sample_capture.pcap         # Muestra de captura forense para Wireshark
│
├── .gitignore
├── LICENSE
└── README.md
```

---

## Notas de Uso Ético

> ⚠️ **IMPORTANTE**

Este proyecto es una herramienta **exclusivamente educativa**, diseñada y probada en el laboratorio aislado del ISTE bajo la supervisión del PhD. Marco Polo Silva.

El uso de cualquiera de estos módulos **fuera de un entorno controlado y sin autorización expresa** puede constituir un delito bajo el **Código Orgánico Integral Penal (COIP) del Ecuador**, específicamente los artículos 229–234, con penas de **3 meses a 5 años** de privación de libertad.

Como tecnólogos en ciberseguridad, la responsabilidad ética es parte central de nuestra profesión.

---

## Autores

| Nombre | Rol |
|--------|-----|
| Jairo Guillen Celi | Autor principal — firmware y documentación |
| Denis Toscano | Co-autor |
| Henry Chimbosina | Co-autor |
| Christian Chiluisa | Co-autor |
| **PhD. Marco Polo Silva** | Tutor |

**Institución:** Instituto Superior Tecnológico Universitario España (ISTE), Ambato, Ecuador  
**Año:** 2026

---

## Licencia

Este proyecto está licenciado bajo la [Licencia MIT](LICENSE).  
Libre para uso educativo con atribución a los autores y al ISTE.
