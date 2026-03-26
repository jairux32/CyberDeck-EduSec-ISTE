// ============================================================
// User_Setup.h para ESP32-2432S028R (CYD — Cheap Yellow Display)
// CyberDeck Edu-Sec v2.1 — ISTE Ambato 2026
//
// INSTRUCCIONES:
// Copiar este archivo a: ~/Arduino/libraries/TFT_eSPI/User_Setup.h
// (reemplazar el archivo existente)
// ============================================================

#define USER_SETUP_INFO "CYD_EduSec_Setup"

// ── Driver de pantalla ──────────────────────────────────────
#define ILI9341_2_DRIVER

// ── Dimensiones de pantalla ─────────────────────────────────
#define TFT_WIDTH  240
#define TFT_HEIGHT 320

// ── Pines SPI de la pantalla TFT (bus SPI principal) ───────
#define TFT_MISO 12
#define TFT_MOSI 13
#define TFT_SCLK 14
#define TFT_CS   15    // Chip Select pantalla
#define TFT_DC    2    // Data/Command
#define TFT_RST  -1    // Reset (conectado al EN del ESP32)
#define TFT_BL   21    // Backlight

// Nivel activo del backlight
#define TFT_BACKLIGHT_ON HIGH

// ── Pin Chip Select del sensor táctil XPT2046 ──────────────
// Nota: comparte el bus SPI con la pantalla (MISO/MOSI/SCLK)
#define TOUCH_CS 33

// ── Inversión de color ──────────────────────────────────────
#define TFT_INVERSION_ON

// ── Fuentes a incluir ───────────────────────────────────────
#define LOAD_GLCD    // Fuente 1 (8px)
#define LOAD_FONT2   // Fuente 2 (16px)
#define LOAD_FONT4   // Fuente 4 (26px) — usada en títulos
#define LOAD_FONT6   // Fuente 6 (48px números grandes)
#define LOAD_FONT7   // Fuente 7 (7-seg 48px)
#define LOAD_FONT8   // Fuente 8 (75px números)
#define LOAD_GFXFF   // FreeFonts de Adafruit_GFX
#define SMOOTH_FONT  // Fuentes anti-alias desde SPIFFS/SD

// ── Frecuencias SPI ─────────────────────────────────────────
// CRÍTICO: 55 MHz para pantalla, 2.5 MHz para táctil
// Valores más altos causan artefactos visuales
#define SPI_FREQUENCY        55000000
#define SPI_READ_FREQUENCY   20000000
#define SPI_TOUCH_FREQUENCY   2500000
