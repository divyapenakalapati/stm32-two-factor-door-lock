#include "main.h"
#include "lock_app.h"
#include "totp.h"
#include "ssd1306.h"
#include "ssd1306_fonts.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

extern I2C_HandleTypeDef  hi2c1;
extern UART_HandleTypeDef huart2;
extern ADC_HandleTypeDef  hadc1;

//pin configurations
#define DHT_PORT   GPIOA
#define DHT_PIN    GPIO_PIN_9
#define LOCK_PORT  GPIOA
#define LOCK_PIN   GPIO_PIN_5
#define BTN_PORT   GPIOC
#define BTN_PIN    GPIO_PIN_13

#define MAX_FAILS        3
#define OTP_TIMEOUT_MS   45000u
#define UNLOCK_SECS      5
#define TAMPER_DELTA     1000      // ADC counts (0..4095) change that counts as tamper
#define MIN_VALID_UNIX   1700000000UL

//internal flash layout (STM32F401RE, 512 KB)
//Sector 6 (0x08040000, 128 KB) : configuration (PIN hash, OTP secret)
//Sector 7 (0x08060000, 128 KB) : event log, 8 bytes per entry
//Program code lives at the start of flash, far away from these sectors.           */
#define CFG_ADDR    0x08040000UL
#define CFG_SECTOR  FLASH_SECTOR_6
#define LOG_BASE    0x08060000UL
#define LOG_SIZE    0x00020000UL
#define LOG_SECTOR  FLASH_SECTOR_7
#define CFG_MAGIC   0x4C4F434BUL    //lock

typedef struct {
    uint32_t magic;
    uint8_t  secret[20];
    uint8_t  slen;
    uint8_t  salt[4];
    uint8_t  pin_hash[20];
} cfg_t;

typedef struct {                   //8 bytes per log entry
    uint32_t ts;
    uint8_t  ev;
    int8_t   temp;
    uint8_t  hum;
    uint8_t  light;                //ADC >> 4
} log_t;

enum { EV_BOOT = 1, EV_PIN_FAIL, EV_PIN_OK, EV_OTP_FAIL, EV_UNLOCK, EV_LOCKOUT, EV_TAMPER, EV_SETUP };
static const char *EVN[] = {"?", "BOOT", "PIN_FAIL", "PIN_OK", "OTP_FAIL", "UNLOCK", "LOCKOUT", "TAMPER", "SETUP"};

//state
static cfg_t     cfg;
static uint32_t  log_next;
static uint32_t  unix_base, tick_base;
static uint64_t  last_step;
static int       temp_c = 0, hum_pc = 0, dht_ok = 0;
static uint16_t  light_raw, light_base;
static int       fails = 0, lock_level = 0;
static volatile int locked = 1, idle = 0, tamper_flag = 0;
static volatile int armed = 0;     //tamper detection active only after boot finishes
static uint32_t  t_adc, t_env, t_tamper;
static uint32_t  rng_state = 2463534242u;

//small helpers
static void say(const char *fmt, ...)
{
    char b[160]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    if (n > 0) HAL_UART_Transmit(&huart2, (uint8_t *)b, (uint16_t)n, 200);
}

static uint32_t now(void) { return unix_base + (HAL_GetTick() - tick_base) / 1000u; }

static void dwt_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
static inline uint32_t us_now(void) { return DWT->CYCCNT / (SystemCoreClock / 1000000u); }
static void delay_us(uint32_t us) { uint32_t s = us_now(); while (us_now() - s < us) {} }

static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 17; rng_state ^= rng_state << 5;
    return rng_state;
}
static void rnd_seed(void)
{
    rng_state ^= DWT->CYCCNT ^ (HAL_GetTick() * 2654435761u) ^ ((uint32_t)light_raw << 16);
    if (!rng_state) rng_state = 1;
    for (int i = 0; i < 16; i++) rnd();
}

//ADC (LDR)
static uint16_t adc_read(void)
{
    HAL_ADC_Start(&hadc1);
    if (HAL_ADC_PollForConversion(&hadc1, 5) != HAL_OK) return light_raw;
    return (uint16_t)HAL_ADC_GetValue(&hadc1);
}
static void light_calibrate(void)
{
    uint32_t s = 0;
    for (int i = 0; i < 16; i++) { s += adc_read(); HAL_Delay(10); }
    light_base = (uint16_t)(s / 16); light_raw = light_base;
}

//OLED
static void i2c_recover(void)            //frees a stuck I2C bus (SCL=PB8, SDA=PB9)
{
    GPIO_InitTypeDef g = {0};
    HAL_I2C_DeInit(&hi2c1);
    g.Pin = GPIO_PIN_8 | GPIO_PIN_9;
    g.Mode = GPIO_MODE_OUTPUT_OD; g.Pull = GPIO_PULLUP; g.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOB, &g);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_8 | GPIO_PIN_9, GPIO_PIN_SET);
    delay_us(50);
    for (int i = 0; i < 9; i++) {
        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_8, GPIO_PIN_RESET); delay_us(10);
        HAL_GPIO_WritePin(GPIOB, GPIO_PIN_8, GPIO_PIN_SET);   delay_us(10);
    }
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_9, GPIO_PIN_RESET); delay_us(10);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_8, GPIO_PIN_SET);   delay_us(10);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_9, GPIO_PIN_SET);   delay_us(10);
    HAL_I2C_Init(&hi2c1);
}
static void oled_check(void)
{
    if (HAL_I2C_IsDeviceReady(&hi2c1, SSD1306_I2C_ADDR, 2, 20) != HAL_OK) {
        i2c_recover();
        ssd1306_Init();
    }
}
static void oled(const char *l1, const char *l2, const char *l3, const char *l4)
{
    const char *L[4] = {l1, l2, l3, l4};
    oled_check();
    ssd1306_Fill(Black);
    for (int i = 0; i < 4; i++) {
        if (!L[i]) continue;
        ssd1306_SetCursor(2, (uint8_t)(i * 16));
        ssd1306_WriteString((char *)L[i], Font_7x10, White);
    }
    ssd1306_UpdateScreen();
}
static void oledf(const char *l1, const char *fmt2, int v2, const char *l3, const char *l4)
{
    char b[24]; snprintf(b, sizeof b, fmt2, v2); oled(l1, b, l3, l4);
}

//internal flash driver
static void fl_read(uint32_t a, void *d, uint32_t n) { memcpy(d, (const void *)a, n); }

static int fl_erase(uint32_t sector)
{
    FLASH_EraseInitTypeDef e = {0};
    uint32_t err = 0;
    e.TypeErase    = FLASH_TYPEERASE_SECTORS;
    e.Sector       = sector;
    e.NbSectors    = 1;
    e.VoltageRange = FLASH_VOLTAGE_RANGE_3;      //2.7 - 3.6 V, 32-bit programming
    HAL_FLASH_Unlock();
    HAL_StatusTypeDef r = HAL_FLASHEx_Erase(&e, &err);
    HAL_FLASH_Lock();
    return r == HAL_OK;
}

static int fl_write(uint32_t a, const void *d, uint32_t n)   //a must be 4-byte aligned
{
    const uint8_t *p = d; int ok = 1;
    HAL_FLASH_Unlock();
    for (uint32_t i = 0; i < n; i += 4) {
        uint32_t w = 0xFFFFFFFFu, k = (n - i > 4) ? 4 : (n - i);
        memcpy(&w, p + i, k);
        if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD, a + i, w) != HAL_OK) { ok = 0; break; }
    }
    HAL_FLASH_Lock();
    return ok;
}

//DHT11
static void dht_dir(int out)
{
    GPIO_InitTypeDef g = {0};
    g.Pin = DHT_PIN; g.Pull = GPIO_NOPULL; g.Speed = GPIO_SPEED_FREQ_HIGH;
    g.Mode = out ? GPIO_MODE_OUTPUT_PP : GPIO_MODE_INPUT;
    HAL_GPIO_Init(DHT_PORT, &g);
}
static int dht_wait(int level, uint32_t to_us)
{
    uint32_t s = us_now();
    while ((HAL_GPIO_ReadPin(DHT_PORT, DHT_PIN) == GPIO_PIN_SET) != (level != 0))
        if (us_now() - s > to_us) return 0;
    return 1;
}
static int dht11_read(int *t, int *h)
{
    uint8_t d[5] = {0};
    dht_dir(1); HAL_GPIO_WritePin(DHT_PORT, DHT_PIN, GPIO_PIN_RESET); HAL_Delay(20);
    __disable_irq();
    HAL_GPIO_WritePin(DHT_PORT, DHT_PIN, GPIO_PIN_SET); delay_us(30); dht_dir(0);
    int ok = dht_wait(0, 100) && dht_wait(1, 120) && dht_wait(0, 120);
    for (int i = 0; ok && i < 40; i++) {
        if (!dht_wait(1, 100)) { ok = 0; break; }
        uint32_t s = us_now();
        if (!dht_wait(0, 120)) { ok = 0; break; }
        d[i / 8] <<= 1;
        if (us_now() - s > 40) d[i / 8] |= 1;
    }
    __enable_irq();
    dht_dir(1); HAL_GPIO_WritePin(DHT_PORT, DHT_PIN, GPIO_PIN_SET);
    if (!ok || (uint8_t)(d[0] + d[1] + d[2] + d[3]) != d[4]) return -1;
    *h = d[0]; *t = d[2];
    return 0;
}

//event log
static void log_scan(void)
{
    log_t e; uint32_t a = LOG_BASE;
    for (; a < LOG_BASE + LOG_SIZE; a += sizeof e) {
        fl_read(a, &e, sizeof e);
        if (e.ts == 0xFFFFFFFFu) break;
    }
    log_next = a;
}
static void log_add(uint8_t ev)
{
    if (log_next >= LOG_BASE + LOG_SIZE) { fl_erase(LOG_SECTOR); log_next = LOG_BASE; }
    log_t e = { now(), ev, (int8_t)temp_c, (uint8_t)hum_pc, (uint8_t)(light_raw >> 4) };
    fl_write(log_next, &e, sizeof e);
    log_next += sizeof e;
}
static void log_dump(void)
{
    log_t e;
    say("\r\n--- EVENT LOG ---\r\n");
    for (uint32_t a = LOG_BASE; a < log_next; a += sizeof e) {
        fl_read(a, &e, sizeof e);
        say("%lu  %-9s T=%dC H=%u%% L=%u\r\n", (unsigned long)e.ts,
            EVN[e.ev <= EV_SETUP ? e.ev : 0], e.temp, e.hum, e.light);
    }
    say("--- %lu entries ---\r\n", (unsigned long)((log_next - LOG_BASE) / sizeof e));
}

//background tasks (called while waiting for input)
static void draw_idle(void)
{
    char a[24], b[24];
    if (tamper_flag) {
        oled("!! TAMPER !!", "Press the USER", "button to reset", "the alarm");
        return;
    }
    if (dht_ok) snprintf(a, sizeof a, "T:%dC  H:%d%%", temp_c, hum_pc); else snprintf(a, sizeof a, "T:--  H:--");
    snprintf(b, sizeof b, "Light:%u", light_raw);
    oled("DOOR LOCKED", a, b, "Enter PIN on PC");
}
static void background(void)
{
    uint32_t t = HAL_GetTick();
    if (t - t_adc > 200) {
        t_adc = t; light_raw = adc_read();
        int diff = (int)light_raw - (int)light_base; if (diff < 0) diff = -diff;
        if (armed && locked && !tamper_flag && diff > TAMPER_DELTA) {
            tamper_flag = 1;
            log_add(EV_TAMPER);
        }
    }
    if (idle && !tamper_flag && t - t_env > 2000) {
        t_env = t;
        int tt, hh;
        if (dht11_read(&tt, &hh) == 0) { temp_c = tt; hum_pc = hh; dht_ok = 1; }
        draw_idle();
    }
}

//UART line input
//mask: 0 = echo all, 1 = mask everything, 2 = mask digits only (PIN prompt also accepts commands)
static int getline_(char *b, int max, uint32_t to_ms, int mask)
{
    int n = 0; uint8_t c; uint32_t t0 = HAL_GetTick();
    for (;;) {
        background();
        if (tamper_flag) return -2;
        if (to_ms && HAL_GetTick() - t0 > to_ms) return -1;
        if (HAL_UART_Receive(&huart2, &c, 1, 5) != HAL_OK) {
            __HAL_UART_CLEAR_OREFLAG(&huart2);
            continue;
        }
        if (c == '\r') { b[n] = 0; say("\r\n"); return n; }
        if (c == '\n') continue;
        if ((c == 0x08 || c == 0x7F)) { if (n) { n--; say("\b \b"); } continue; }
        if (c >= 32 && c < 127 && n < max - 1) {
            b[n++] = (char)c;
            char e = (mask == 1 || (mask == 2 && isdigit(c))) ? '*' : (char)c;
            HAL_UART_Transmit(&huart2, (uint8_t *)&e, 1, 20);
        }
    }
}
static void drain_uart(void)
{
    uint8_t c; __HAL_UART_CLEAR_OREFLAG(&huart2);
    while (HAL_UART_Receive(&huart2, &c, 1, 2) == HAL_OK) {}
    __HAL_UART_CLEAR_OREFLAG(&huart2);
}

//PIN / OTP
static void pin_hash(const uint8_t salt[4], const char *pin, uint8_t out[20])
{
    uint8_t buf[4 + 16]; size_t l = strlen(pin); if (l > 16) l = 16;
    memcpy(buf, salt, 4); memcpy(buf + 4, pin, l);
    sha1_buf(buf, 4 + l, out);
}
static int pin_ok(const char *pin)
{
    uint8_t h[20]; pin_hash(cfg.salt, pin, h);
    return ct_equal(h, cfg.pin_hash, 20);
}
static int all_digits(const char *s, int n) { for (int i = 0; i < n; i++) if (!isdigit((unsigned char)s[i])) return 0; return n > 0; }

static int otp_ok(const char *s)
{
    if (strlen(s) != 6 || !all_digits(s, 6)) return 0;
    uint32_t val = (uint32_t)atol(s);
    uint64_t step = now() / 30u;
    int found = 0; uint64_t used = 0;
    for (int d = -1; d <= 1; d++) {                      /* +/-30 s clock drift tolerance */
        uint64_t st = step + d;
        if (hotp_code(cfg.secret, cfg.slen, st) == val) { found = 1; used = st; }
    }
    if (!found) return 0;
    if (used <= last_step) return 0;                     /* replay protection: each code works once */
    last_step = used;
    return 1;
}

//setup / provisioning
static void setup_mode(void)
{
    char b[64]; int n;
    oled("SETUP MODE", "Use PC terminal", NULL, NULL);
    say("\r\n=== SETUP MODE ===\r\n");
    for (;;) {
        say("Choose PIN (4-8 digits): ");
        n = getline_(b, sizeof b, 0, 1);
        if (n >= 4 && n <= 8 && all_digits(b, n)) break;
        say("Invalid PIN.\r\n");
    }
    rnd_seed();
    uint32_t r = rnd(); memcpy(cfg.salt, &r, 4);
    pin_hash(cfg.salt, b, cfg.pin_hash);

    for (;;) {
        say("Base32 secret (16-32 chars) or just ENTER to auto-generate: ");
        n = getline_(b, sizeof b, 0, 0);
        if (n == 0) {
            static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            for (int i = 0; i < 16; i++) b[i] = A[rnd() & 31];
            b[16] = 0;
        }
        int l = base32_decode(b, cfg.secret, sizeof cfg.secret);
        if (l >= 10) { cfg.slen = (uint8_t)l; break; }
        say("Invalid secret.\r\n");
    }
    say("\r\nADD THIS TO YOUR AUTHENTICATOR APP (type: time-based, SHA1, 6 digits, 30 s):\r\n");
    say("   SECRET KEY:  %s\r\n\r\n", b);
    cfg.magic = CFG_MAGIC;
    say("Saving (flash erase takes a second or two)...\r\n");
    fl_erase(CFG_SECTOR); fl_write(CFG_ADDR, &cfg, sizeof cfg);
    fl_erase(LOG_SECTOR); log_next = LOG_BASE;
    say("Saved to internal flash.\r\n");
}

static void set_time(void)
{
    char b[32];
    oled("SET CLOCK", "Type T<unix> on", "the PC terminal", NULL);
    for (;;) {
        say("\r\nUTC time needed. Type  T<unix-seconds>  (e.g. T1760000000): ");
        int n = getline_(b, sizeof b, 0, 0);
        if (n > 1 && (b[0] == 'T' || b[0] == 't')) {
            unsigned long u = strtoul(b + 1, NULL, 10);
            if (u > MIN_VALID_UNIX) { unix_base = u; tick_base = HAL_GetTick(); say("Clock set.\r\n"); return; }
        }
        say("Rejected.\r\n");
    }
}

//door actions
static void lockout(void)
{
    uint32_t secs = 30u << (lock_level > 4 ? 4 : lock_level);
    lock_level++;
    log_add(EV_LOCKOUT);
    say("\r\nToo many failures. Locked out for %lu s.\r\n", (unsigned long)secs);
    for (uint32_t s = secs; s > 0; s--) {
        oledf("LOCKED OUT", "Wait %d s", (int)s, NULL, NULL);
        for (int i = 0; i < 10; i++) { background(); HAL_Delay(100); }
    }
    drain_uart(); fails = 0;
}

static void unlock_door(void)
{
    locked = 0; tamper_flag = 0;
    HAL_GPIO_WritePin(LOCK_PORT, LOCK_PIN, GPIO_PIN_SET);
    log_add(EV_UNLOCK);
    say("*** ACCESS GRANTED - door unlocked ***\r\n");
    for (int s = UNLOCK_SECS; s > 0; s--) {
        oledf("UNLOCKED", "Relock in %ds", s, "Welcome!", NULL);
        HAL_Delay(1000);
    }
    HAL_GPIO_WritePin(LOCK_PORT, LOCK_PIN, GPIO_PIN_RESET);
    light_calibrate();                    //door was open: re-learn the light baseline
    locked = 1;
    say("Door locked again.\r\n");
}

static void tamper_alarm(void)
{
    idle = 0;
    say("\r\n\r\n!!! TAMPER ALERT !!!  Input disabled.\r\n");
    say("Press the blue USER button on the board to reset the alarm.\r\n");
    oled("!! TAMPER !!", "Press the USER", "button to reset", "the alarm");

    while (HAL_GPIO_ReadPin(BTN_PORT, BTN_PIN) != GPIO_PIN_RESET) {   //wait for press
        background();
        drain_uart();                                                 //keyboard ignored
        HAL_Delay(50);
    }
    HAL_Delay(50);
    while (HAL_GPIO_ReadPin(BTN_PORT, BTN_PIN) == GPIO_PIN_RESET) HAL_Delay(10);   //release

    light_calibrate();
    tamper_flag = 0;
    drain_uart();
    say("Alarm cleared.\r\n");
}

//public API
void App_Init(void)
{
    dwt_init();
    HAL_GPIO_WritePin(LOCK_PORT, LOCK_PIN, GPIO_PIN_RESET);
    i2c_recover();
    ssd1306_Init();
    oled("2FA Door Lock", "Booting...", NULL, NULL);
    say("\r\n\r\n== Two-Factor Smart Door Lock ==\r\n");

    light_calibrate(); rnd_seed();
    fl_read(CFG_ADDR, &cfg, sizeof cfg);
    int btn = (HAL_GPIO_ReadPin(BTN_PORT, BTN_PIN) == GPIO_PIN_RESET);
    if (cfg.magic != CFG_MAGIC || btn) { set_time(); setup_mode(); }
    else set_time();
    log_scan();
    log_add(EV_BOOT);
    drain_uart();
    armed = 1;
}

void App_Loop(void)
{
    char b[32];
    if (tamper_flag) { tamper_alarm(); return; }
    if (fails >= MAX_FAILS) lockout();

    locked = 1; idle = 1; t_env = 0; draw_idle();
    say("\r\nPIN> ");
    int n = getline_(b, sizeof b, 0, 2);
    idle = 0;
    if (n == -2) { tamper_alarm(); return; }
    if (n <= 0) return;

    if (b[0] == 'T' || b[0] == 't') {                       //admin: re-sync clock
        unsigned long u = strtoul(b + 1, NULL, 10);
        if (u > MIN_VALID_UNIX) { unix_base = u; tick_base = HAL_GetTick(); say("Clock set.\r\n"); }
        return;
    }
    if (!strcasecmp(b, "LOG")) { log_dump(); return; }

    //FACTOR 1 : PIN
    if (!pin_ok(b)) {
        fails++; log_add(EV_PIN_FAIL);
        say("Wrong PIN (%d/%d)\r\n", fails, MAX_FAILS);
        oled("WRONG PIN", NULL, NULL, NULL); HAL_Delay(1200);
        return;
    }
    log_add(EV_PIN_OK);
    say("PIN OK. Open your authenticator app.\r\n");
    oled("PIN OK", "Enter OTP now", "(6 digits)", NULL);

    //FACTOR 2 : TOTP
    say("OTP> ");
    n = getline_(b, sizeof b, OTP_TIMEOUT_MS, 1);
    if (n == -2) { tamper_alarm(); return; }
    if (n < 0) { say("\r\nOTP timeout.\r\n"); return; }
    if (!otp_ok(b)) {
        fails++; log_add(EV_OTP_FAIL);
        say("Wrong/expired/reused OTP (%d/%d)\r\n", fails, MAX_FAILS);
        oled("WRONG OTP", NULL, NULL, NULL); HAL_Delay(1200);
        return;
    }
    fails = 0; lock_level = 0;
    unlock_door();
}
