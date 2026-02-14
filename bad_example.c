/*
 * bad_cpu_load_demo.c
 *
 * Intentionally bad CPU-load practices for embedded C.
 * This file is a teaching aid: it shows patterns that often waste cycles,
 * blow up ISR time, cause jitter, or defeat compiler optimizations.
 *
 * Notes:
 * - This code is deliberately NOT hardware-specific and uses "fake" peripherals.
 * - You can compile it on a PC to inspect assembly (-S) and see how patterns expand.
 * - Many of these are "bad" only in hot paths (ISRs, tight loops, high-rate tasks).
 */

#include <stdint.h>
#include <stdbool.h>

/* --------------------------- Fake HW / HAL --------------------------- */

volatile uint32_t HW_TICK = 0;                 /* pretend systick */
volatile uint32_t ADC_REG = 1234;              /* pretend ADC register */
volatile uint32_t UART_TX_READY = 1;           /* pretend UART status */
volatile uint8_t  UART_TX_REG = 0;             /* pretend UART TX register */
volatile uint32_t GPIO_PORT = 0;               /* pretend GPIO port */

static inline uint32_t read_adc(void) { return ADC_REG; }
static inline bool uart_ready(void) { return (UART_TX_READY != 0); }
static inline void uart_send_byte(uint8_t b) { UART_TX_REG = b; }
static inline void gpio_toggle(void) { GPIO_PORT ^= 1u; }

/* ------------------------ Global state (also "bad") ------------------------ */


volatile uint32_t g_sample_count = 0;
volatile uint32_t g_accum = 0;


bool g_flag = false;

/* --------------------------- Bad helpers --------------------------- */


static uint32_t expensive_mod_u64(uint64_t x)
{

    return (uint32_t)(x % 1000003ull);
}


__attribute__((noinline))
static uint32_t slow_function_call(uint32_t x)
{

    x = (x / 37u) + (x % 37u);


    if (x & 1u) {
        x ^= 0xA5A5A5A5u;
    } else {
        x += 0x1234567u;
    }
    return x;
}


static void busy_delay(volatile uint32_t cycles)
{

    while (cycles--) {
        __asm__ volatile ("nop");
    }
}


static void uart_print_hex_polling(uint32_t v)
{

    for (int i = 7; i >= 0; --i) {
        uint8_t nibble = (uint8_t)((v >> (i * 4)) & 0xFu);
        uint8_t ch = (nibble < 10) ? (uint8_t)('0' + nibble) : (uint8_t)('A' + nibble - 10);


        while (!uart_ready()) { /* spin */ }
        uart_send_byte(ch);
    }

    while (!uart_ready()) { /* spin */ }
    uart_send_byte('\n');
}

/* --------------------------- Intentionally bad ISR --------------------------- */


void ADC_IRQHandler(void)
{
    uint32_t raw = read_adc();
    g_sample_count++;


    uint64_t wide = ((uint64_t)raw << 32) | (uint64_t)g_sample_count;
    uint32_t m = expensive_mod_u64(wide);     /* modulo with large prime-ish divisor */


    uint32_t q = (m / 37u);
    uint32_t r = (m % 37u);


    if ((raw ^ m) & 0x100u) {
        g_accum += q;
    } else {
        g_accum += r;
    }


    g_accum ^= slow_function_call(g_accum);


    uart_print_hex_polling(g_accum);


    busy_delay(2000);


    gpio_toggle();
    gpio_toggle();
}

/* --------------------------- Bad main loop --------------------------- */

static uint32_t pretend_workload(uint32_t x)
{

    volatile uint32_t *tick = &HW_TICK;


    uint32_t start = *tick;
    while ((*tick - start) < 100u) {



        x = (x / (x | 1u)) + (x % (x | 1u));


        /* (Kept simple to compile everywhere; still illustrates the pattern.) */
        float f = (float)x * 1.0001234f;
        x = (uint32_t)f;


        x ^= slow_function_call(x);


        if (x & 0x4000u) {
            x += 3u;
        } else {
            x -= 1u;
        }
    }
    return x;
}

int main(void)
{
    uint32_t x = 0xDEADBEEFu;

    for (;;) {

        while (!g_flag) {

            x = pretend_workload(x);
        }


        g_flag = false;


        busy_delay(50000);


        x = (x * 1664525u + 1013904223u);          /* LCG step */
        x = (x / 37u) + (x % 37u);                 /* pointless div/mod */


        uart_print_hex_polling(x);

        gpio_toggle();
    }

    /* never reached */
    /* return 0; */
}
