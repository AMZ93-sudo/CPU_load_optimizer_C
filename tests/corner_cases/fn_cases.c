/* FALSE-NEGATIVE bait: ALL of these SHOULD be flagged */
#include <stdint.h>
#include <string.h>
#include <math.h>

/* FN1: hex power-of-2 divisor — C02 should fire */
uint32_t f1(uint32_t x) { uint32_t y; y = x / 0x10; return y; }

/* FN2: MISRA-style suffixed divisor — C02 should fire */
uint32_t f2(uint32_t x) { uint32_t y; y = x / 4U; return y; }

/* FN3: compound assignment div by pow2 — C02 should fire */
uint32_t f3(uint32_t x) { x /= 8; x %= 16; x *= 4; return x; }

/* FN4: strlen in WHILE condition — H03/H01 should fire */
uint32_t f4(const char *s)
{
    uint32_t i = 0;
    uint32_t acc = 0;
    while (i < strlen(s)) {
        acc += (uint32_t)s[i];
        i++;
    }
    return acc;
}

/* FN5: braceless loop with sqrtf — C05 should fire */
float f5(float v)
{
    float acc = 0.0f;
    int i;
    for (i = 0; i < 100; i++)
        acc += sqrtf(v + (float)i);
    return acc;
}

/* FN6: float equality on vars declared float elsewhere — H06 should fire */
static float ratio;
int f6(void)
{
    if (ratio == 1.0f) { return 1; }
    return 0;
}

/* FN7: MISRA 0u loop init, index unused — H09 should fire */
extern void tick(void);
void f7(void)
{
    uint32_t i;
    for (i = 0u; i < 64u; i++) {
        tick();
    }
}

/* FN8: read-only static table, never written — M12 SHOULD fire */
static uint16_t lut[8] = {1, 2, 4, 8, 16, 32, 64, 128};
uint16_t f8(uint8_t idx) { return lut[idx & 7u]; }
