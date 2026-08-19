/* FALSE-POSITIVE bait: none of these should be flagged */
#include <stdint.h>
#include <stdio.h>

/* FP1: unsigned bit-field must NOT trigger M07 (signed bit-field) */
struct Flags {
    unsigned int ready : 1;
    unsigned int mode  : 3;
};

/* FP2: main() must NOT trigger M02 (add static) */
int main(void)
{
    return 0;
}

/* FP3: float division by 2.0f must NOT trigger C02 (int div by pow2) */
static float scale_it(int32_t raw)
{
    float r;
    r = raw / 2.0f;
    return r;
}

/* FP4: patterns inside string literals must NOT fire C02/C09/L01/C06 */
static void log_stuff(int speed)
{
    puts("speed/2 in path/to/file with 500 ms delay");
    printf("usr/lib/gcc %d\n", speed);
}

/* FP5: switch WITH default (inner brace block) must NOT fire M06 */
static void handle(int x)
{
    switch (x) {
        case 1: { int t = 0; (void)t; } break;
        default: break;
    }
}

/* FP6: string containing own name must NOT trigger H02 recursion */
static void report_status(void)
{
    puts("report_status( called )");
}

/* FP7: cheap-call && another CALL — M10 reorder advice is dubious */
extern int a_check(int v);
extern int b_check(int v);
static int both(int v)
{
    if (a_check(v) && b_check(v)) { return 1; }
    return 0;
}

/* FP8: M12 validator — table IS written at runtime, const would be wrong */
static uint8_t rw_table[4] = {1, 2, 3, 4};
static void mutate(uint8_t v)
{
    rw_table[0] = v;
}
