
#ifndef FIX_POINTED_REAL
#define FIX_POINTED_REAL

#define FRACTIONAL_COUNT 14
#define INTERGER_COUNT 17
#define FRACTION (1 << FRACTIONAL_COUNT)

typedef int32_t fpreal_t;


static inline fpreal_t itofp(int32_t n) {
    return n * FRACTION;
}
static inline fpreal_t fptoiz(fpreal_t x) {
    return x / FRACTION;
}
static inline fpreal_t fptoin(fpreal_t x) {
    if(x >= 0) {
        return (x + FRACTION / 2) / FRACTION;
    }
    else {
        return (x - FRACTION / 2) / FRACTION;
    }
}
static inline fpreal_t add(fpreal_t x, fpreal_t y) {
    return x + y;
}
static inline fpreal_t sub(fpreal_t x,fpreal_t y) {
    return x - y;
}
static inline fpreal_t addi(fpreal_t x, int32_t n) {
    return add(x, itofp(n));
}
static inline fpreal_t subi(fpreal_t x, int32_t n) {
    return sub(x, itofp(n));
}
static inline fpreal_t mul(fpreal_t x, fpreal_t y) {
    return ((int64_t) x) * y / FRACTION;
}
static inline fpreal_t muli(fpreal_t x, int32_t n) {
    return x * n;
}
static inline fpreal_t div(fpreal_t x, fpreal_t y) {
    return ((int64_t) x) * FRACTION / y;
}
static inline fpreal_t divi(fpreal_t x, int32_t n) {
    return x / n;
}

#endif