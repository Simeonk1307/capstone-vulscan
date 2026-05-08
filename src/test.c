#include <stdio.h>
#include <stdint.h>

uint64_t factorial(unsigned int n) {
    uint64_t result = 1;

    for (unsigned int i = 2; i <= n; ++i)
        result *= i;

    return result;
}

int main() {
    unsigned int n = 1000;
    printf("%u! = %llu\n", n, factorial(n));
    return 0;
}
