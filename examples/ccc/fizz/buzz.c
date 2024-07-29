#include <stdio.h>

int main(void) {
    for (int i = 1;; ++i) {
        if (i % 15 == 0) {
            puts("fizz buzz!");
        } else if (i % 3 == 0) {
            puts("fizz...");
        } else if (i % 5 == 0) {
            puts("buzz?");
        } else {
            printf("%d\n", i);
        }
    }
}
