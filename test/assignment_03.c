#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SYS_read_data 471
#define BUFSIZE 20

struct data {
    long counter;
    long data;
};

int main() {
    struct data kernel_data[BUFSIZE] = {};
    printf("errno before syscall: %d\n", errno);
    long ret_val = syscall(SYS_read_data, &kernel_data, BUFSIZE * sizeof(struct data));
    printf("errno after syscall: %d\n", errno);
    printf("syscall return value = %ld\n", ret_val);

    if (ret_val > 0) {
        unsigned items_filled = ret_val / sizeof(struct data);
        printf("%u items received\n", items_filled);

        for (int i = 0; i < items_filled; i++) {
            printf("Counter Value = %ld\n", kernel_data[i].counter);
            printf("Data Value = %ld\n", kernel_data[i].data);
            printf("----------\n");
        }
    }
    return 0;
}
