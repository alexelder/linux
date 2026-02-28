#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/syscall.h>

#define SYS_read_data	471

#define BUF_COUNT	20

struct data {
	long counter;
	long data;
};

int main()
{
	struct data kernel_data[BUF_COUNT] = { };
	struct data *data = &kernel_data[0];
	unsigned int count;
	long ret;

	printf("errno before syscall: %d\n", errno);

	ret = syscall(SYS_read_data, data, sizeof(kernel_data));

	printf("errno after syscall: %d\n", errno);
	printf("syscall return value = %ld\n", ret);

	if (ret < 0)
		return ret;

	count = ret / sizeof(*data);
	printf("%u/%u item%s received\n", count, BUF_COUNT,
	       count == 1 ? "" : "s");
	while (count--) {
		printf("counter: %ld\n", data->counter);
		printf("   data: %ld\n", data->data);
		printf("----------\n");
		data++;
	}

	return 0;
}
