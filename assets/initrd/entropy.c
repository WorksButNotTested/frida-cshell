#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/random.h>
#include <sys/ioctl.h>

#define ENTROPY_SIZE 4096
#define ENTROPY_COUNT 256

typedef struct
{
    struct rand_pool_info pool_info;
    uint8_t data[ENTROPY_SIZE];
} entropy_t;

int main(int argc, char **argv)
{
    entropy_t entropy = {
        .pool_info = {
            .buf_size = ENTROPY_SIZE,
            .entropy_count = ENTROPY_SIZE * 8,
        },
        .data = {0}};
    int fd = open("/dev/random", O_RDWR);
    if (fd < 0)
    {
        perror("failed to open /dev/random");
        return EXIT_FAILURE;
    }

    for (uint32_t i = 0; i < ENTROPY_COUNT; i++)
    {
        if (ioctl(fd, RNDADDENTROPY, &entropy) != 0)
        {
            perror("failed to write entropy");
            return EXIT_FAILURE;
        }
    }

    close(fd);

    return EXIT_SUCCESS;
}
