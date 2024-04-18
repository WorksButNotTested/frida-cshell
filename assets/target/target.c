#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) void my_memcpy(void *dest, const void *src, size_t n)
{
  memcpy(dest, src, n);
}

const char test[] = "TEST_STRING";

int main(int argc, char **argv, char **envp)
{
  int fd = open("/dev/null", O_RDWR);
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  while (true)
  {
    char *buf = malloc(sizeof(test));

    if (buf == NULL)
      break;

    my_memcpy(buf, test, sizeof(test));

    puts(buf);

    free(buf);
    usleep(500000);
  }
}
