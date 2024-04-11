#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp)
{
  int fd = open("/dev/null", O_RDWR);
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  static const char test[] = "TEST_STRING";

  while (true)
  {
    char *buf = malloc(sizeof(test));

    if (buf == NULL)
      break;

    memcpy(buf, test, sizeof(test));

    puts(buf);

    free(buf);
    usleep(1000);
  }
}
