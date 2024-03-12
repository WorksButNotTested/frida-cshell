#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp)
{
  int fd = open("/dev/null", O_RDWR);
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  while (true)
  {
    usleep(500);
  }
}
