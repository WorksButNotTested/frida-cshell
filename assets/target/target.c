#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned int uint;

__attribute__((noinline)) void my_memcpy(void *dest, const void *src, size_t n)
{
  memcpy(dest, src, n);
}

const char test[] = "TEST_STRING";

void my_h(uint i)
{
  printf("chain: %u\n", i);
}

void my_g(uint i)
{
  if ((i % 2) == 0)
  {
    my_h(1);
  }
  else
  {
    my_h(2);
  }
}

void my_f(uint i)
{
  if ((i % 2) == 0)
  {
    my_g(1);
  }
  else
  {
    my_g(2);
  }
}

void my_e(uint i)
{
  if ((i % 2) == 0)
  {
    my_f(1);
  }
  else
  {
    my_f(2);
  }
}

void my_d(uint i)
{
  if ((i % 2) == 0)
  {
    my_e(1);
  }
  else
  {
    my_e(2);
  }
}

void my_c(uint i)
{
  if ((i % 2) == 0)
  {
    my_d(1);
  }
  else
  {
    my_d(2);
  }
}

void my_b(uint i)
{
  if ((i % 2) == 0)
  {
    my_c(1);
  }
  else
  {
    my_c(2);
  }
}

void my_a(uint i)
{
  for (uint n = 0; n < 3; n++)
  {
    if ((i % 2) == 0)
    {
      my_b(1);
    }
    else
    {
      my_b(2);
    }
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd = open("/dev/null", O_RDWR);
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  while (true)
  {

    my_a(rand());

    char *buf = malloc(sizeof(test));

    if (buf == NULL)
      break;

    my_memcpy(buf, test, sizeof(test));

    puts(buf);

    free(buf);
    usleep(500000);
  }
}
