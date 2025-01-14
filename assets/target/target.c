#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define NUM_THREADS 5
#define PORT 1337
#define BUFFER_SIZE 1024

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

static void *busy_loop(void *arg)
{
  char thread_name[16] = {0};
  int index = *(int *)arg;
  printf("Thread %d started\n", index);

  snprintf(thread_name, sizeof(thread_name), "Child-%d", index);
  pthread_setname_np(pthread_self(), thread_name);

  long limit = (index + 1) * 10000000L;

  while (true)
  {
    for (volatile long i = 0; i < limit; i++)
      ;

    usleep(500000);
  }

  return NULL;
}

static void *network_loop(void *arg)
{
  char thread_name[] = "Network";
  pthread_setname_np(pthread_self(), thread_name);
  int server_fd, client_fd;
  struct sockaddr_in server_addr, client_addr;
  socklen_t addr_len = sizeof(client_addr);
  char buffer[BUFFER_SIZE];
  ssize_t bytes_read;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORT);
  bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  listen(server_fd, 5);

  while (1)
  {
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
    while ((bytes_read = read(client_fd, buffer, sizeof(buffer))) > 0)
    {
      write(client_fd, buffer, bytes_read);
    }
    close(client_fd);
  }

  close(server_fd);
  return NULL;
}

int main(int argc, char **argv, char **envp)
{
  pthread_t threads[NUM_THREADS] = {0};
  pthread_t network_thread = 0;
  int thread_indices[NUM_THREADS] = {0};

  int fd = open("/dev/null", O_RDWR);
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  pthread_setname_np(pthread_self(), "Parent");

  for (int i = 0; i < NUM_THREADS; i++)
  {
    thread_indices[i] = i;
    if (pthread_create(&threads[i], NULL, busy_loop, &thread_indices[i]) != 0)
    {
      perror("Failed to create thread");
      return 1;
    }
  }

  if (pthread_create(&network_thread, NULL, network_loop, NULL) != 0)
  {
    perror("Failed to create network thread");
    return 1;
  }

  while (true)
  {

    my_a(rand());

    char *buf = malloc(sizeof(test));

    if (buf == NULL)
      break;

    my_memcpy(buf, test, sizeof(test));

    puts(buf);

    free(buf);

    for (volatile long i = 0; i < 100000000L; i++)
      ;

    usleep(500000);
  }

  for (int i = 0; i < NUM_THREADS; i++)
  {
    pthread_join(threads[i], NULL);
  }
}
