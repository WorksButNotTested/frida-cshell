#include <stdio.h>

void __attribute__((constructor)) my_constructor()
{
    puts("Shared object loaded\n");
}

void __attribute__((destructor)) my_destructor()
{
    puts("Shared object unloaded\n");
}