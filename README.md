# Overview
The C-Shell is a command line interpreter embedded as part of the `frida-inject` tool, it takes inspiration from the VxWorks C-Shell and is intended to allow the user to interactively inspect a running process by issuing commands. By setting `frida-inject` to use raw mode, the tool acts as a dumb byte pump sending and receiving raw key-strokes between the TTY and the C-shell. It is implmented purely in about 4k lines of Typescript (which is embedded as a resource) and converts the user's input into calls into the [FRIDA JS API bindings](https://frida.re/docs/javascript-api/).

# Getting Started
The C-Shell can be started by using the `-s` flag provided to the `frida-inject` tool as follows:
* `frida-inject -f <file> --interactive -s frida-cshell.js`
* `frida-inject -p <pid> --interactive -s frida-cshell.js`

When launched the user will see the welcome banner as shown below:

```
     _.---._                    _          _ _
 .'"".'/|\'.""'.               | |        | | |
:  .' / | \ '.  :      ____ ___| |__   ___| | |
'.'  /  |  \  '.'     /  _ / __| '_ \ / _ \ | |
 `. /   |   \ .'      | (__\__ \ | | | |__/ | |
   `-.__|__.-'        \____|___/_| |_|\___|_|_|
CSHELL running in FRIDA 16.2.2-dev.6 using QJS
Attached to:
        PID: 2047276
        Name: vim.basic
->
```
**Important** Be sure to include the `--interactive` command line option, otherwise the terminal will appear non-responsive.

# Wrapper
Alternatively, included in the release is a wrapper shell script `frida-cshell`:
```
# ./frida-cshell -h
Usage
  ./frida-cshell [OPTION?]

Help Options:
  -h,   show help options

Application Options:
  -f    spawn FILE
  -n    attach to NAME
  -p    attach to PID
  -V    enable verbose mode
```
It assumes that `frida-inject` can be found on the path, otherwise an alternative can be provided using the `FRIDA_INJECT` environment variable. As an example, it can be used as follows:

```
# FRIDA_INJECT=frida-inject-64 ./frida-cshell -f ./target
     _.---._                   _          _ _
 .'"".'/|\'.""'.              | |        | | |
:  .' / | \ '.  :     ____ ___| |__   ___| | |
'.'  /  |  \  '.'    /  _ / __| '_ \ / _ \ | |
 `. /   |   \ .'     | (__\__ \ | | | |__/ | |
   `-.__|__.-'       \____|___/_| |_|\___|_|_|

CSHELL v1.0.6, running in FRIDA 0.0.0 using QJS
Attached to:
        PID:  253520
        Name: target

->
```
# Init Scripts
Commands which should be run on start-up can be provided in a file name `.cshellrc` in the current directory. An example can be found [here](assets/initrd/.cshellrc)

# Development
For documentation on how to develop `frida-cshell`, or provide additional commandlets via script files, see [here](DEVELOPMENT.md)

# Walkthrough
Perhaps the easiest way to understand the C-Shell is by an example, let's walk through a fictional sequence of commands to analyse a program
## #0 Threads
Let's have a look at what threads our process has:
```
->t
2068775: vim             waiting pc: 0x7f14abb1b63d sp: 0x7ffd8ace6940

ret: 0x00000000`00000000 (0)
```
And now check out it's backtrace:
```
->bt 2068775
0
0x5583a9deae0f vim.basic!0x187e0f
0x5583a9deda1c vim.basic!0x18aa1c
0x5583a9f353e4 vim.basic!0x2d23e4
0x5583a9eb0746 vim.basic!0x24d746
0x5583a9d6ef47 vim.basic!0x10bf47
0x5583a9d75817 vim.basic!0x112817
0x5583a9d77d2a vim.basic!0x114d2a
0x5583a9dc422a vim.basic!0x16122a
0x5583a9f27ab7 vim.basic!0x2c4ab7
0x5583a9cb0303 vim.basic!0x4d303
0x7f14aba29d90 libc.so.6!0x29d90
0x7f14aba29e40 libc.so.6!__libc_start_main+0x80
0x5583a9cb1ad5 vim.basic!0x4ead5

ret: 0x00000000`001f9127 (2068775)
```
## #1 Symbols
Lets look-up the address of malloc:
```
->sym malloc
Symbol: malloc found at 0x00007f14`abaa50a0

ret: 0x00007f14`abaa50a0 (139726756139168)
```
Oh, I wonder what's at this random address:
```
->sym 0x00007f14`abaa53e0
Symbol: libc.so.6!free found at 0x00007f14`abaa53e0

ret: 0x00007f14`abaa53e0 (139795156849632)
```

## #2 Code
Let's list some assembly:
```
-> l malloc
  #1: 0x00007f63`d755b0a0: endbr64                                  f3 0f 1e fa
  #2: 0x00007f63`d755b0a4: push r12                                 41 54
  #3: 0x00007f63`d755b0a6: push rbp                                 55
  #4: 0x00007f63`d755b0a7: mov rbp, rdi                             48 89 fd
  #5: 0x00007f63`d755b0aa: push rbx                                 53
  #6: 0x00007f63`d755b0ab: sub rsp, 0x10                            48 83 ec 10
  #7: 0x00007f63`d755b0af: cmp byte ptr [rip + 0x17c432], 0         80 3d 32 c4 17 00 00
  #8: 0x00007f63`d755b0b6: je 0x7f63c678f81a                        0f 84 14 02 00 00
  #9: 0x00007f63`d755b0bc: test rbp, rbp                            48 85 ed
 #10: 0x00007f63`d755b0bf: js 0x7f63c678f81f                        0f 88 19 02 00 00

ret: 0x00007f63`d755b0c5 140066791207109
```
and a bit more...
```
-> l ret
  #1: 0x00007f63`d755b0c5: lea rax, [rbp + 0x17]                    48 8d 45 17
  #2: 0x00007f63`d755b0c9: xor r12d, r12d                           45 31 e4
  #3: 0x00007f63`d755b0cc: cmp rax, 0x1f                            48 83 f8 1f
  #4: 0x00007f63`d755b0d0: ja 0x7f63d4117790                        0f 87 da 00 00 00
  #5: 0x00007f63`d755b0d6: mov rbx, qword ptr [rip + 0x174ccb]      48 8b 1d cb 4c 17 00
  #6: 0x00007f63`d755b0dd: mov rdx, qword ptr fs:[rbx]              64 48 8b 13
  #7: 0x00007f63`d755b0e1: test rdx, rdx                            48 85 d2
  #8: 0x00007f63`d755b0e4: je 0x7f63d4117794                        0f 84 de 00 00 00
  #9: 0x00007f63`d755b0ea: cmp qword ptr [rip + 0x1752d7], r12      4c 39 25 d7 52 17 00
 #10: 0x00007f63`d755b0f1: ja 0x7f63d41177bf                        0f 87 09 01 00 00

ret: 0x00007f63`d755b0f7 140066791207159
```
## #3 Modules & Virtual Memory
Let's find out which module `malloc` is in:
```
->mod malloc
Address: 0x00007f14`abaa50a0 is within module:
0x00007f14`aba00000-0x00007f14`abc28e50    2 MB libc.so.6                      /usr/lib/x86_64-linux-gnu/libc.so.6

ret: 0x00007f14`abaa50a0 (139726756139168)
```
Not suprising, let's look at `libc`'s memory layout...
```
->vm libc.so.6
        0x00007f14`99a00000-0x00007f14`99c1f000 r--    2 MB offset: 0x00000000`00000000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba00000-0x00007f14`aba28000 r--  160 KB offset: 0x00000000`00000000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba28000-0x00007f14`aba29000 rwx    4 KB offset: 0x00000000`00028000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba29000-0x00007f14`aba42000 r-x  100 KB offset: 0x00000000`00029000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba42000-0x00007f14`aba43000 rwx    4 KB offset: 0x00000000`00042000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba43000-0x00007f14`aba45000 r-x    8 KB offset: 0x00000000`00043000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba45000-0x00007f14`aba46000 rwx    4 KB offset: 0x00000000`00045000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`aba46000-0x00007f14`abaea000 r-x  656 KB offset: 0x00000000`00046000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abaea000-0x00007f14`abaeb000 rwx    4 KB offset: 0x00000000`000ea000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abaeb000-0x00007f14`abbbd000 r-x  840 KB offset: 0x00000000`000eb000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abbbd000-0x00007f14`abc15000 r--  352 KB offset: 0x00000000`001bd000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abc15000-0x00007f14`abc16000 ---    4 KB offset: 0x00000000`00215000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abc16000-0x00007f14`abc1a000 r--   16 KB offset: 0x00000000`00215000, name: /usr/lib/x86_64-linux-gnu/libc.so.6
        0x00007f14`abc1a000-0x00007f14`abc1c000 rw-    8 KB offset: 0x00000000`00219000, name: /usr/lib/x86_64-linux-gnu/libc.so.6

ret: 0x00000000`00000000 (0)
```
Which mapping is `malloc` in?
```
->vm malloc
Address: 0x00007f14`abaa50a0 is within allocation:
        0x00007f14`aba46000-0x00007f14`abaea000 r-x  656 KB offset: 0x00000000`00046000, name: /usr/lib/x86_64-linux-gnu/libc.so.6

ret: 0x00007f14`abaa50a0 (139726756139168)
```
## #4 Functions & Variables
Now, let's allocate a buffer:
```
->malloc 32

ret: 0x00007f14`88000cb0 (139726157778096)
```
Let's call it `p`:
```
->v p ret

ret: 0x00007f14`88000cb0 (139726157778096)
```
```
->v
Vars:
p                        : 0x00007f14`88000cb0 = 139726157778096

ret: 0x00007f14`88000cb0 (139726157778096)
```

## #5 Modifying data
Let's see where our buffer is:
```
->vm p
Address: 0x00007f14`88000cb0 is within allocation:
        0x00007f14`88000000-0x00007f14`88021000 rw-  132 KB

ret: 0x00007f14`88000cb0 (139726157778096)
```

Now let's copy some data in:
```
->w 8 p 0xddccbbaa11223344
Wrote value: 0xddccbbaa`11223344 = 15982355516737336132 to 0x00007f14`88000cb0

ret: 0x00007f14`88000cb0 (139726157778096)
->d p
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000cb0  44 33 22 11 aa bb cc dd 00 00 00 00 00 00 00 00  D3".............
7f1488000cc0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

ret: 0x00007f14`88000cb0 (139726157778096)
```
Let's put a string at offset `0x8`:
```
->v s "PQRSTUVWABCDEFG"

ret: 0x00007f14`999ed190 (139726453395856)
```
```
->+ p 8
0x00007f14`88000cb0 + 0x00000000`00000008 = 0x00007f14`88000cb8
139726157778096 + 8 = 139726157778104

ret: 0x00007f14`88000cb8 (139726157778104)
```
```
->cp ret s 16
Copied 16 bytes from 0x00007f14`abd1c2a0 to 0x00007f14`88000cb8

ret: 0x00007f14`88000cb8 (139726157778104)
```
```
->d p
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000cb0  44 33 22 11 aa bb cc dd 50 51 52 53 54 55 56 57  D3".....PQRSTUVW
7f1488000cc0  41 42 43 44 45 46 47 00 00 00 00 00 00 00 00 00  ABCDEFG.........

ret: 0x00007f14`88000cb0 (139726157778096)
```

## #6 Octal
Let's define a couple of useful flags:
```
->v O_CREAT 00000100

ret: 0x00000000`00000040 (64)
```
```
->v O_RDWR 00000002

ret: 0x00000000`00000002 (2)
```
Now let's combine them together with a logical OR
```
->| O_CREAT O_RDWR
0x00000000`00000040 | 0x00000000`00000002 = 0x00000000`00000042
64 | 2 = 66

ret: 0x00000000`00000042 (66)
```
```
->v flags ret

ret: 0x00000000`00000042 (66)
```

## #7 Files
Let create a variable for our filename:
```
->v name "/tmp/test.txt"

ret: 0x00007f85`581ef9f0 (140210685802992)
```
Let's open it:
```
->open name flags

ret: 0x00000000`00000007 (7)
```
And save the file descriptor in an variable:
```
->v fd ret

ret: 0x00000000`00000007 (7)
```
Then let's write out the buffer we made earlier:
```
->write fd p 32

ret: 0x00000000`00000010 (16)
```
Meanwhile, back in Linux:
```
$ hexdump -C /tmp/test.txt
00000000  44 33 22 11 aa bb cc dd  50 51 52 53 54 55 56 57  |D3".....PQRSTUVW|
00000010  41 42 43 44 45 46 47 00  00 00 00 00 00 00 00 00  |ABCDEFG.........|
00000020
```
## #8 Loading Modules
We can load a module using the `ld` command. File names must be double-quoted if they contain spaces:
```
-> ld /workspaces/frida-cshell/module.so
Loading: /workspaces/frida-cshell/module.so

ret: 0x00007600`d05dc430 "0x7600c8ed9000"
-> mod
0x00000000`00400000-0x00000000`00404070   16 KB target                         /workspaces/frida-cshell/target
0x00007ffe`4fb2f000-0x00007ffe`4fb300ab    4 KB linux-vdso.so.1                linux-vdso.so.1
0x00007600`d1f85000-0x00007600`d21ade50    2 MB libc.so.6                      /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007600`d21b4000-0x00007600`d21ef2d8  236 KB ld-linux-x86-64.so.2           /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007600`d1778000-0x00007600`d177c028   16 KB libdl.so.2                     /usr/lib/x86_64-linux-gnu/libdl.so.2
0x00007600`d1773000-0x00007600`d1777038   16 KB librt.so.1                     /usr/lib/x86_64-linux-gnu/librt.so.1
0x00007600`d168c000-0x00007600`d1772108  920 KB libm.so.6                      /usr/lib/x86_64-linux-gnu/libm.so.6
0x00007600`d1687000-0x00007600`d168b028   16 KB libpthread.so.0                /usr/lib/x86_64-linux-gnu/libpthread.so.0
0x00007600`c8ed9000-0x00007600`c8edd030   16 KB module.so                      /workspaces/frida-cshell/module.so

ret: 0x00000000`00000000 0
->
```
## #9 Breakpoints
First we will create a simple target application to make things a bit easier:
```c
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

    my_memcpy(buf, test, sizeof(test));

    puts(buf);

    free(buf);
    usleep(500000);
  }
}
```
First, lets see who calls `malloc`:
```
-> @f 1 malloc
Created #1  . function entry 0x00007f21`6f2970a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- bt
- q

ret: 0x00007f21`6f2970a0 139781575635104
Break #1 [function entry] @ $pc=0x00007f21`6f2970a0, $tid=1150000

0x4012bc target!main /workspaces/frida-cshell/target.c:27:8
0x4012bc target!main /workspaces/frida-cshell/target.c:27:8
0x7f216f21bd90 libc.so.6!0x29d90
0x7f216f21be40 libc.so.6!__libc_start_main+0x80
0x401155 target!_start+0x25


ret: 0x00000000`00000000 0
->
```

Let's see how many bytes are being allocated, we will set a function entry break-point to show it. Note here we use the new `r` commandlet and we will use the value `1` to our command so our breakpoint only fires the once. Note that we could have used `*` in its place to set a breakpoint which fires repeatedly:
```
-> @f 1 malloc
Created #1  . function entry 0x00007f00`18dbb0a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- R rdi
- q

ret: 0x00007f00`18dbb0a0 139638393778336
Break #1 [function entry] @ $pc=0x00007f00`18dbb0a0, $tid=1140600

Register rdi, value: 0x00000000`0000000c 12


ret: 0x00000000`0000000c 12
```

Now let's see the data in the buffer when it has been allocated, for this we will use a function exit breakpoint:
```
-> @F 1 malloc
Created #1  . function exit 0x00007f00`18dbb0a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- d $rax
- q

ret: 0x00007f00`18dbb0a0 139638393778336
Break #1 [function exit] @ $pc=0x00007f00`18dbb0a0, $tid=1140600

           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
01df2420  f2 1d 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01df2430  00 00 00 00 00 00 00 00 d1 fb 01 00 00 00 00 00  ................


ret: 0x00000000`01df2420 31400992
->
```
Now let's try an instruction breakpoint. We can set those at any address, not just the start of a function. Here we we can see that the 4th instruction copies `rdi` into `rbp`. Lets inspect that shall we?
```
-> l malloc
  #1: 0x00007fe2`821090a4: endbr64                                  f3 0f 1e fa
  #2: 0x00007fe2`821090a6: push r12                                 41 54
  #3: 0x00007fe2`821090a7: push rbp                                 55
  #4: 0x00007fe2`821090aa: mov rbp, rdi                             48 89 fd
  #5: 0x00007fe2`821090ab: push rbx                                 53
  #6: 0x00007fe2`821090af: sub rsp, 0x10                            48 83 ec 10
  #7: 0x00007fe2`821090b6: cmp byte ptr [rip + 0x17c432], 0         80 3d 32 c4 17 00 00
  #8: 0x00007fe2`821090bc: je 0x7f63c678f81a                        0f 84 14 02 00 00
  #9: 0x00007fe2`821090bf: test rbp, rbp                            48 85 ed
 #10: 0x00007fe2`821090c2: js 0x7f63c678f81f                        0f 88 19 02 00 00

ret: 0x00007fe2`821090c9 140610821460169
-> @i 1 0x00007fe2`821090c9
Created #1  . instruction 0x00007fe2`821090ab: 0x00007fe2`821090ab [hits:1]

Type 'q' to finish, or 'x' to abort
- R
- q

ret: 0x00007fe2`821090ab 140610821460139
Break #1 [instruction] @ $pc=0x00007fe2`821090ab, $tid=1141330

Registers:
rax : 0x00000000`00000000 0
rcx : 0x00007fe2`821497f8 140610821724152
rdx : 0x00000000`00000000 0
rbx : 0x00000000`00000000 0
rsp : 0x00007ffe`174a82d0 140729289179856
rbp : 0x00000000`0000000c 12
rsi : 0x00000000`00000000 0
rdi : 0x00000000`0000000c 12
r8  : 0x00000000`00000000 0
r9  : 0x00000000`019353e0 26432480
r10 : 0x00000000`00000000 0
r11 : 0x00000000`00000293 659
r12 : 0x00007ffe`174a8438 140729289180216
r13 : 0x00000000`00401248 4198984
r14 : 0x00000000`00403e18 4210200
r15 : 0x00007fe2`822cd040 140610823311424
rip : 0x00007fe2`821090ab 140610821460139
tid : 0x00000000`00116a52 1141330
ra  : 0x00007fe2`821090ab 140610821460139


ret: 0x00007fe2`821090ab 140610821460139
->
```

Now let's display that last breakpoint:
```
-> @i
instruction breakpoints:
#1  .  0x00007fe2`821090ab: 0x00007fe2`821090ab [hits:disabled]
  - r


ret: 0x00000000`00000000 0
->
```

We can delete our breakpoint like so:
```
-> @i #1 #
Deleted #1  . instruction 0x00007fe2`821090ab: 0x00007fe2`821090ab [hits:disabled]
  - r


ret: 0x00007fe2`821090ab 140610821460139
```
```
-> @i
instruction breakpoints:

ret: 0x00000000`00000000 0
->
```

## #10 Advanced Breakpoints (#1)
In this first example, we will test modifying the return value from a function:

First, we will allocate 16 pages of memory (as it is unlikely that this buffer will be re-used by our application once freed).
```
-> * 4096 16
0x00000000`00001000 * 0x00000000`00000010 = 0x00000000`00010000
4096 * 16 = 65536

ret: 0x00000000`00010000 65536
-> malloc ret
```
Let's call our buffer `p`:
```
ret: 0x00007fe2`68000c90 140610384170128
-> v p ret
```
Now let's set a function exit breakpoint for `malloc` which is triggered only once, and replaces the return value with our buffer:
```
ret: 0x00007fe2`68000c90 140610384170128
-> @F 1 malloc
Created #1  . function exit 0x00007fe2`821090a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- R ret p
- q

ret: 0x00007fe2`821090a0 140610821460128
Break #1 [function exit] @ $pc=0x00007fe2`821090a0, $tid=1141330

Register ret, set to value: 0x00007fe2`68000c90 140610384170128


ret: 0x00007fe2`68000c90 140610384170128
```
Now we can inspect out buffer to see what the program did with it:
```
-> d p
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7fe268000c90  54 45 53 54 5f 53 54 52 49 4e 47 00 00 00 00 00  TEST_STRING.....
7fe268000ca0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

ret: 0x00007fe2`68000c90 140610384170128
->
```
## #11 Advanced Breakpoints (#2)
In this example, we will use breakpoints to see where our allocated buffer is written. We set our function exit breakpoint on malloc, then in it's command list, we use the `@w` command to set a breakpoint which fires when memory is written on the return value for a length of 16-bytes.
```
-> @F 1 malloc
Created #1  . function exit 0x00007f2b`4cba00a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- @w 1 $ret 16
- q

ret: 0x00007f2b`4cba00a0 139823947579552
Break #1 [function exit] @ $pc=0x00007f2b`4cba00a0, $tid=1143546

Created #1  . memory write 0x00000000`0143e3c0: $ret [hits:1] [length:16]



ret: 0x00000000`0143e3c0 21226432
Break #1 [memory write] @ $pc=0x00007f2b`4cca9e48, $addr=0x00000000`0143e3c0


ret: 0x00000000`0143e3c0 21226432
->
```
We can see in our output the program counter at the point the buffer was modified. But what if we want more details?

## #12 Advanced Breakpoints (#3)
Here we will continue where our previous example left off. Note that since the CShell isn't a debugger it doesn't stop any threads, the program is always running. Whilst this limits our interactivity a little, it can also be an advantage since it won't interrupt any programs which may be monitored by watchdogs. As a result, however, we must decide what our breakpoints should do prior to them being hit and configure them appropriately. We cannot edit our command list after the breakpoint has fired.

First, we will create a memory write breakpoint without assigning an address. Note that we set the hit count to `0` so that it doesn't fire. We omit an address from the command altogether. For our command list, we assign the command `l $pc` to display the code at the point the breakpoint fires.
```
-> @w 0
Created #1  . memory write unassigned:  [hits:disabled] [length:0]

Type 'q' to finish, or 'x' to abort
- l $pc
- q

ret: 0x00000000`00000000 0
```
Now we set a function exit breakpoint on `malloc`, in it's command list, we set a single command `@w #1 1 $ret 16`. This command modifies the memory write breakpoint with index `#1`, configuring it to fire once, when the 16 byte region starting at the return value (`$ret`) is written.
```
-> @F 1 malloc
Created #1  . function exit 0x00007fab`70e770a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- @w #1 1 $ret 16
- q

ret: 0x00007fab`70e770a0 140374310351008
Break #1 [function exit] @ $pc=0x00007fab`70e770a0, $tid=1152420

Modified #1  . memory write 0x00000000`00b1f3c0: $ret [hits:1] [length:16]
  - l $pc



ret: 0x00000000`00000000 0
Break #1 [memory write] @ $pc=0x00007fab`70f80e48, $addr=0x00000000`00b1f3c0

0x00007fab`70f80e4b: mov qword ptr [rdi], rsi
0x00007fab`70f80e50: mov qword ptr [rdi + rdx - 8], rcx
0x00007fab`70f80e51: ret
0x00007fab`70f80e59: vmovdqu64 ymm18, ymmword ptr [rsi + rdx - 0x20]
0x00007fab`70f80e61: vmovdqu64 ymm19, ymmword ptr [rsi + rdx - 0x40]
0x00007fab`70f80e67: vmovdqu64 ymmword ptr [rdi], ymm16
ERROR: Failed to read 0x00000000`00000020 bytes from 0x00007fab`70f80e48, Error: invalid instruction

ret: 0x00000000`00000000 0
->
```
Unfortunately, here, we are limited somewhat by the capabilities of FRIDA, since the  `MemoryAccessMonitor` doesn't expose the register values at the point of a memory access. But we can use it to set a code breakpoint where we can get this detail.

We will do this therefore using a combination of 3 breakpoints. Our first breakpoint will fire when `malloc` returns, we will use this to configure a memory write breakpoint on the buffer it returns. We will then configure this breakpoint to set an instruction breakpoint on the next instruction.

First we will create an unassigned instruction breakpoint and set it's commands to show a backtrace:
```
-> @i 0
Created #1  . instruction unassigned:  [hits:disabled]

Type 'q' to finish, or 'x' to abort
- bt
- q

ret: 0x00000000`00000000 0
```
Next we will set an unassigned memory write breakpoint, its command list contains a single command `@i #1 1 $pc`. It will set instruction breakpoint number `#1` to first a single time at the address `$pc` (e.g. the exact same location that the memory breakpoint fired).
```
-> @w 0
Created #1  . memory write unassigned:  [hits:disabled] [length:0]

Type 'q' to finish, or 'x' to abort
- @i #1 1 $pc
- q

ret: 0x00000000`00000000 0
```
Lastly, just like before, we can configure our function exit breakpoint for `malloc` to configure our memory write breakpoint to fire once if the 16-byte region at the start of the returned buffer is written.
```
-> @F 1 malloc
Created #1  . function exit 0x00007f36`fd7750a0: malloc [hits:1]

Type 'q' to finish, or 'x' to abort
- @w #1 1 $ret 16
- q

ret: 0x00007f36`fd7750a0 139874157416608
Break #1 [function exit] @ $pc=0x00007f36`fd7750a0, $tid=1163391

Modified #1  . memory write 0x00000000`010833c0: $ret [hits:1] [length:16]
  - @i #1 1 $pc



ret: 0x00000000`00000000 0
Break #1 [memory write] @ $pc=0x00007f36`fd87ee48, $addr=0x00000000`010833c0

Modified #1  . instruction 0x00007f36`fd87ee48: $pc [hits:1]
  - bt



ret: 0x00000000`00000000 0
Break #1 [instruction] @ $pc=0x00007f36`fd87ee48, $tid=1163391

0x401245 target!my_memcpy /workspaces/frida-cshell/target.c:11:1
0x401245 target!my_memcpy /workspaces/frida-cshell/target.c:11:1
0x4012e2 target!main /workspaces/frida-cshell/target.c:32:5
0x7f36fd6f9d90 libc.so.6!0x29d90
0x7f36fd6f9e40 libc.so.6!__libc_start_main+0x80
0x401155 target!_start+0x25


ret: 0x00000000`00000000 0
->
```
# Commands
In contrast to a conventional shell, commands are not processes to be executed, but rather functions. `C` functions within the target application. For example, we can call `malloc` to provide us some memory as follows:

```
->malloc 16

ret: 0x00007f53`1c000c70 (139994928778352)
```

Here, our C-Shell has found the symbol for the function `malloc` and invoked it for us with the parameter `16`. Equally, if we only had the address for our function, we could use that directly instead:

```
->sym malloc
Symbol: malloc found at 0x00007f58`7d6a50a0

ret: 0x00007f58`7d6a50a0 (140018037969056)
```

```
->0x00007f587d6a50a0 16

ret: 0x00007f58`64000c70 (140017611574384)
```

# Commandlets
As well as being able to directly call functions in `C`, the C-Shell also provides a number of Commandlets, we can see a list of these by running the `help` command:
```
-> help
breakpoints:
        @F        :  function exit breakpoint
        @f        :  function entry breakpoint
        @i        :  instruction breakpoint
        @r        :  memory read breakpoint
        @w        :  memory write breakpoint
        R         :  register management
data:
        cp        :  copy data in memory
        d         :  dump data from memory
        l         :  disassembly listing
        r         :  read data from memory
        w         :  write data to memory
math:
        &         :  and two operands
        *         :  multiply two operands
        +         :  add two operands
        -         :  subtract two operands
        /         :  divide two operands
        <<        :  shl op1 by op2
        >>        :  shr op1 by op2
        ^         :  xor two operands
        |         :  or two operands
        ~         :  bitwise not
memory:
        sym       :  look up a symbol information
        vm        :  display virtual memory ranges
misc:
        h         :  command history
        help      :  print this message
        v         :  variable management
modules:
        ld        :  load modules
        mod       :  display module information
thread:
        bt        :  display backtrace information
        t         :  display thread information

For more information about a command use:
        help <cmd>

ret: 0x00000000 0
```

For more details on any command we can run `help <cmd>`, e.g.
```
->help mod
Usage: mod

mod - show all modules

mod address - show module for address
  address   the address/symbol to show module information for

mod name - show named module
  name      the name of the module to show information for

ret: 0x00000000`00000000 (0)
```
When using a commandlet, just like calling a `C` function, it's name appears first on the command line, followed by its arguments. Each token is separated by a space. e.g.

```
->mod libc.so.6
0x00007fb6`57a00000-0x00007fb6`57c28e50    2 MB libc.so.6                      /usr/lib/x86_64-linux-gnu/libc.so.6

ret: 0x00000000`00000000 (0)
```

Thus our mathematic operations use a prefix notation, e.g.
```
->+ 3 5
0x00000000`00000003 + 0x00000000`00000005 = 0x00000000`00000008
3 + 5 = 8

ret: 0x00000000`00000008 (8)
```
# Development
The reponsitory is configured to support Visual Studio Code's `Dev Containers`. Open the repository in VSCode, install the `Dev Containers` extension and when prompted opt to `Reopen in Container` or select `Dev Containers: Reopen in Container` from the command pallete. To build, select `Terminal` -> `Run Build Task` from the menu. The output `frida-cshell.js` can be found in the root directory of the repository.

To build without VSCode, refer to the file `.devcontainer/Dockerfile` to see the required dependencies.

# Parameters
C-Shell supports 4 kinds or parameters:
* **symbols** - Either from debug symbols, or exported symbols.
* **numerics** - Octal, Decimal or Hexadecimal numbers
* **strings** - Ascii string literals enclosed in quotation marks
* **variables** - Pseudonyms configured by the user as substitures for the other parameter types.

# Symbols
Symbol information can be interrogated using the `sym` command as follows:
```
->sym
Usage: sym

sym name - display address information for a named symbol
  name   the name of the symbol to lookup

sm addr - display symbol information associated with an address
  addr   the address of the symbol to lookup

ret: 0x00000000`00000000 (0)
```

For example:
```
->sym malloc
Symbol: malloc found at 0x00007f24`98aa50a0

ret: 0x00007f24`98aa50a0 (139795156848800)
```

```
->sym 0x00007f24`98aa53e0
Symbol: libc.so.6!free found at 0x00007f24`98aa53e0

ret: 0x00007f24`98aa53e0 (139795156849632)
```

# Numerics
Numeric values can be in either octal, decimal or hexadecimal. The backtick (`` ` ``) character can be used to aid readability and is ignored:
* ``1`000`000``
* ``0xaabbccdd`11223344``

Octal values must be represented with either a leading `0o` or `0O` prefix, or otherwise just a leading `0` like in `C`:
* `0o777`
* `0O12`
* `016`

Decimal values can be represented with an optional `0d` or `0D` prefix, or simply as a string of digits. Any numbers without a prefix are assumed to be decimal:
* `0d123`
* `0D135`
* `54321`

Hexadecimal values must be represented with a leading `0x` or `0X` prefix:
* `0xdeadface`
* `0xBEEFD00D`

Hexadecimal values are not premitted without a prefix. e.g. the following would be invalid:
* `add`

# Strings
Strings are delimited with `"` at the start and end.

# Variables
Variables are a useful way to be able to assign meaningful names to values. Consider our example earlier, where we allocated an arbitrary buffer:
```
->malloc 16

ret: 0x00007f24`78000c70 (139794608819312)
```
Every time we want to view, modify, or read the buffer, without variables, we would need to use its address:
```
->malloc 16

ret: 0x00007fcf`b0000c70 (140529987751024)
```
```
->d 0x00007fcf`b0000c70
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7fcfb0000c70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
7fcfb0000c80  00 00 00 00 00 00 00 00 81 03 02 00 00 00 00 00  ................

ret: 0x00007fcf`b0000c70 (140529987751024)
```
```
->w 8 0x00007fcf`b0000c70 0xaabbccdd`11223344
Wrote value: 0xaabbccdd`11223344 = 12302652056939934532 to 0x00007fcf`b0000c70

ret: 0x00007fcf`b0000c70 (140529987751024)
```
```
->d 0x00007fcf`b0000c70
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7fcfb0000c70  44 33 22 11 dd cc bb aa 00 00 00 00 00 00 00 00  D3".............
7fcfb0000c80  00 00 00 00 00 00 00 00 81 03 02 00 00 00 00 00  ................

ret: 0x00007fcf`b0000c70 (140529987751024)
```
This gets very tedious very quickly.

## Assigning a Variable
Instead we can assign a variable (`p`) to our buffer and use it in our subsequent commands:
```
->malloc 16

ret: 0x00007f14`88000c70 (139726157778032)
```
```
->v p 0x00007f1488000c70

ret: 0x00007f14`88000c70 (139726157778032)
```
```
->v
Vars:
p                        : 0x00007f14`88000c70 = 139726157778032

ret: 0x00007f14`88000c70 (139726157778032)
```
```
->d p
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000c70  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
7f1488000c80  00 00 00 00 00 00 00 00 25 00 00 00 00 00 00 00  ........%.......

ret: 0x00007f14`88000c70 (139726157778032)
```
```
->w 8 p 0xaabbccdd11223344
Wrote value: 0xaabbccdd`11223344 = 12302652056939934532 to 0x00007f14`88000c70

ret: 0x00007f14`88000c70 (139726157778032)
```
```
->d p
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000c70  44 33 22 11 dd cc bb aa 00 00 00 00 00 00 00 00  D3".............
7f1488000c80  00 00 00 00 00 00 00 00 25 00 00 00 00 00 00 00  ........%.......

ret: 0x00007f14`88000c70 (139726157778032)
```
This makes things much more efficient.

## Ret
Better still, we can avoid having to copy-paste, or type out the address of our buffer at all. When you invoke a `C` function, or call a commandlet, a pseudo-variable named `ret` is assigned to the result. In the case of a `C` function, this is the value returned by the function. In the case of a commandlet, it is determined by the commandlet itself, but should probably be set to the value that is likely to be most useful. We can therefore use the following short-hand:

```
->malloc 16

ret: 0x00007f14`88000c90 (139726157778064)
```
```
->d ret
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000c90  00 80 48 f1 07 00 00 00 00 00 00 00 00 00 00 00  ..H.............
7f1488000ca0  00 00 00 00 00 00 00 00 61 03 02 00 00 00 00 00  ........a.......

ret: 0x00007f14`88000c90 (139726157778064)
```
```
->w 8 ret 0xaabbccdd`11223344
Wrote value: 0xaabbccdd`11223344 = 12302652056939934532 to 0x00007f14`88000c90

ret: 0x00007f14`88000c90 (139726157778064)
```
```
->d ret
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7f1488000c90  44 33 22 11 dd cc bb aa 00 00 00 00 00 00 00 00  D3".............
7f1488000ca0  00 00 00 00 00 00 00 00 61 03 02 00 00 00 00 00  ........a.......

ret: 0x00007f14`88000c90 (139726157778064)
```
