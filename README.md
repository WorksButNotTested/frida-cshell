# Overview
The C-Shell is a command line interpreter which can be used in conjunction with the `frida-inject` tool, it takes inspiration from the VxWorks C-Shell and is intended to allow the user to interactively inspect a running process by issuing commands. By setting `frida-inject` to use `raw` and `interactive` modes, the script can read and write raw bytes to the TTY allowing direct interation with the user. It is implmented purely in about 12k lines of Typescript (which is embedded as a resource into a shell script which launches `frida-inject`) and converts the user's input into calls into the [FRIDA JS API bindings](https://frida.re/docs/javascript-api/). 

It is intended to allow much more dynamic interaction with a process, without requiring the user to write and modify JS each time they wish to inspect something new. It works much more like a debugger, but without the complex syntax of GDB and without stopping threads (which can interefere with watchdog timers). It is extensible too, allowing the user to define macros, run commands from a file, as well as add new commands in an adhoc fashion via `JS` (so if you want to add a command to dump some application specific data format then you can).

Some of the key features are:
* Add breakpoints on function entry and exit, instructions, memory access (without stopping the target application)
* Log coverage data (using stalker) for a function to show the executed blocks or calls for a function or thread.
* Collect coverage data into a dynamoRIO format file for inspection with `lighthouse` (IDA) or `lightkeeper` (Ghidra) for a function or thread or application.
* Patch a function with another implementation (including one written in JS)
* Modify memory, or dump it to screen or to a file
* Show diassassembly listings or register contents
* Dump a file or show the open file descriptors for the process
* Perform basic math operations with a relatively simple syntax
* Query symbol and virtual memory information
* Create a coredump of the running process without killing it
* Call any function in the application with any arguments you like
* Display the value of `errno`
* Log all commands and output to file
* Filter command output using regular expressions
* Command history
* Create and manage variables (to give a friendly name to strings, addresses or numbers)
* Load modules and display module information
* Show the threads running in the application and their backtraces
* Determine which threads are busiest and compare to a baseline

# Install
## Using NPM as root
The easiest way to install `frida-cshell` is to use the command:
```bash
sudo npm install -g frida-cshell
```

## Using NPM as a normal user
If you can't or don't want to install `frida-cshell` as root, then you can install and run it as follows:
```bash
npm install frida-cshell
```
```bash
npm exec frida-cshell
```

## Adhoc
Alternatively you can download the [latest](https://github.com/WorksButNotTested/frida-cshell/releases/latest) directly from release from GitHub and download and run the `frida-cshell-x.y.z` bash script

# Options
The `frida-cshell` script presents the following options:
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

# Advanced
Alternatively you can use `frida-inject` directly to load the `frida-inject-x.y.z.js` script (available from the [releases](https://github.com/WorksButNotTested/frida-cshell/releases/latest) page).

**Important** Be sure to include the `--interactive` command line option, in addition to your other usual options, otherwise the terminal will appear non-responsive.

# Startup

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
-> @f malloc 1
Created #1.  [function entry] malloc @ $pc=0x00007f58`767df0a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- bt
- q

ret: 0x00007f58`767df0a0 140017921814688
--------------------------------------------------------------------------------
| Break #1 [function entry] malloc @ $pc=0x00007f58`767df0a0 $tid=261570
--------------------------------------------------------------------------------
|
| -> bt
| target64!main........................... 0x00000000`004014a5|         /root/target.c:124 |
| target64!main........................... 0x00000000`004014a5|         /root/target.c:124 |
| libc.so.6!0x29d90....................... 0x00007f58`76763d90|
| libc.so.6!__libc_start_main+0x80........ 0x00007f58`76763e40|
| target64!_start+0x25.................... 0x00000000`00401195|
|
| ret: 0x00000000`00000000 0
|
--------------------------------------------------------------------------------
->
```

Let's see how many bytes are being allocated, we will set a function entry break-point to show it. Note here we use the new `r` commandlet and we will use the value `1` to our command so our breakpoint only fires the once. Note that we could have used `*` in its place to set a breakpoint which fires repeatedly:
```
-> @f malloc 1
Created #2.  [function entry] malloc @ $pc=0x00007f58`767df0a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- R rdi
- q

ret: 0x00007f58`767df0a0 140017921814688
--------------------------------------------------------------------------------
| Break #2 [function entry] malloc @ $pc=0x00007f58`767df0a0 $tid=261570
--------------------------------------------------------------------------------
|
| -> R rdi
| Register rdi, value: 0x00000000`0000000c 12
|
| ret: 0x00000000`0000000c 12
|
--------------------------------------------------------------------------------
->
```

Now let's see the data in the buffer when it has been allocated, for this we will use a function exit breakpoint:
```
-> @F malloc 1
Created #1.  [function exit] malloc @ $pc=0x00007f58`767df0a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- d $rax
- q

ret: 0x00007f58`767df0a0 140017921814688
--------------------------------------------------------------------------------
| Break #1 [function exit] malloc @ $pc=0x00007f58`767df0a0 $tid=261570
--------------------------------------------------------------------------------
|
| -> d $rax
|              0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
| 0x022593d0  59 22 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Y"..............
| 0x022593e0  00 00 00 00 00 00 00 00 21 fc 01 00 00 00 00 00  ........!.......
|
| ret: 0x00000000`022593d0 36017104
|
--------------------------------------------------------------------------------
->
```
Now let's try an instruction breakpoint. We can set those at any address, not just the start of a function. Here we we can see that the 4th instruction copies `rdi` into `rbp`. Lets inspect that shall we?
```
-> l malloc
  #1: 0x00007f58`767df0a0: endbr64                                  f3 0f 1e fa
  #2: 0x00007f58`767df0a4: push r12                                 41 54
  #3: 0x00007f58`767df0a6: push rbp                                 55
  #4: 0x00007f58`767df0a7: mov rbp, rdi                             48 89 fd
  #5: 0x00007f58`767df0aa: push rbx                                 53
  #6: 0x00007f58`767df0ab: sub rsp, 0x10                            48 83 ec 10
  #7: 0x00007f58`767df0af: cmp byte ptr [rip + 0x17c432], 0         80 3d 32 c4 17 00 00
  #8: 0x00007f58`767df0b6: je 0x7f58741c621a                        0f 84 14 02 00 00
  #9: 0x00007f58`767df0bc: test rbp, rbp                            48 85 ed
 #10: 0x00007f58`767df0bf: js 0x7f58741c621f                        0f 88 19 02 00 00

ret: 0x00007f58`767df0c5 140017921814725
-> @i 0x00007f58`767df0a7 1
Created #1.  [instruction] 0x00007f58`767df0a7 @ $pc=0x00007f58`767df0a7 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- R
- q

ret: 0x00007f58`767df0a7 140017921814695
--------------------------------------------------------------------------------
| Break #1 [instruction] 0x00007f58`767df0a7 @ $pc=0x00007f58`767df0a7 $tid=261570
--------------------------------------------------------------------------------
|
| -> R
| Registers:
| rax : 0x00000000`00000009 9
| rcx : 0x00000000`00000001 1
| rdx : 0x00000000`00000000 0
| rbx : 0x00000000`00000000 0
| rsp : 0x00007ffd`22c2dcb8 140725186649272
| rbp : 0x00007ffd`22c2dd00 140725186649344
| rsi : 0x00000000`0040201d 4202525
| rdi : 0x00000000`0000000c 12
| r8  : 0x00000000`00000000 0
| r9  : 0x00007ffd`22c2da97 140725186648727
| r10 : 0x00000000`00000000 0
| r11 : 0x00000000`00000001 1
| r12 : 0x00007ffd`22c2de18 140725186649624
| r13 : 0x00000000`00401425 4199461
| r14 : 0x00000000`00403e18 4210200
| r15 : 0x00007f58`769a8040 140017923686464
| rip : 0x00007f58`767df0a7 140017921814695
| tid : 0x00000000`0003fdc2 261570
| ra  : 0x00007f58`767df0a7 140017921814695
|
| ret: 0x00007f58`767df0a7 140017921814695
|
--------------------------------------------------------------------------------
->
```

Now let's display that last breakpoint:
```
-> @i
instruction breakpoints:
#1.  [instruction] 0x00007f58`767df0a7 @ $pc=0x00007f58`767df0a7 [hits:disabled]
  - R


ret: 0x00000000`00000000 0
->
```

We can delete our breakpoint like so:
```
-> @i #1 #
Deleted #1.  [instruction] 0x00007f58`767df0a7 @ $pc=0x00007f58`767df0a7 [hits:disabled]
  - R


ret: 0x00007f58`767df0a7 140017921814695
->
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

          HEXADECIMAL           DECIMAL
  0x00000000`00001000              4096
* 0x00000000`00000010     *          16
---------------------     -------------
  0x00000000`00010000             65536
---------------------     -------------


ret: 0x00000000`00010000 65536
-> malloc ret

ret: 0x00007f58`5c000c90 140017477356688
->
```
Let's call our buffer `p`:
```
-> v p ret

ret: 0x00007f58`5c000c90 140017477356688
->
```
Now let's set a function exit breakpoint for `malloc` which is triggered only once, and replaces the return value with our buffer:
```
-> @F malloc 1
Created #2.  [function exit] malloc @ $pc=0x00007f58`767df0a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- R ret p
- q

ret: 0x00007f58`767df0a0 140017921814688
--------------------------------------------------------------------------------
| Break #2 [function exit] malloc @ $pc=0x00007f58`767df0a0 $tid=261570
--------------------------------------------------------------------------------
|
| -> R ret p
| Register ret, set to value: 0x00007f58`5c000c90 140017477356688
|
| ret: 0x00007f58`5c000c90 140017477356688
|
--------------------------------------------------------------------------------
->
```
Now we can inspect out buffer to see what the program did with it:
```
-> d p
                 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
0x7f585c000c90  54 45 53 54 5f 53 54 52 49 4e 47 00 00 00 00 00  TEST_STRING.....
0x7f585c000ca0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................

ret: 0x00007f58`5c000c90 140017477356688
->
```
## #11 Advanced Breakpoints (#2)
In this example, we will use breakpoints to see where our allocated buffer is written. We set our function exit breakpoint on malloc, then in it's command list, we use the `@w` command to set a breakpoint which fires when memory is written on the return value for a length of 16-bytes.
```
-> @F malloc 1
Created #2.  [function exit] malloc @ $pc=0x00007f88`7bcd90a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- @w $ret 16 1
- q

ret: 0x00007f88`7bcd90a0 140224169349280
--------------------------------------------------------------------------------
| Break #2 [function exit] malloc @ $pc=0x00007f88`7bcd90a0 $tid=263577
--------------------------------------------------------------------------------
|
| -> @w $ret 16 1
| Created #1.  [memory write] ret @ $pc=0x00000000`00f453d0 [hits:1] [length:16]
|
|
| ret: 0x00000000`00f453d0 16012240
|
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
| Break #1 [memory write] ret @ $pc=0x00007f88`7bde2e48 $addr=0x00000000`00f453d0
--------------------------------------------------------------------------------
|
--------------------------------------------------------------------------------
->
```
We can see in our output the program counter at the point the buffer was modified. But what if we want more details?

## #12 Advanced Breakpoints (#3)
Here we will continue where our previous example left off. Note that since the CShell isn't a debugger it doesn't stop any threads, the program is always running. Whilst this limits our interactivity a little, it can also be an advantage since it won't interrupt any programs which may be monitored by watchdogs. As a result, however, we must decide what our breakpoints should do prior to them being hit and configure them appropriately. We cannot edit our command list after the breakpoint has fired.

First, we will create a memory write breakpoint without assigning an address. Note that we set the hit count to `0` so that it doesn't fire. We omit an address from the command altogether. For our command list, we assign the command `l $pc` to display the code at the point the breakpoint fires.
```
-> @w 0 0
Created #1.  [memory write]  @ $pc=unassigned [hits:disabled] [length:0]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- l $pc
- q

ret: 0x00000000`00000000 0
->
```
Now we set a function exit breakpoint on `malloc`, in it's command list, we set a single command `@w #1 1 $ret 16`. This command modifies the memory write breakpoint with index `#1`, configuring it to fire once, when the 16 byte region starting at the return value (`$ret`) is written.
```
-> @F malloc 1
Created #1.  [function exit] malloc @ $pc=0x00007f73`ce5980a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- @w #1 $ret 16 1
- q

ret: 0x00007f73`ce5980a0 140135359938720
--------------------------------------------------------------------------------
| Break #1 [function exit] malloc @ $pc=0x00007f73`ce5980a0 $tid=264154
--------------------------------------------------------------------------------
|
| -> @w #1 $ret 16 1
| Modified #1.  [memory write] ret @ $pc=0x00000000`00d363d0 [hits:1] [length:16]
|   - l $pc
|
|
| ret: 0x00000000`00d363d0 13853648
|
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
| Break #1 [memory write] ret @ $pc=0x00007f73`ce6a1e48 $addr=0x00000000`00d363d0
--------------------------------------------------------------------------------
|
| -> l $pc
|   #1: 0x00007f73`ce6a1e48: mov qword ptr [rdi], rsi                 48 89 37
|   #2: 0x00007f73`ce6a1e4b: mov qword ptr [rdi + rdx - 8], rcx       48 89 4c 17 f8
|   #3: 0x00007f73`ce6a1e50: ret                                      c3
|   #4: 0x00007f73`ce6a1e51: vmovdqu64 ymm18, ymmword ptr [rsi + rdx - 0x20] 62 e1 fe 28 6f 54 16 ff
|   #5: 0x00007f73`ce6a1e59: vmovdqu64 ymm19, ymmword ptr [rsi + rdx - 0x40] 62 e1 fe 28 6f 5c 16 fe
|   #6: 0x00007f73`ce6a1e61: vmovdqu64 ymmword ptr [rdi], ymm16       62 e1 fe 28 7f 07
|   #7: 0x00007f73`ce6a1e67: vmovdqu64 ymmword ptr [rdi + 0x20], ymm17 62 e1 fe 28 7f 4f 01
|   #8: 0x00007f73`ce6a1e6e: vmovdqu64 ymmword ptr [rdi + rdx - 0x20], ymm18 62 e1 fe 28 7f 54 17 ff
|   #9: 0x00007f73`ce6a1e76: vmovdqu64 ymmword ptr [rdi + rdx - 0x40], ymm19 62 e1 fe 28 7f 5c 17 fe
|  #10: 0x00007f73`ce6a1e7e: ret                                      c3
|
| ret: 0x00007f73`ce6a1e7f 140135361027711
|
--------------------------------------------------------------------------------
->
```
Unfortunately, here, we are limited somewhat by the capabilities of FRIDA, since the  `MemoryAccessMonitor` doesn't expose the register values at the point of a memory access. But we can use it to set a code breakpoint where we can get this detail.

We will do this therefore using a combination of 3 breakpoints. Our first breakpoint will fire when `malloc` returns, we will use this to configure a memory write breakpoint on the buffer it returns. We will then configure this breakpoint to set an instruction breakpoint on the next instruction.

First we will create an unassigned instruction breakpoint and set it's commands to show a backtrace:
```
-> @i 0
Created #1.  [instruction]  @ $pc=unassigned [hits:disabled]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- bt
- q

ret: 0x00000000`00000000 0
->
```
Next we will set an unassigned memory write breakpoint, its command list contains a single command `@i #1 1 $pc`. It will set instruction breakpoint number `#1` to first a single time at the address `$pc` (e.g. the exact same location that the memory breakpoint fired).
```
-> @w 0 0
Created #1.  [memory write]  @ $pc=unassigned [hits:disabled] [length:0]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- @i #1 $pc 1
- q

ret: 0x00000000`00000000 0
->
```
Lastly, just like before, we can configure our function exit breakpoint for `malloc` to configure our memory write breakpoint to fire once if the 16-byte region at the start of the returned buffer is written.
```
-> @F malloc 1
Created #1.  [function exit] malloc @ $pc=0x00007fd8`ee1d40a0 [hits:1]

Type 'q' to finish, 'c' to clear, or 'x' to abort
- @w #1 $ret 16 1
- q

ret: 0x00007fd8`ee1d40a0 140569684557984
--------------------------------------------------------------------------------
| Break #1 [function exit] malloc @ $pc=0x00007fd8`ee1d40a0 $tid=264959
--------------------------------------------------------------------------------
|
| -> @w #1 $ret 16 1
| Modified #1.  [memory write] ret @ $pc=0x00000000`00a483d0 [hits:1] [length:16]
|   - @i #1 $pc 1
|
|
| ret: 0x00000000`00a483d0 10781648
|
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
| Break #1 [memory write] ret @ $pc=0x00007fd8`ee2dde48 $addr=0x00000000`00a483d0
--------------------------------------------------------------------------------
|
| -> @i #1 $pc 1
| Modified #1.  [instruction] pc @ $pc=0x00007fd8`ee2dde48 [hits:1]
|   - bt
|
|
| ret: 0x00007fd8`ee2dde48 140569685646920
|
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
| Break #1 [instruction] pc @ $pc=0x00007fd8`ee2dde48 $tid=264959
--------------------------------------------------------------------------------
|
| -> bt
| target64!my_memcpy...................... 0x00000000`00401285|         /root/target.c:13 |
| target64!my_memcpy...................... 0x00000000`00401285|         /root/target.c:13 |
| target64!main........................... 0x00000000`004014cb|         /root/target.c:129 |
| libc.so.6!0x29d90....................... 0x00007fd8`ee158d90|
| libc.so.6!__libc_start_main+0x80........ 0x00007fd8`ee158e40|
| target64!_start+0x25.................... 0x00000000`00401195|
|
| ret: 0x00000000`00000000 0
|
--------------------------------------------------------------------------------
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
