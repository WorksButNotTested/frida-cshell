# Overview
The C-Shell is a command line interpreter embedded as part of the `frida-inject` tool, it takes inspiration from the VxWorks C-Shell and is intended to allow the user to interactively inspect a running process by issuing commands. By setting `frida-inject` to use raw mode, the tool acts as a dumb byte pump sending and receiving raw key-strokes between the TTY and the C-shell. It is implmented purely in about 2k lines of Typescript (which is embedded as a resource) and converts the user's input into calls into the [FRIDA JS API bindings](https://frida.re/docs/javascript-api/).

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
->l malloc
0x00007f14`abaa50a0: endbr64
0x00007f14`abaa50a4: push r12
0x00007f14`abaa50a6: push rbp
0x00007f14`abaa50a7: mov rbp, rdi
0x00007f14`abaa50aa: push rbx
0x00007f14`abaa50ab: sub rsp, 0x10
0x00007f14`abaa50af: cmp byte ptr [rip + 0x17c432], 0
0x00007f14`abaa50b6: je 0x7f14abaa52d0
0x00007f14`abaa50bc: test rbp, rbp
0x00007f14`abaa50bf: js 0x7f14abaa52de

ret: 0x00007f14`abaa50c9 (139726756139209)
```
and a bit more...
```
->l ret
0x00007f14`abaa50c9: xor r12d, r12d
0x00007f14`abaa50cc: cmp rax, 0x1f
0x00007f14`abaa50d0: ja 0x7f14abaa51b0
0x00007f14`abaa50d6: mov rbx, qword ptr [rip + 0x174ccb]
0x00007f14`abaa50dd: mov rdx, qword ptr fs:[rbx]
0x00007f14`abaa50e1: test rdx, rdx
0x00007f14`abaa50e4: je 0x7f14abaa51c8

ret: 0x00007f14`abaa50f1 (139726756139249)
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
->w8 p 0xddccbbaa11223344
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
# TODO
Commandlets not yet implemented:
* `ld` - Load a shared library into the target process.
* `fd` - Show open file descriptors (for Unix like OS)
* `@` - Add breakpoints (or at least watchpoints which dump things like register context etc)
* `@r/@w` - Memory breakpionts (as above)
* `src` - Support loading Javascript from file to augment the set of supported Commandlets.

Others
* Add support for display exception information in the event of an unhandled signal

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
->help
data:
        cp        :  copy data in memory
        d         :  dump data from memory
        l         :  disassembly listing
        r1        :  read a byte from memory
        r2        :  read a half from memory
        r4        :  read a word from memory
        r8        :  read a double word from memory
        w1        :  write a byte to memory
        w2        :  write a half to memory
        w4        :  write a word to memory
        w8        :  write a double word to memory
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
        mod       :  display module information
        sym       :  look up a symbol information
        vm        :  display virtual memory ranges
misc:
        h         :  command history
        help      :  print this message
        v         :  variable management
thread:
        bt        :  display backtrace information
        t         :  display thread information

For more information about a command use:
        help <cmd>

ret: 0x00000000`00000000 (0)
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
->w8 0x00007fcf`b0000c70 0xaabbccdd`11223344
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
->w8 p 0xaabbccdd11223344
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
->w8 ret 0xaabbccdd`11223344
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
