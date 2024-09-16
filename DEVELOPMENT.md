# Development
All of the commands supported by `frida-cshell` are implemented as commandlets. A list of available commands can be seen by running `help`:
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
# Interface
Commandlets all implement the following interface:
```js
export abstract class CmdLet {
  public abstract readonly category: string;
  public abstract readonly name: string;
  public abstract readonly help: string;
  public readonly visible: boolean = true;
  public abstract usage(): Var;
  public abstract run(tokens: Token[]): Var;
  public isSupported(): boolean {
    return true;
  }
}
```
## Members
* The `category` field is used to group the commandlets in the `help` output.
* The `name` field is used to determine the command name which must be entered by the user.
* The `help` field contains the string printed alongside the command in the `help` output
* The `visible` field dictates whether the commandlet is visible in the help menu.
* The `usage` method is called when the user enters `help <cmd name>` to print more detailed usage information to the console.
* The `run` method is called when the user executes the command, it is passed the `tokens` which have been passed as arguments.
* The `isSupported` method is called during initialization to allow it to determine whether it should be ignored, e.g. if the command only works on a subset of operating systems or architectures.

# Tokens
The token class represents each token the user has entered on the command line (each separated by whitespace). The `getLiteral` method can be used to retrieve the original string which the user typed. Otherwise, the `toVar` method can be used to interpret the value as a `Var` type.
```js
export class Token {
  ...
  public getLiteral(): string;
  public toVar(): Var | null;
  ...
}
```

# Var
The `Var` class represents the parameters passed to a commandlet after their interpretation by `frida-cshell`. Each can be accessed as either a `UInt64` or a `NativePointer` type. Note that `UInt64` is used in place of `number` since the number type loses precision handling numbers greater than `2^52`.

When converting tokens, `frida-cshell` will automatically convert several types of input:
1. Double-quoted strings will be interpreted and copied into memory. The `toPointer` method of these can then be used to reference the UTF-8 string data.
2. Numeric types are parsed from their string form. These can either be:
   * Hexadecimal numbers with a `0x` or `0X` prefix
   * Decimal numbers with a `0d` or `0D` prefix
   * Octal numbers with a `0o` or `0O` prefix
   * Decimal numbers without a prefix
3. Register names starting with a `$` prefix (these are only available during breakpoint execution).
4. Names variables which have been created using the `v` command.
5. Exported function names
6. Debug symbol names

Each of these types of input is handled transparently by `frida-cshell` and passed to the commandlet in a single consistent form.

```js
export class Var {
  ...
  public toPointer(): NativePointer;
  public toU64(): UInt64;
  ...
}
```

Similarly, the `run` method of each commandlet is expected to return a `Var` type which can subsequently be referenced by the user using the `ret` keyword in the execution of the next command.

# Parsing
Below is snippet of the `dump` commandlet showing how it parses it's three arguments. The first is the address which to dump and the second is the length, and the fourth the width. Note that the first argument is also used as the return value for this commandlet. Note also that the second argument is also converted from a `UInt64` to a `number` type, since this is what is reqired by the `hexdump` function called by `this.dump`. This is used in many commands where the parameter is likely to be a small number and therefore loss of precision is not a concern.
```js
  public runSync(tokens: Token[]): Var {
    const vars = this.transformOptional(
      tokens,
      [this.parseVar],
      [this.parseVar, this.parseWidth],
    );
    if (vars === null) return this.usage();
    const [[v0], [v1, v2]] = vars as [[Var], [Var | null, number | null]];

    const address = v0.toPointer();
    const count = v1 === null ? DEFAULT_COUNT : v1.toU64().toNumber();
    const width = v2 === null ? 1 : v2;
    this.dump(address, count, width);
    return v0;
  }

  private dump(address: NativePointer, count: number, width: number = 1) {
        ...
  }
```
# Scripts
Whilst scripts can be written in Typescript and added to the project, for more adhoc use cases, it is also possible to write commandlets in JavaScript and load them dynamically into `frida-cshell`. An example script can be seen [here](src.js). Note that all of the exported classes within `frida-cshell` should also be available to these scripts. These scripts can be loaded using the `src` command, simply passing the filename to be loaded.

# Initialization
To automate this process, it is also possible to provide a [`.cshellrc`](assets/initrd/.cshellrc) file in your home directory containing commands to execute during start-up. This can include the use of the `src` command and the subsequent execution of any commandlets loaded as a result.
