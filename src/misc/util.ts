import { MemoryBps } from '../breakpoints/memory.js';
import { Output } from '../io/output.js';
import { Regs } from '../breakpoints/regs.js';
import { Format } from '../misc/format.js';

export class Util {
  public static maxPtr(a: NativePointer, b: NativePointer): NativePointer {
    if (a.compare(b) > 0) return a;
    else return b;
  }

  public static minPtr(a: NativePointer, b: NativePointer): NativePointer {
    if (a.compare(b) < 0) return a;
    else return b;
  }

  public static exceptionHandler(details: ExceptionDetails) {
    if (details.type === 'access-violation') {
      const address = details.memory?.address;
      if (address !== undefined) {
        if (MemoryBps.containsAddress(address)) {
          return;
        }
      }
    }
    Output.writeln();
    Output.writeln(`${Output.bold(Output.red('*** EXCEPTION ***'))}`);
    Output.writeln();
    Output.writeln(`${Output.bold('type:   ')} ${details.type}`);
    Output.writeln(
      `${Output.bold('address:')} ${Format.toHexString(details.address)}`,
    );
    if (details.memory !== undefined) {
      Output.writeln(
        `${Output.bold('memory: ')} ${Format.toHexString(details.memory.address)} [${details.memory.operation}]`,
      );
    }
    Output.writeln();
    const regs = Regs.getRegs(details.context);
    Output.writeln(Output.bold('Registers:'));
    for (const [key, value] of regs) {
      Output.writeln(`${Output.bold(key.padEnd(4, ' '))}: ${value.toString()}`);
    }
    Output.writeln();
    Output.writeln(`${Output.bold(Output.red('*****************'))}`);
    Thread.sleep(1);
  }
}
