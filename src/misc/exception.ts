import { BpMemory } from '../breakpoints/memory.js';
import { Regs } from '../breakpoints/regs.js';
import { Output } from '../io/output.js';
import { Format } from './format.js';

export class Exception {
  private static propagateExceptions: boolean = true;

  public static exceptionHandler(details: ExceptionDetails): boolean {
    if (Exception.propagateExceptions) return false;
    if (details.type === 'access-violation') {
      const address = details.memory?.address;
      if (address !== undefined) {
        if (BpMemory.addressHasBreakpoint(address)) {
          /*
           * Return false since we want to allow the memory breakpoint handler
           * to fire
           */
          return false;
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

    Exception.printBacktrace(details.context);
    Output.writeln(`${Output.bold(Output.red('*****************'))}`);
    Thread.sleep(1);
    return true;
  }

  public static propagate() {
    Exception.propagateExceptions = true;
  }

  public static suppress() {
    Exception.propagateExceptions = false;
  }

  public static printBacktrace(ctx: CpuContext) {
    Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .forEach(s => {
        const prefix = s.moduleName === null ? '' : `${s.moduleName}!`;
        const name = `${prefix}${s.name}`;
        let fileInfo = '';
        if (s.fileName !== null && s.lineNumber !== null) {
          if (s.fileName.length !== 0 && s.lineNumber !== 0) {
            fileInfo = `\t${Output.blue(s.fileName)}:${Output.blue(s.lineNumber.toString())}`;
          }
        }
        Output.writeln(
          [
            Output.green(name.padEnd(40, '.')),
            Output.yellow(Format.toHexString(s.address)),
            fileInfo,
          ].join(' '),
          true,
        );
      });
  }
}
