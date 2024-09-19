/**
 * The script can send strings to frida-inject to write to its stdout or
 * stderr. This can be done either inside the RPC handler for receiving
 * input from frida-inject, or elsewhere at any arbitrary point in the
 * script. We use the following syntax:
 *
 * send(['frida:stdout', 'DATA']);
 * send(['frida:stderr', 'DATA']);
 */
import { Input } from './io/input.js';
import { Output } from './io/output.js';
import { MemoryBps } from './breakpoints/memory.js';
import { Regs } from './breakpoints/regs.js';
import { Format } from './misc/format.js';
import { SrcCmdLet } from './cmdlets/files/src.js';
import { BtCmdLet } from './cmdlets/thread/bt.js';

export const DEFAULT_SRC_PATH: string = `${Process.getHomeDir()}/.cshellrc`;

type InitParams = {
  debug: boolean;
};

rpc.exports = {
  init(stage: string, params: InitParams | null = null) {
    const debug = params?.debug ?? false;
    Output.setDebugging(debug);
    Output.debug(`init - stage: ${stage}, debug: ${debug}`);
    Output.banner();
    Process.setExceptionHandler(exceptionHandler);
    SrcCmdLet.loadInitScript(DEFAULT_SRC_PATH);
    Input.prompt();
  },
  /**
   * Support reading from stdin for communications with the injected script.
   * With the console in its default canonical mode, we will read a line at a
   * time when the user presses enter and send it to a registered RPC method
   * in the script as follows. Here, the data parameter is the string typed
   * by the user including the newline.
   */
  async onFridaStdin(data: string) {
    await Input.read(data);
  },
  /*
   * If getFridaTerminalMode returns "raw", then frida-inject will set the
   * console mode to RAW
   */
  getFridaTerminalMode() {
    return 'raw';
  },
};

function exceptionHandler(details: ExceptionDetails) {
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

  BtCmdLet.printBacktrace(details.context);
  Output.writeln(`${Output.bold(Output.red('*****************'))}`);
  Thread.sleep(1);
}
