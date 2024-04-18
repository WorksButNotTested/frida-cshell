/**
 * The script can send strings to frida-inject to write to its stdout or
 * stderr. This can be done either inside the RPC handler for receiving
 * input from frida-inject, or elsewhere at any arbitrary point in the
 * script. We use the following syntax:
 *
 * send(['frida:stdout', 'DATA']);
 * send(['frida:stderr', 'DATA']);
 */
import { Input } from './input.js';
import { Output } from './output.js';
import { Util } from './util.js';

type InitParams = {
  verbose: boolean | undefined;
};

rpc.exports = {
  init(stage: string, params: InitParams | undefined) {
    const verbose = params?.verbose ?? false;
    Output.setVerbose(verbose);
    Output.writeln(`init - stage: ${stage}, verbose: ${verbose}`, true);
    Output.banner();
    Process.setExceptionHandler(Util.exceptionHandler);
    Input.prompt();
  },
  /**
   * Support reading from stdin for communications with the injected script.
   * With the console in its default canonical mode, we will read a line at a
   * time when the user presses enter and send it to a registered RPC method
   * in the script as follows. Here, the data parameter is the string typed
   * by the user including the newline.
   */
  onFridaStdin(data: string) {
    Input.read(data);
  },
  /*
   * If getFridaTerminalMode returns "raw", then frida-inject will set the
   * console mode to RAW
   */
  getFridaTerminalMode() {
    return 'raw';
  },
};
