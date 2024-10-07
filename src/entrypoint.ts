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
import { SrcCmdLet } from './cmdlets/files/src.js';
import { Exception } from './misc/exception.js';
import { Version } from './misc/version.js';
import { Format } from './misc/format.js';

export const DEFAULT_SRC_PATH: string = `${Process.getHomeDir()}/.cshellrc`;

type InitParams = {
  debug: boolean;
};

rpc.exports = {
  async init(stage: string, params: InitParams | null = null) {
    if (params != null) {
      Output.writeln(`params: ${JSON.stringify(params)}`);
      Output.setDebugging(params.debug);
    }
    Output.debug(`init - stage: ${stage}`);
    Output.banner();
    Process.setExceptionHandler(Exception.exceptionHandler);
    await SrcCmdLet.loadInitScript(DEFAULT_SRC_PATH);
    Input.prompt();
  },
  /**
   * Support reading from stdin for communications with the injected script.
   * With the console in its default canonical mode, we will read a line at a
   * time when the user presses enter and send it to a registered RPC method
   * in the script as follows. Here, the data parameter is the string typed
   * by the user including the newline.
   */
  async onFridaStdin(data: string, bytes: ArrayBuffer | null) {
    if (bytes === null) {
      await Input.read(Format.toByteArray(data));
    } else {
      await Input.read(bytes);
    }
  },
  /*
   * If getFridaTerminalMode returns "raw", then frida-inject will set the
   * console mode to RAW
   */
  getFridaTerminalMode() {
    if (Version.VERSION >= Version.BINARY_MODE_MIN_VERSION) {
      return 'binary';
    } else {
      return 'raw';
    }
  },
};
