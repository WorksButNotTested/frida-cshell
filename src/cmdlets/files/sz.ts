import { CmdLetBase } from '../../commands/cmdlet.js';
import { Input } from '../../io/input.js';
import { Output } from '../../io/output.js';
import { Token } from '../../io/token.js';
import { InputBuffer } from '../../io/zmodem/input.js';
import { OutputBuffer } from '../../io/zmodem/output.js';
import { Sz } from '../../io/zmodem/sz.js';
import { Zmodem } from '../../io/zmodem/zmodem.js';
import { Files } from '../../misc/files.js';
import { Version } from '../../misc/version.js';
import { Var } from '../../vars/var.js';

export class SzCmdLet extends CmdLetBase {
  name = 'sz';
  category = 'files';
  help = 'send a file using Z-Modem';

  private static readonly USAGE: string = `Usage: sz

cat file - send file
  file      the file to send`;

  public override runSync(_tokens: Token[]): Var {
    throw new Error("can't run in synchronous mode");
  }

  public override async run(tokens: Token[]): Promise<Var> {
    const vars = this.transform(tokens, [this.parseLiteral]);
    if (vars === null) return this.usage();

    const [filePath] = vars as [string];
    Output.writeln(`Sending file: ${Output.green(filePath)}`);

    const debugFileName = Files.getRandomFileName('debug');
    let debug = (_msg: string) => {};

    if (Output.getDebugging()) {
      Output.debug(`writing debug to: ${debugFileName}`);
      const debugFile = new File(debugFileName, 'w');
      debug = (msg: string) => {
        debugFile.write(`${msg}\n`);
        debugFile.flush();
      };
    }

    debug('Starting transmission');

    Output.writeln(`Transmission will start in 2 seconds....`);
    Output.writeln();

    const input = new InputBuffer(debug);
    const output = new OutputBuffer(debug);

    Input.setInterceptRaw(input);
    try {
      await Sz.sleep(2000);
      const zmodem = new Zmodem(input, output, debug);
      await zmodem.send(filePath);
    } catch (error) {
      if (error instanceof Error) {
        debug(`Error: ${error.message}`);
        debug(`Stack: ${error.stack}`);
      } else {
        debug(`Error: Unknown error`);
      }
    } finally {
      Input.setInterceptRaw(null);
      this.checkDebugFile(debugFileName);
    }
    return Var.ZERO;
  }

  private checkDebugFile(debugFileName: string) {
    Output.debug('ZModem output...');
    try {
      const debugFile = new File(debugFileName, 'r');
      for (
        let line = debugFile.readLine();
        line.length != 0;
        line = debugFile.readLine()
      ) {
        Output.debug(`\t${Output.yellow(line.trimEnd())}`);
      }
    } finally {
      Output.debug('ZModem output complete');
    }
  }

  public usage(): Var {
    Output.writeln(SzCmdLet.USAGE);
    return Var.ZERO;
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux':
        if (Version.VERSION >= Version.BINARY_MODE_MIN_VERSION) {
          return true;
        } else {
          return false;
        }
      case 'windows':
      case 'barebone':
      case 'darwin':
      case 'freebsd':
      case 'qnx':
      default:
        return false;
    }
  }
}
