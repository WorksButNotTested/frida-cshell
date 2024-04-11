import { CharCode } from './char.js';
import { History } from './history.js';
import { Vars } from './vars.js';

export class Output {
  private static readonly VERSION = '@VER@';

  private static readonly PROMPT: string = '-> ';

  private static readonly EDIT_PROMPT: string = '. ';

  private static readonly shell: string[] = [
    '     _.---._         ',
    ' .\'"".\'/|\\\'.""\'.',
    ":  .' / | \\ '.  :   ",
    "'.'  /  |  \\  '.'   ",
    " `. /   |   \\ .'    ",
    "   `-.__|__.-'       ",
  ];

  private static readonly label: string[] = [
    '          _          _ _    ',
    '         | |        | | |   ',
    ' ____ ___| |__   ___| | |   ',
    "/  _ / __| '_ \\ / _ \\ | | ",
    '| (__\\__ \\ | | | |__/ | |',
    '\\____|___/_| |_|\\___|_|_| ',
  ];

  private static verbose: boolean = false;

  public static banner() {
    this.shell
      .map((s, i) => {
        return { shell: s, label: this.label[i] };
      })
      .forEach(r => {
        this.writeln(this.blue(`${r.shell.padEnd(21, ' ')}${r.label}`));
      });

    this.writeln();
    this.writeln(
      this.bold(
        `CSHELL v${this.VERSION}, running in FRIDA ${Frida.version} using ${Script.runtime}`,
      ),
    );

    this.writeln('Attached to:');
    this.writeln(`\tPID:  ${this.green(Process.id.toString())}`);
    const first = Process.enumerateModules()[0];
    if (first !== undefined) this.writeln(`\tName: ${this.green(first.name)}`);
  }

  public static clearLine() {
    this.write(CharCode.ERASE_LINE);
    this.write(String.fromCharCode(CharCode.CR));
  }

  public static prompt() {
    this.clearLine();
    this.write(this.bold(this.PROMPT));

    const cmd = History.getCurrent();
    const line = cmd.toString();
    this.write(line);

    const remain = cmd.getLength() - cmd.getPos();
    const backspaces = String.fromCharCode(CharCode.BS).repeat(remain);
    this.write(backspaces);
  }

  public static promptEdit() {
    this.write(CharCode.ERASE_LINE);
    this.write(String.fromCharCode(CharCode.CR));
    this.write(this.bold(this.EDIT_PROMPT));

    const cmd = History.getCurrent();
    const line = cmd.toString();
    this.write(line);

    const remain = cmd.getLength() - cmd.getPos();
    const backspaces = String.fromCharCode(CharCode.BS).repeat(remain);
    this.write(backspaces);
  }

  public static writeRet() {
    Output.writeln();
    Output.writeln(`ret: ${Output.bold(Vars.getRet().toString())}`);
  }

  public static write(buffer?: string, verbose: boolean = false) {
    if (verbose && !this.verbose) return;

    if (buffer) {
      const fixed = buffer.replace(new RegExp('\n', 'g'), '\r\n');
      send(['frida:stderr', fixed]);
    }
  }

  public static writeln(buffer?: string, verbose: boolean = false) {
    if (buffer) {
      this.write(`${buffer}\n`, verbose);
    } else {
      this.write('\n', verbose);
    }
  }

  public static setVerbose(dev: boolean) {
    this.verbose = dev;
  }

  public static bold(input: string): string {
    return `${CharCode.BOLD}${input}${CharCode.RESET}`;
  }

  public static blue(input: string): string {
    return `${CharCode.BLUE}${input}${CharCode.RESET}`;
  }

  public static green(input: string): string {
    return `${CharCode.GREEN}${input}${CharCode.RESET}`;
  }

  public static yellow(input: string): string {
    return `${CharCode.YELLOW}${input}${CharCode.RESET}`;
  }
}
