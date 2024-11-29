import { CharCode } from './char.js';
import { Vars } from '../vars/vars.js';
import { DEFAULT_SRC_PATH } from '../entrypoint.js';
import { Format } from '../misc/format.js';
import { APP_VERSION, GIT_COMMIT_HASH } from '../version.js';

export class Output {
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

  private static debugging: boolean = false;
  private static indent: boolean = false;
  private static filter: RegExp | null = null;
  private static logFile: string | null = null;
  private static log: File | null = null;
  private static suppressed: boolean = false;

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
        [
          `CSHELL: v${APP_VERSION}`,
          `COMMIT: ${GIT_COMMIT_HASH}`,
          `FRIDA: ${Frida.version}`,
          `RUNTIME: ${Script.runtime}`,
        ].join('\n'),
      ),
    );
    this.writeln(`init script: ${Output.bold(DEFAULT_SRC_PATH)}`);

    this.writeln('Attached to:');
    this.writeln(`\tPID:  ${this.green(Process.id.toString())}`);

    const modules = Process.enumerateModules();
    if (modules.length === 0) return;

    const first = modules[0] as Module;
    this.writeln(`\tName: ${this.green(first.name)}`);
  }

  public static debug(buffer: string | null) {
    this.dowrite(`${buffer ?? ''}\n`, true, false);
  }

  public static writeln(buffer: string | null = null, filter: boolean = false) {
    this.dowrite(`${buffer ?? ''}\n`, false, filter);
  }

  public static write(buffer: string | null = null, filter: boolean = false) {
    this.dowrite(buffer, false, filter);
  }

  private static dowrite(
    buffer: string | null = null,
    debug: boolean,
    filter: boolean,
  ) {
    if (debug && !this.debugging) return;
    if (this.suppressed) return;
    if (buffer === null) return;

    const filterExpression = (l: string) =>
      filter === false ||
      l.trim().length === 0 ||
      Output.filter === null ||
      Output.filter.test(l);

    let text = '';
    if (this.indent) {
      if (buffer.endsWith('\n')) {
        const lines = buffer.slice(0, buffer.length - 1).split('\n');
        const fixed = lines
          .filter(filterExpression)
          .join(`\r\n${Output.yellow('| ')}`);
        text = `${Output.yellow('| ')}${fixed}\r\n`;
      } else {
        const lines = buffer.split('\n');
        const fixed = lines
          .filter(filterExpression)
          .join(`\r\n${Output.yellow('| ')}`);
        text = `${Output.yellow('| ')}${fixed}`;
      }
    } else {
      const lines = buffer.split('\n');
      text = lines.filter(filterExpression).join(`\r\n`);
    }

    if (this.log !== null) {
      const uncoloured = Format.removeColours(text);
      this.log.write(uncoloured);
      this.log.flush();
    }
    send(['frida:stderr', text]);
  }

  public static writeRaw(bytes: ArrayBuffer) {
    send(['frida:stdout'], bytes);
  }

  public static clearLine() {
    this.write(CharCode.ERASE_LINE);
    this.write(String.fromCharCode(CharCode.CR));
  }

  public static writeRet() {
    Output.writeln();
    Output.writeln(`ret: ${Output.bold(Vars.getRet().toString())}`);
  }

  public static getDebugging(): boolean {
    return this.debugging;
  }

  public static setDebugging(debugging: boolean) {
    this.debugging = debugging;
  }

  public static setIndent(indent: boolean) {
    this.indent = indent;
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

  public static red(input: string): string {
    return `${CharCode.RED}${input}${CharCode.RESET}`;
  }

  public static setFilter(filter: string) {
    this.filter = new RegExp(filter);
  }

  public static clearFilter() {
    this.filter = null;
  }

  public static isFiltered() {
    return this.filter !== null;
  }

  public static setLog(logFile: string) {
    this.logFile = logFile;
    this.log = new File(logFile, 'w');
  }

  public static clearLog(): string | null {
    if (this.log !== null) {
      const pos = this.log.tell();
      Output.writeln(`Wrote  ${Output.blue(pos.toString())} bytes to log.`);
      this.log.flush();
      this.log.close();
      this.log = null;
    }
    return this.logFile;
  }

  public static suppress(suppressed: boolean) {
    this.suppressed = suppressed;
  }

  public static isSuppressed(): boolean {
    return this.suppressed;
  }
}
