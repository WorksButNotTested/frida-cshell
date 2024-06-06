import { Output } from './output.js';
import { History } from '../terminal/history.js';
import { Vars } from '../vars/vars.js';
import { CharCode, Vt } from './char.js';
import { CmdLetEdit } from '../commands/cmdlet.js';
import { Parser } from './parser.js';
import { Command } from '../commands/command.js';

enum InputState {
  Default,
  Esc,
  Csi,
}

const QUIT_CHAR: string = 'q';
const ABORT_CHAR: string = 'x';

export class Input {
  private static readonly PROMPT: string = '-> ';
  private static readonly EDIT_PROMPT: string = '. ';

  private static buffer: string = '';
  private static state: InputState = InputState.Default;
  private static edit: CmdLetEdit | null = null;
  private static editSuppressed: boolean = false;

  private constructor() {}

  public static read(buffer: string) {
    this.buffer += buffer;
    while (this.buffer.length !== 0) {
      this.parse();
    }
    this.prompt();
  }

  private static parse() {
    switch (this.state) {
      case InputState.Default:
        this.parseDefault();
        break;
      case InputState.Esc:
        this.ParseEsc();
        break;
      case InputState.Csi:
        this.parseCsi();
        break;
    }
  }

  private static parseDefault() {
    const c = this.pop();
    switch (c) {
      case CharCode.ESC:
        this.state = InputState.Esc;
        break;
      case CharCode.DEL:
        History.getCurrent().backspace();
        break;
      case CharCode.TAB:
        /* TODO - Command Completion */
        break;
      case CharCode.BS:
        History.getCurrent().backspace();
        break;
      case CharCode.CR:
        this.parseEnter();
        break;
      case CharCode.FF:
        Output.writeln(CharCode.CLEAR_SCREEN);
        Output.writeln(CharCode.CURSOR_TOP_LEFT);
        Output.banner();
        break;
      default:
        History.getCurrent().push(c);
        break;
    }
  }

  private static pop(): number {
    const c = this.buffer.charCodeAt(0);
    this.buffer = this.buffer.slice(1);
    return c;
  }

  private static parseEnter() {
    const current = History.getCurrent();
    if (current.getLength() === 0 || current.peek(1).charAt(0) === '#') {
      History.clearLine();
      Output.writeln();
      Input.prompt();
      return;
    }

    try {
      if (this.edit === null) {
        this.parseEnterDefault();
      } else {
        this.parseEnterEdit();
      }
    } catch (error) {
      if (error instanceof Error) {
        Output.writeln(`ERROR: ${error.message}`);
        Output.writeln(`${error.stack}`, true);
      } else {
        Output.writeln(`ERROR: Unknown error`);
      }
    } finally {
      History.clearLine();
    }
  }

  public static prompt() {
    Output.clearLine();
    if (this.edit === null) {
      Output.write(Output.bold(this.PROMPT));
    } else {
      Output.write(Output.bold(this.EDIT_PROMPT));
    }

    const cmd = History.getCurrent();
    const line = cmd.toString();
    Output.write(line);

    const remain = cmd.getLength() - cmd.getPosition();
    const backspaces = String.fromCharCode(CharCode.BS).repeat(remain);
    Output.write(backspaces);
  }

  private static parseEnterDefault() {
    const ret = History.run();
    Vars.setRet(ret);

    /*
     * If our command hasn't caused us to enter edit mode print the result,
     * otherwise we will defer until the edit is complete.
     */
    if (this.edit === null) {
      Output.writeRet();
    }
  }

  private static parseEnterEdit() {
    const edit = this.edit as CmdLetEdit;

    /* Display the line */
    const line = History.getCurrent().toString();
    Output.clearLine();
    Output.writeln(`- ${line}`);

    if (line === QUIT_CHAR) {
      /* Notify the commandlet we are done and exit edit mode */
      try {
        edit.done();
      } finally {
        this.edit = null;
      }
      Output.writeRet();
    } else if (line === ABORT_CHAR) {
      /* Notify the commandlet we aborted and exit edit mode */
      try {
        edit.abort();
      } finally {
        this.edit = null;
      }
      this.edit = null;
      Output.writeRet();
    } else {
      /* Notify the commandlet of the line */
      edit.addCommandLine(line);
    }
  }

  private static ParseEsc() {
    const c = this.pop();
    if (c === CharCode.CSI) {
      this.state = InputState.Csi;
    } else {
      this.state = InputState.Default;
    }
  }

  private static parseCsi() {
    const c = this.pop();
    switch (c) {
      case CharCode.LEFT:
        History.getCurrent().left();
        break;
      case CharCode.RIGHT:
        History.getCurrent().right();
        break;
      case CharCode.UP:
        History.up();
        break;
      case CharCode.DOWN:
        History.down();
        break;
      case CharCode.HOME:
        History.getCurrent().home();
        break;
      case CharCode.END:
        History.getCurrent().end();
        break;
      case Vt.DELETE:
        if (this.popIf(String.fromCharCode(CharCode.VT))) {
          History.getCurrent().del();
        }
        break;
      case Vt.HOME:
        if (this.popIf(String.fromCharCode(CharCode.VT))) {
          History.getCurrent().home();
        } else if (this.popIf(Vt.wordLeft())) {
          History.getCurrent().wordLeft();
        } else if (this.popIf(Vt.wordRight())) {
          History.getCurrent().wordRight();
        }
        break;
      case Vt.END:
        if (this.popIf(String.fromCharCode(CharCode.VT))) {
          History.getCurrent().end();
        }
        break;
    }
    this.state = InputState.Default;
  }

  private static popIf(buf: string): boolean {
    if (this.buffer.slice(0, buf.length) === buf) {
      this.buffer = this.buffer.slice(buf.length);
      return true;
    }
    return false;
  }

  public static suppressEdit(value: boolean) {
    this.editSuppressed = value;
  }

  public static setEdit(edit: CmdLetEdit) {
    if (this.editSuppressed) {
      edit.abort();
    } else {
      Output.writeln(
        `Type '${QUIT_CHAR}' to finish, or '${ABORT_CHAR}' to abort`,
      );
      this.edit = edit;
    }
  }

  public static loadInitScript(): void {
    try {
      const initScript = File.readAllText(`${Process.getHomeDir()}/.cshellrc`);
      const lines = initScript.split('\n');
      for (const line of lines) {
        if (line.length === 0) continue;
        if (line.charAt(0) === '#') continue;
        const parser = new Parser(line.toString());
        const tokens = parser.tokenize();
        const ret = Command.run(tokens);
        Vars.setRet(ret);
        Output.writeln();
      }
    } catch (_) {}
  }
}
