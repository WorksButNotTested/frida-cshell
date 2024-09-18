import { Output } from './output.js';
import { History } from '../terminal/history.js';
import { Vars } from '../vars/vars.js';
import { CharCode, Vt } from './char.js';

enum InputState {
  Default,
  Esc,
  Csi,
}

const QUIT_CHAR: string = 'q';
const ABORT_CHAR: string = 'x';
const CLEAR_CHAR: string = 'c';

export class Input {
  public static readonly PROMPT: string = '-> ';
  public static readonly FILTERED_PROMPT: string = '~> ';
  private static readonly EDIT_PROMPT: string = '. ';

  private static buffer: string = '';
  private static state: InputState = InputState.Default;
  private static interceptLine: InputInterceptLine | null = null;
  private static interceptRaw: InputInterceptRaw | null = null;
  private static interceptSuppressed: boolean = false;

  private constructor() {}

  public static async read(buffer: string) {
    if (this.interceptRaw !== null) {
      if (this.buffer.length === 0) {
        this.interceptRaw.addRaw(buffer);
        this.buffer = '';
      }
      this.interceptRaw.addRaw(buffer);
    } else {
      this.buffer += buffer;
      while (this.buffer.length !== 0) {
        await this.parse();
      }
      this.prompt();
    }
  }

  private static async parse() {
    switch (this.state) {
      case InputState.Default:
        await this.parseDefault();
        break;
      case InputState.Esc:
        this.ParseEsc();
        break;
      case InputState.Csi:
        this.parseCsi();
        break;
    }
  }

  private static async parseDefault() {
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
        await this.parseEnter();
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

  private static async parseEnter() {
    const current = History.getCurrent();
    if (current.getLength() === 0 || current.peek(1).charAt(0) === '#') {
      History.clearLine();
      Output.writeln();
      Input.prompt();
      return;
    }

    try {
      if (this.interceptLine === null) {
        await this.parseEnterDefault();
      } else {
        this.parseEnterEdit();
      }
    } catch (error) {
      if (error instanceof Error) {
        Output.writeln(`ERROR: ${error.message}`);
        Output.verboseWriteln(`${error.stack}`);
      } else {
        Output.writeln(`ERROR: Unknown error`);
      }
    } finally {
      History.clearLine();
    }
  }

  public static prompt() {
    Output.clearLine();
    if (this.interceptLine === null) {
      if (Output.isFiltered()) {
        Output.write(Output.bold(this.FILTERED_PROMPT));
      } else {
        Output.write(Output.bold(this.PROMPT));
      }
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

  private static async parseEnterDefault() {
    const ret = await History.run();
    Vars.setRet(ret);

    /*
     * If our command hasn't caused us to enter edit mode print the result,
     * otherwise we will defer until the edit is complete.
     */
    if (this.interceptLine === null) {
      Output.writeRet();
    }
  }

  private static parseEnterEdit() {
    const edit = this.interceptLine as InputInterceptLine;

    /* Display the line */
    const line = History.getCurrent().toString();
    Output.clearLine();
    Output.writeln(`- ${line}`);

    if (line === QUIT_CHAR) {
      /* Notify the commandlet we are done and exit edit mode */
      try {
        edit.done();
      } finally {
        this.interceptLine = null;
      }
      Output.writeRet();
    } else if (line === CLEAR_CHAR) {
      /* Notify the commandlet we cleared and exit edit mode */
      try {
        edit.clear();
      } finally {
        this.interceptLine = null;
      }
      Output.writeRet();
    } else if (line === ABORT_CHAR) {
      /* Notify the commandlet we aborted and exit edit mode */
      try {
        edit.abort();
      } finally {
        this.interceptLine = null;
      }
      Output.writeRet();
    } else {
      /* Notify the commandlet of the line */
      edit.addLine(line);
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

  public static suppressIntercept(value: boolean) {
    this.interceptSuppressed = value;
  }

  public static setInterceptLine(interceptLine: InputInterceptLine) {
    if (this.interceptSuppressed) {
      interceptLine.abort();
    } else {
      if (this.interceptRaw !== null) {
        this.interceptRaw.abort();
        this.interceptRaw = null;
      }
      Output.writeln(
        `Type '${QUIT_CHAR}' to finish, '${CLEAR_CHAR}' to clear, or '${ABORT_CHAR}' to abort`,
      );
      this.interceptLine = interceptLine;
    }
  }

  public static setInterceptRaw(interceptRaw: InputInterceptRaw | null) {
    if (interceptRaw === null) {
      this.interceptRaw = null;
      return;
    }
    if (this.interceptSuppressed) {
      interceptRaw.abort();
    } else {
      if (this.interceptLine !== null) {
        this.interceptLine.abort();
        this.interceptLine = null;
      }
      this.interceptRaw = interceptRaw;
    }
  }
}

export interface InputInterceptLine {
  addLine(line: string): void;
  clear(): void;
  done(): void;
  abort(): void;
}

export interface InputInterceptRaw {
  addRaw(c: string): void;
  abort(): void;
}
