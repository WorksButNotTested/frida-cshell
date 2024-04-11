import { Output } from './output.js';
import { History } from './history.js';
import { Vars } from './vars.js';
import { CharCode, Vt } from './char.js';
import { CmdLetEdit } from './cmdlet.js';

enum InputState {
  Default,
  Esc,
  Csi,
}

const QUIT_CHAR: string = 'q';
const ABORT_CHAR: string = 'x';

export class Input {
  private static buffer: string = '';
  private static state: InputState = InputState.Default;
  private static edit: CmdLetEdit | undefined = undefined;

  private constructor() {}

  private static pop(): number {
    const c = this.buffer.charCodeAt(0);
    this.buffer = this.buffer.slice(1);
    return c;
  }

  private static popIf(buf: string): boolean {
    if (this.buffer.slice(0, buf.length) === buf) {
      this.buffer = this.buffer.slice(buf.length);
      return true;
    }
    return false;
  }

  private static parseEnterDefault() {
    const ret = History.run();
    Vars.setRet(ret);

    /*
     * If our command hasn't caused us to enter edit mode print the result,
     * otherwise we will defer until the edit is complete.
     */
    if (this.edit === undefined) {
      Output.writeRet();
    }
  }

  private static parseEnterEdit() {
    const edit = this.edit as CmdLetEdit;

    /* Display the line */
    const line = History.getCurrent().toString();
    Output.clearLine();
    Output.writeln(`- ${line}`);

    if (line == QUIT_CHAR) {
      /* Notify the commandlet we are done and exit edit mode */
      edit.done();
      this.edit = undefined;
      Output.writeRet();
    } else if (line == ABORT_CHAR) {
      /* Notify the commandlet we aborted and exit edit mode */
      edit.abort();
      this.edit = undefined;
      Output.writeRet();
    } else {
      /* Notify the commandlet of the line */
      edit.addCommandLine(line);
    }
  }

  private static parseEnter() {
    try {
      if (this.edit === undefined) {
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

  public static read(buffer: string) {
    this.buffer += buffer;
    while (this.buffer.length !== 0) {
      this.parse();
    }
    if (this.edit === undefined) {
      Output.prompt();
    } else {
      Output.promptEdit();
    }
  }

  public static setEdit(edit: CmdLetEdit) {
    Output.writeln(
      `Type '${QUIT_CHAR}' to finish, or '${ABORT_CHAR}' to abort`,
    );
    this.edit = edit;
  }
}
