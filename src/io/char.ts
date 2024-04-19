export class CharCode {
  public static readonly ESC: number = 0x1b;
  public static readonly CSI: number = CharCode.from('[');

  public static readonly CUP: number = CharCode.from('H');

  public static readonly EL: number = CharCode.from('K');
  public static readonly EL_BACK = CharCode.from('0');
  public static readonly EL_FORWARD = CharCode.from('1');
  public static readonly EL_ALL = CharCode.from('2');

  public static readonly ED: number = CharCode.from('J');
  public static readonly ED_BACK = CharCode.from('0');
  public static readonly ED_FORWARD = CharCode.from('1');
  public static readonly ED_ALL = CharCode.from('2');

  public static readonly BS: number = CharCode.from('\b');
  public static readonly DEL: number = 0x7f;
  public static readonly CR: number = CharCode.from('\r');
  public static readonly TAB: number = 0x09;
  public static readonly LEFT: number = 0x44;
  public static readonly RIGHT: number = 0x43;
  public static readonly UP: number = 0x41;
  public static readonly DOWN: number = 0x42;
  public static readonly HOME: number = 0x48;
  public static readonly END: number = 0x46;
  public static readonly FF: number = 0x0c;
  public static readonly VT = CharCode.from('~');
  public static readonly SGR = CharCode.from('m');
  public static readonly SEPARATOR = CharCode.from(';');

  public static readonly CLEAR_SCREEN: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.ED_ALL,
    CharCode.ED,
  );
  public static readonly CURSOR_TOP_LEFT: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.CUP,
  );
  public static readonly ERASE_LINE: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.EL_ALL,
    CharCode.EL,
  );

  public static readonly RESET: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('0'),
    CharCode.SGR,
  );

  public static readonly BOLD: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('1'),
    CharCode.SGR,
  );

  public static readonly GREEN: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('0'),
    CharCode.SEPARATOR,
    CharCode.from('3'),
    CharCode.from('2'),
    CharCode.SGR,
  );

  public static readonly YELLOW: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('0'),
    CharCode.SEPARATOR,
    CharCode.from('3'),
    CharCode.from('3'),
    CharCode.SGR,
  );

  public static readonly BLUE: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('0'),
    CharCode.SEPARATOR,
    CharCode.from('9'),
    CharCode.from('4'),
    CharCode.SGR,
  );

  public static readonly RED: string = String.fromCharCode(
    CharCode.ESC,
    CharCode.CSI,
    CharCode.from('0'),
    CharCode.SEPARATOR,
    CharCode.from('3'),
    CharCode.from('1'),
    CharCode.SGR,
  );

  public static from(val: string): number {
    if (val.length != 1) {
      throw new Error(`Invalid escape char ${val}`);
    }
    return val.charCodeAt(0);
  }
}

enum VtModifierCode {
  Shift = 1,
  Alt = 2,
  Ctrl = 4,
  Meta = 8,
}

export class Vt {
  public static readonly HOME = CharCode.from('1');
  public static readonly INSERT = CharCode.from('2');
  public static readonly DELETE = CharCode.from('3');
  public static readonly END = CharCode.from('4');
  public static readonly PG_UP = CharCode.from('5');
  public static readonly PG_DOWN = CharCode.from('6');
  public static readonly UP = CharCode.from('A');
  public static readonly DOWN = CharCode.from('B');
  public static readonly RIGHT = CharCode.from('C');
  public static readonly LEFT = CharCode.from('D');
  public static readonly SEPARATOR = CharCode.from(';');

  public static wordLeft(): string {
    const vt = new Vt()
      .add(this.SEPARATOR)
      .addModifier(VtModifierCode.Ctrl)
      .add(this.LEFT);
    return vt.toString();
  }

  public static wordRight(): string {
    const vt = new Vt()
      .add(this.SEPARATOR)
      .addModifier(VtModifierCode.Ctrl)
      .add(this.RIGHT);
    return vt.toString();
  }

  private val: string = '';

  private constructor() {}

  private addModifier(...modifiers: VtModifierCode[]): Vt {
    let val = 1;
    modifiers.forEach(m => {
      val |= m;
    });
    this.val = this.val.concat(String(val));
    return this;
  }

  private add(...val: number[]): Vt {
    this.val = this.val.concat(String.fromCharCode(...val));
    return this;
  }

  private toString() {
    return this.val;
  }
}
