export class Line {
  private line: string;
  private pos: number;

  public constructor(val?: string) {
    if (val) {
      this.line = val;
      this.pos = val.length;
    } else {
      this.line = '';
      this.pos = 0;
    }
  }

  public toString(): string {
    return this.line;
  }

  public getLength(): number {
    return this.line.length;
  }

  public getPos(): number {
    return this.pos;
  }

  public peek(len: number): string {
    return this.line.slice(len);
  }

  public push(char: number) {
    this.line = [
      this.line.slice(0, this.pos),
      String.fromCharCode(char),
      this.line.slice(this.pos),
    ].join('');
    this.pos++;
  }

  public backspace() {
    if (this.pos === 0) return;

    this.pos--;
    this.line = [
      this.line.slice(0, this.pos),
      this.line.slice(this.pos + 1),
    ].join('');
  }

  public left() {
    if (this.pos > 0) this.pos--;
  }

  public right() {
    if (this.pos < this.line.length) this.pos++;
  }

  public home() {
    this.pos = 0;
  }

  public end() {
    this.pos = this.line.length;
  }

  public del() {
    if (this.pos >= this.line.length) return;

    this.line = [
      this.line.slice(0, this.pos),
      this.line.slice(this.pos + 1),
    ].join('');
  }

  private isAlpha(idx: number): boolean {
    const line = this.line[idx];
    if (line === undefined) return false;
    return /^[a-zA-Z0-9]$/.test(line);
  }

  public wordLeft() {
    if (this.pos == 0) return;

    this.pos--;
    while (this.pos != 0) {
      if (!this.isAlpha(this.pos - 1) && this.isAlpha(this.pos)) {
        break;
      }
      this.pos--;
    }
  }

  public wordRight() {
    if (this.pos == this.line.length) return;

    this.pos++;
    while (this.pos < this.line.length) {
      if (!this.isAlpha(this.pos) && this.isAlpha(this.pos - 1)) {
        break;
      }
      this.pos++;
    }
  }
}
