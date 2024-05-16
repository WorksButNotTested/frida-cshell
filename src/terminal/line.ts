export class Line {
  private line: string;
  private pos: number;

  public constructor(val: string | null = null) {
    if (val === null) {
      this.line = '';
      this.pos = 0;
    } else {
      this.line = val;
      this.pos = val.length;
    }
  }

  public toString(): string {
    return this.line;
  }

  public getLength(): number {
    return this.line.length;
  }

  public getPosition(): number {
    return this.pos;
  }

  public peek(len: number): string {
    return this.line.slice(0, len);
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

  public wordLeft() {
    if (this.pos === 0) return;

    this.pos--;
    while (this.pos !== 0) {
      if (!this.isAlpha(this.pos - 1) && this.isAlpha(this.pos)) {
        break;
      }
      this.pos--;
    }
  }

  public wordRight() {
    if (this.pos === this.line.length) return;

    this.pos++;
    while (this.pos < this.line.length) {
      if (!this.isAlpha(this.pos) && this.isAlpha(this.pos - 1)) {
        break;
      }
      this.pos++;
    }
  }

  private isAlpha(idx: number): boolean {
    if (idx >= this.line.length) return false;
    const line = this.line[idx] as string;
    return /^[a-zA-Z0-9]$/.test(line);
  }
}
