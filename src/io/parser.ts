import { Token } from './token.js';

export class Parser {
  private line: string;
  private inEscape = false;

  public constructor(line: string) {
    this.line = line;
  }

  public tokenize(): Token[] {
    const tokens: Token[] = [];
    let inQuoteString = false;
    let inWord = false;
    let current = '';

    while (true) {
      const c = this.popEscaped();
      if (c === null) break;

      switch (c) {
        case '\\':
          if (!inQuoteString)
            throw new Error('\\ outside quoted string is illegal');
          this.inEscape = true;
          break;
        case ' ':
          if (inQuoteString) {
            current += c;
          } else if (inWord) {
            inWord = false;
            tokens.push(new Token(current));
            current = '';
          }
          break;
        case '"':
          if (inQuoteString) {
            inQuoteString = false;
            tokens.push(new Token(`"${current}"`));
            current = '';
          } else {
            inQuoteString = true;
            if (current.length !== 0) {
              tokens.push(new Token(current));
              current = '';
            }
          }
          break;
        default:
          current += c;
          if (!inQuoteString) {
            inWord = true;
          }
          break;
      }
    }
    if (inQuoteString) {
      throw new Error('unescaped quotation');
    }

    if (current.length !== 0) {
      tokens.push(new Token(current));
    }
    return tokens;
  }

  private popEscaped(): string | null {
    const c = this.pop();
    if (!this.inEscape) {
      return c;
    }
    switch (c) {
      case 'n':
        return '\n';
      case 't':
        return '\t';
      default:
        return c;
    }
  }

  private pop(): string | null {
    if (this.line.length === 0) return null;
    const c = this.line[0] as string;
    this.line = this.line.slice(1);
    return c;
  }
}
