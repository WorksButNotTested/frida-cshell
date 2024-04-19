export class Base64 {
  private static readonly BASE64_CHARS: string =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

  public static encode(input: Uint8Array): string {
    let output: string = '';

    while (input.length !== 0) {
      const buffer = input.slice(0, 3);
      input = input.slice(3);

      const [b1, b2, b3] = buffer;
      const [c1, c2, c3] = [b1 as number, b2 as number, b3 as number];

      const bits: number = (c1 << 16) | (c2 << 8) | c3;
      const e1: number = (bits >> 18) & 0x3f;
      const e2: number = (bits >> 12) & 0x3f;
      const e3: number = isNaN(c2) ? 64 : (bits >> 6) & 0x3f;
      const e4: number = isNaN(c3) ? 64 : bits & 0x3f;

      output +=
        this.BASE64_CHARS.charAt(e1) +
        this.BASE64_CHARS.charAt(e2) +
        (isNaN(c2) ? '=' : this.BASE64_CHARS.charAt(e3)) +
        (isNaN(c3) ? '=' : this.BASE64_CHARS.charAt(e4));
    }

    return output;
  }
}
