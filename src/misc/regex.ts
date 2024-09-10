export class Regex {
  public static readonly MatchAll: RegExp = /^.*$/;

  public static isGlob(input: string): boolean {
    const globRegex = /[[\]?!*]/;
    return globRegex.test(input);
  }

  public static globToRegex(input: string): RegExp | null {
    if (!Regex.isGlob(input)) return new RegExp(`^${input}$`);

    const escaped = input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = escaped
      .replace(/\\\*/g, '.*')
      .replace(/\\\?/g, '.')
      .replace(/\\\[/g, '[')
      .replace(/\\\]/g, ']')
      .replace(/\[!(.*?)]/g, (match, chars) => {
        return '[^' + chars + ']';
      });
    return new RegExp(`^${regex}$`);
  }
}
