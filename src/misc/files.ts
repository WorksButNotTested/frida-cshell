export class Files {
  private static getRandomString(length: number): string {
    let output: string = '';
    const lookup = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
      const idx = Math.floor(Math.random() * lookup.length);
      const value = lookup[idx];
      output += value;
    }
    return output;
  }

  public static getRandomFileName(extension: string): string {
    const rand = Files.getRandomString(16);
    const filename = `/tmp/${rand}.${extension}`;
    return filename;
  }
}
