export class SeLinux {
  private static readonly SELINUX_PATH: string = '/sys/fs/selinux/enforce';

  private constructor() {}

  public static isPermissive(): boolean {
    try {
      const value = File.readAllText(SeLinux.SELINUX_PATH).trimEnd();
      if (value === '0') return true;
      return false;
    } catch {
      return false;
    }
  }
}
