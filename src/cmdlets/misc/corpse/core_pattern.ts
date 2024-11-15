export class CorePattern {
  private static readonly CORE_PATTERN: string =
    '/proc/sys/kernel/core_pattern';
  private static readonly CORE_USES_PID: string =
    '/proc/sys/kernel/core_uses_pid';

  private constructor() {}

  public static get(): string {
    const value = File.readAllText(CorePattern.CORE_PATTERN).trimEnd();
    if (value.startsWith('|'))
      throw new Error(
        `core pattern must not start with '|' - value: '${value}'`,
      );

    if (value.indexOf('%') !== -1)
      throw new Error(`core pattern must not contain '%' - value: '${value}'`);

    return value;
  }

  public static appendPid(): boolean {
    try {
      const text = File.readAllText(CorePattern.CORE_USES_PID).trimEnd();
      const value = uint64(text);
      if (value.equals(0)) {
        return false;
      } else {
        return true;
      }
    } catch {
      return false;
    }
  }
}
