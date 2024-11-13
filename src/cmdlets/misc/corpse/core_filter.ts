export class CoreFilter {
  private static readonly CORE_FILTER: string = '/proc/self/coredump_filter';
  public static readonly NEEDED: UInt64 = uint64(0x1ff);
  private constructor() {}

  public static get(): UInt64 {
    const text = File.readAllText(CoreFilter.CORE_FILTER).trimEnd();
    const value = uint64(`0x${text}`);
    return value;
  }

  public static trySet(value: UInt64): boolean {
    const text = `0x${value.toString(16)}`;
    try {
      File.writeAllText(CoreFilter.CORE_FILTER, text);
      return true;
    } catch {
      return false;
    }
  }
}
