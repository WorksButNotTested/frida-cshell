export class CoreFilter {
  private static readonly CORE_FILTER: string = '/proc/self/coredump_filter';
  public static readonly NEEDED: UInt64 = uint64(0x1ff);
  private constructor() {}

  public static set(value: UInt64) {
    const text = `0x${value.toString(16)}`;
    try {
      File.writeAllText(CoreFilter.CORE_FILTER, text);
    } catch (error) {
      throw new Error(`failed to set core filter, ${error}`);
    }
  }
}
