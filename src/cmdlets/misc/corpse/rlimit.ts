export type Rlimits = {
  sortLimit: Int64;
  hardLimit: Int64;
};

export class Rlimit {
  private static readonly RLIMIT_CORE: number = 4;
  private fnSetrlimit: SystemFunction<number, [number, NativePointer]>;

  public static readonly UNLIMITED: Rlimits = {
    sortLimit: int64(-1),
    hardLimit: int64(-1),
  };

  public constructor() {
    const pSetrlimit = Module.findGlobalExportByName('setrlimit');
    if (pSetrlimit === null) throw new Error('failed to find setrlimit');

    this.fnSetrlimit = new SystemFunction(pSetrlimit, 'int', [
      'int',
      'pointer',
    ]);
  }

  public set(rlimits: Rlimits) {
    const buffer = Memory.alloc(Process.pointerSize * 2);
    let cursor = buffer;
    cursor.writeLong(rlimits.sortLimit);
    cursor = cursor.add(Process.pointerSize);
    cursor.writeLong(rlimits.hardLimit);
    cursor = cursor.add(Process.pointerSize);

    const ret = this.fnSetrlimit(
      Rlimit.RLIMIT_CORE,
      buffer,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0)
      throw new Error(`failed to setrlimit, errno: ${ret.errno}`);
  }

  public isUnlimited(rlimits: Rlimits): boolean {
    if (!rlimits.sortLimit.equals(Rlimit.UNLIMITED.sortLimit)) return false;
    if (!rlimits.hardLimit.equals(Rlimit.UNLIMITED.hardLimit)) return false;
    return true;
  }
}
