export class Dumpable {
  private static readonly PR_SET_DUMPABLE: number = 4;
  private fnSetPrctl: SystemFunction<number, [number, number | UInt64]>;

  public constructor() {
    const pPrctl = Module.findExportByName(null, 'prctl');
    if (pPrctl === null) throw new Error('failed to find prctl');

    this.fnSetPrctl = new SystemFunction(pPrctl, 'int', ['int', 'size_t']);
  }

  public set(value: number) {
    const ret = this.fnSetPrctl(
      Dumpable.PR_SET_DUMPABLE,
      value,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value !== 0)
      throw new Error(`failed to prctl, errno: ${ret.errno}`);
  }
}
