export class Dumpable {
  private static readonly PR_GET_DUMPABLE: number = 3;
  private static readonly PR_SET_DUMPABLE: number = 4;
  private fnGetPrctl: SystemFunction<number, [number]>;
  private fnSetPrctl: SystemFunction<number, [number, number | UInt64]>;

  public constructor() {
    const pPrctl = Module.findExportByName(null, 'prctl');
    if (pPrctl === null) throw new Error('failed to find prctl');

    this.fnGetPrctl = new SystemFunction(pPrctl, 'int', ['int']);

    this.fnSetPrctl = new SystemFunction(pPrctl, 'int', ['int', 'size_t']);
  }

  public get(): number {
    const ret = this.fnGetPrctl(
      Dumpable.PR_GET_DUMPABLE,
    ) as UnixSystemFunctionResult<number>;
    return ret.value;
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
