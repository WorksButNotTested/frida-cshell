export class Fork {
  private fnFork: SystemFunction<number, []>;
  public constructor() {
    const pFork = Module.findGlobalExportByName('fork');
    if (pFork === null) throw new Error('failed to find fork');

    this.fnFork = new SystemFunction(pFork, 'int', []);
  }

  public fork(
    parentCallback: (childPid: number) => void,
    childCallback: () => void,
  ): number {
    const ret = this.fnFork() as UnixSystemFunctionResult<number>;
    if (ret.value === -1) {
      throw new Error(`failed to clone, errno: ${ret.errno}`);
    } else if (ret.value === 0) {
      childCallback();
    } else {
      parentCallback(ret.value);
    }

    return ret.value;
  }
}
