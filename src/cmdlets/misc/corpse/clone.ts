export class Clone {
  private static readonly SIGCHLD: number = 17;
  private static readonly CLONE_CLEAR_SIGHAND: number = 0x100000000;
  private fnSyscall: SystemFunction<
    number,
    [number | UInt64, number, NativePointer, NativePointer]
  >;
  public constructor() {
    const pSyscall = Module.findExportByName(null, 'syscall');
    if (pSyscall === null) throw new Error('failed to find syscall');

    this.fnSyscall = new SystemFunction(pSyscall, 'int', [
      'size_t',
      'int',
      'pointer',
      'pointer',
    ]);
  }

  public clone(
    parentCallback: (childPid: number) => void,
    childCallback: () => void,
  ): number {
    const syscallNumber = Clone.getCloneSyscallNumber();
    const flags = Clone.SIGCHLD | Clone.CLONE_CLEAR_SIGHAND;
    const ret = this.fnSyscall(
      syscallNumber,
      flags,
      ptr(0),
      ptr(0),
    ) as UnixSystemFunctionResult<number>;
    if (ret.value === -1) {
      throw new Error(`failed to clone, errno: ${ret.errno}`);
    } else if (ret.value === 0) {
      childCallback();
    } else {
      parentCallback(ret.value);
    }

    return ret.value;
  }

  private static getCloneSyscallNumber(): number {
    switch (Process.arch) {
      case 'arm':
        return 120;
      case 'arm64':
        return 220;
      case 'ia32':
        return 120;
      case 'x64':
        return 56;
      default:
        throw new Error(`unsupported architecutre: ${Process.arch}`);
    }
  }
}
