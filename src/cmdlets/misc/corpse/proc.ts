export type WaitStatus = {
  exitStatus: number | null;
  termSignal: number | null;
  stopped: boolean;
};

export class Proc {
  private static readonly INT_SIZE: number = 4;
  private static readonly WNOHANG: number = 1;
  public static readonly SIGABRT: number = 6;
  public static readonly SIGKILL: number = 9;

  private fnWaitPid: SystemFunction<number, [number, NativePointer, number]>;
  private fnGetPid: SystemFunction<number, []>;
  private fnKill: SystemFunction<number, [number, number]>;

  public constructor() {
    const pWaitPid = Module.findExportByName(null, 'waitpid');
    if (pWaitPid === null) throw new Error('failed to find waitpid');

    this.fnWaitPid = new SystemFunction(pWaitPid, 'int', [
      'int',
      'pointer',
      'int',
    ]);

    const pGetPid = Module.findExportByName(null, 'getpid');
    if (pGetPid === null) throw new Error('failed to find getpid');

    this.fnGetPid = new SystemFunction(pGetPid, 'int', []);

    const pKill = Module.findExportByName(null, 'kill');
    if (pKill === null) throw new Error('failed to find kill');

    this.fnKill = new SystemFunction(pKill, 'int', ['int', 'int']);
  }

  public kill(pid: number, signal: number) {
    const ret = this.fnKill(pid, signal) as UnixSystemFunctionResult<number>;
    if (ret.value === -1)
      throw new Error(`failed to kill, errno: ${ret.errno}`);
  }

  public getpid(): number {
    const ret = this.fnGetPid() as UnixSystemFunctionResult<number>;
    return ret.value;
  }

  public waitpid(pid: number): WaitStatus {
    const pStatus = Memory.alloc(Proc.INT_SIZE);
    const ret = this.fnWaitPid(
      pid,
      pStatus,
      Proc.WNOHANG,
    ) as UnixSystemFunctionResult<number>;
    if (ret.value === -1)
      throw new Error(`failed to waitpid, errno: ${ret.errno}`);

    if (ret.value === 0) {
      return {
        exitStatus: null,
        termSignal: null,
        stopped: false,
      };
    }

    if (ret.value !== pid)
      throw new Error('failed to waitpid ${pid} got ${ret.value}');
    const status = pStatus.readInt();
    if (Proc.wifExited(status)) {
      const exitStatus = Proc.wExitStatus(status);
      return {
        exitStatus,
        termSignal: null,
        stopped: true,
      };
    } else if (Proc.wifSignalled(status)) {
      const termSignal = Proc.wTermSig(status);
      return {
        exitStatus: null,
        termSignal,
        stopped: true,
      };
    } else {
      throw new Error(`failed to waitpid, pid: ${pid}, status: ${status}`);
    }
  }

  private static wExitStatus(status: number): number {
    return (status & 0xff00) >> 8;
  }

  private static wTermSig(status: number): number {
    return status & 0x7f;
  }

  private static wifExited(status: number): boolean {
    return Proc.wTermSig(status) === 0;
  }

  private static wifSignalled(status: number): boolean {
    const signal = Proc.wTermSig(status);
    return signal !== 0 && signal !== 0x7f;
  }
}
