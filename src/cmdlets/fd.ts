import { CmdLet } from '../commands/cmdlet.js';
import { Output } from '../io/output.js';
import { Token } from '../io/token.js';
import { Var } from '../vars/var.js';

enum DtType {
  DT_UNKNOWN = 0 /* The file type is unknown. */,
  DT_FIFO = 1 /* The file is a named pipe (FIFO). */,
  DT_CHR = 2 /* The file is a character device. */,
  DT_DIR = 4 /* The file is a directory. */,
  DT_BLK = 6 /* The file is a block device. */,
  DT_REG = 8 /* The file is a regular file. */,
  DT_LNK = 10 /* The file is a symbolic link. */,
  DT_SOCK = 12 /* The file is a socket. */,
  DT_WHT = 14 /* The file is a BSD whiteout. */,
}

const USAGE: string = `Usage: fd
fd - show all the open file descriptors for the process

fd idx - show the given file descriptor
  idx    the number of file descriptor to show
`;

type Fds = {
  [key: number]: string;
};

export class FdCmdLet extends CmdLet {
  name = 'fd';
  category = 'misc';
  help = 'display file descriptors';

  private static readonly PATH_MAX: number = 4096;
  private static readonly F_GETFD: number = 1;
  private static readonly F_GETPATH: number = 50;

  private pOpenDir: NativePointer | null = null;
  private pCloseDir: NativePointer | null = null;
  private pReadDir: NativePointer | null = null;
  private pReadLink: NativePointer | null = null;

  private pGetDTableSize: NativePointer | null = null;
  private pFcntl: NativePointer | null = null;

  public usage(): Var {
    Output.write(USAGE);
    return Var.ZERO;
  }

  private readFdsLinux(): Fds {
    const result: Fds = {};

    if (
      this.pOpenDir === null ||
      this.pCloseDir === null ||
      this.pReadDir === null ||
      this.pReadLink === null
    )
      throw new Error('Failed to find necessary native functions');

    // DIR *opendir(const char *name);
    const fnOpenDir = new SystemFunction(this.pOpenDir, 'pointer', ['pointer']);
    // int closedir(DIR *dirp);
    const fnCloseDir = new SystemFunction(this.pCloseDir, 'int', ['pointer']);
    // struct dirent *readdir(DIR *dirp);
    const fnReadDir = new SystemFunction(this.pReadDir, 'pointer', ['pointer']);
    // ssize_t readlink(const char *restrict pathname, char *restrict buf,
    //                     size_t bufsiz);
    const fdReadLink = new SystemFunction(this.pReadLink, 'int', [
      'pointer',
      'pointer',
      'int',
    ]);

    const path = Memory.allocUtf8String('/proc/self/fd/');

    const { value: dir, errno: openErrno } = fnOpenDir(
      path,
    ) as UnixSystemFunctionResult<NativePointer>;
    if (dir.equals(ptr(0)))
      throw new Error(`Failed to opendir /proc/self/fd, errno: ${openErrno}`);

    while (true) {
      const { value: dirent, errno: readDirErrno } = fnReadDir(
        dir,
      ) as UnixSystemFunctionResult<NativePointer>;
      if (dirent.equals(ptr(0))) {
        if (readDirErrno === 0) break;
        else
          throw new Error(
            `Failed to readdir /proc/self/fd, errno: ${readDirErrno}`,
          );
      }

      // struct dirent {
      //     ino_t          d_ino;       /* Inode number */
      //     off_t          d_off;       /* Not an offset; see below */
      //     unsigned short d_reclen;    /* Length of this record */
      //     unsigned char  d_type;      /* Type of file; not supported
      //                                   by all filesystem types */
      //     char           d_name[256]; /* Null-terminated filename */
      // };
      const pType = dirent
        .add(Process.pointerSize)
        .add(Process.pointerSize)
        .add(2);
      const type = pType.readU8();
      if (type !== DtType.DT_LNK) continue;

      const pName = dirent
        .add(Process.pointerSize)
        .add(Process.pointerSize)
        .add(2)
        .add(1);
      const name = pName.readUtf8String();
      if (name === null) throw new Error('Failed to read link name');

      const fd = parseInt(name);
      if (isNaN(fd)) throw new Error(`Failed to parse fd: ${name}`);

      const srcBuff = Memory.allocUtf8String(`/proc/self/fd/${name}`);

      const destBuff = Memory.alloc(FdCmdLet.PATH_MAX + 1);
      const { value: ssize, errno: readLinkErrno } = fdReadLink(
        srcBuff,
        destBuff,
        FdCmdLet.PATH_MAX,
      ) as UnixSystemFunctionResult<number>;
      if (ssize < 0 || ssize >= FdCmdLet.PATH_MAX)
        throw new Error(
          `Failed to readlink: ${srcBuff}, errno: ${readLinkErrno}`,
        );

      const dest = destBuff.readUtf8String();
      if (dest === null) throw new Error('Failed to read link target');

      result[fd] = dest;
    }

    const { value: ret, errno: closeErrno } = fnCloseDir(
      dir,
    ) as UnixSystemFunctionResult<number>;
    if (ret !== 0)
      throw new Error(`Failed to closedir /proc/self/fd, errno: ${closeErrno}`);

    return result;
  }

  private readFdsUnix(): Fds {
    const result: Fds = {};

    if (this.pGetDTableSize === null || this.pFcntl === null)
      throw new Error('Failed to find necessary native functions');

    // int getdtablesize(void);
    const fnGetDtableSize = new SystemFunction(this.pGetDTableSize, 'int', []);
    // int fcntl(int fd, int cmd, ...);
    const fnFcntl = new NativeFunction(this.pFcntl, 'int', [
      'int',
      'int',
      '...',
      'pointer',
    ]);

    const { value: maxFd, errno: getDtableErrno } =
      fnGetDtableSize() as UnixSystemFunctionResult<number>;
    if (maxFd === -1)
      throw new Error(`Failed to getdtablesize, errno: ${getDtableErrno}`);

    for (let fd = 0; fd <= maxFd; fd++) {
      const getFdRet = fnFcntl(fd, FdCmdLet.F_GETFD, ptr(0));
      if (getFdRet === -1) continue;

      const destBuff = Memory.alloc(FdCmdLet.PATH_MAX + 1);

      const getPathRet = fnFcntl(fd, FdCmdLet.F_GETPATH, destBuff);
      if (getPathRet === -1) continue;

      const dest = destBuff.readUtf8String();
      if (dest === null) throw new Error(`Failed to read dest for fd: ${fd}`);
      result[fd] = dest;
    }

    return result;
  }

  private readFds(): Fds {
    switch (Process.platform) {
      case 'linux':
        return this.readFdsLinux();
      case 'darwin':
      case 'freebsd':
      case 'qnx':
        return this.readFdsUnix();
      case 'windows':
      case 'barebone':
      default:
        throw new Error(`Platform: ${Process.platform} unsupported`);
    }
  }

  private runWithId(tokens: Token[]): Var | undefined {
    if (tokens.length != 1) return undefined;

    const fd = tokens[0]?.toVar()?.toU64().toNumber();
    if (fd === undefined) return undefined;

    const path = this.readFds()[fd];
    if (path === undefined) throw new Error(`fd: ${fd} not found`);

    Output.writeln(`Fd: ${fd.toString().padStart(3, ' ')}, Path: ${path}`);

    return new Var(uint64(fd));
  }

  private runWithoutParams(tokens: Token[]): Var | undefined {
    if (tokens.length != 0) return undefined;

    const fds = this.readFds();
    for (const [fd, path] of Object.entries(fds)) {
      Output.writeln(`Fd: ${fd.toString().padStart(3, ' ')}, Path: ${path}`);
    }

    return Var.ZERO;
  }

  public run(tokens: Token[]): Var {
    const retWithId = this.runWithId(tokens);
    if (retWithId !== undefined) return retWithId;

    const retWithoutParams = this.runWithoutParams(tokens);
    if (retWithoutParams !== undefined) return retWithoutParams;

    return this.usage();
  }

  public override isSupported(): boolean {
    switch (Process.platform) {
      case 'linux':
        this.pOpenDir = Module.findExportByName(null, 'opendir');
        this.pCloseDir = Module.findExportByName(null, 'closedir');
        this.pReadDir = Module.findExportByName(null, 'readdir');
        this.pReadLink = Module.findExportByName(null, 'readlink');

        if (
          this.pOpenDir === null ||
          this.pCloseDir === null ||
          this.pReadDir === null ||
          this.pReadLink === null
        )
          return false;
        break;
      case 'darwin':
      case 'freebsd':
      case 'qnx':
        this.pGetDTableSize = Module.findExportByName(null, 'getdtablesize');
        this.pFcntl = Module.findExportByName(null, 'fcntl');

        if (this.pGetDTableSize === null || this.pFcntl === null) return false;
        break;
      case 'windows':
      case 'barebone':
      default:
        return false;
    }

    return true;
  }
}
