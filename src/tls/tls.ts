import { TlsArm } from './arm.js';
import { TlsX64 } from './x64.js';
import { TlsIa32 } from './ia32.js';
import { TlsAarch64 as TlsArm64 } from './arm64.js';

export class Tls {
  public static getTls(): NativePointer {
    switch (Process.arch) {
      case 'x64':
        return TlsX64.getTls();
      case 'ia32':
        return TlsIa32.getTls();
      case 'arm':
        return TlsArm.getTls();
      case 'arm64':
        return TlsArm64.getTls();
      default:
        return ptr(0);
    }
  }

  public static isSupported(): boolean {
    switch (Process.arch) {
      case 'x64':
      case 'ia32':
      case 'arm':
      case 'arm64':
        return true;
      default:
        return false;
    }
  }
}
