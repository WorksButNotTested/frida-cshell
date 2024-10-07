export class Version {
  private readonly major: number;
  private readonly minor: number;
  private readonly patch: number;

  public static readonly BINARY_MODE_MIN_VERSION = new Version('1.7.6');
  public static readonly VERSION = new Version(Frida.version);

  public constructor(version: string) {
    const [major, minor, patch] = version.split('.');
    this.major = Number(major);
    this.minor = Number(minor);
    this.patch = Number(patch);
  }

  public compareTo(other: Version): number {
    if (this.major !== other.major) {
      return this.major > other.major ? 1 : -1;
    } else if (this.minor !== other.minor) {
      return this.minor > other.minor ? 1 : -1;
    } else {
      return this.patch > other.patch ? 1 : -1;
    }
  }
}
