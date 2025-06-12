export class Version {
  private readonly major: number;
  private readonly minor: number;
  private readonly patch: number;

  public static readonly MIN_SUPPORTED_VERSION = new Version('17.0.0');
  public static readonly VERSION = new Version(Frida.version);

  public constructor(version: string) {
    const [major, minor, patch] = version.split('.');
    this.major = Number(major);
    this.minor = Number(minor);
    this.patch = Number(patch);
  }

  public static isSupported(): boolean {
    return this.VERSION.compareTo(this.MIN_SUPPORTED_VERSION) >= 0;
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

  public toString(): string {
    return `v${this.major}.${this.minor}.${this.patch}`;
  }
}
