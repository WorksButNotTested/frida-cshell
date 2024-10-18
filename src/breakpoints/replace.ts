import { Output } from '../io/output.js';
import { Format } from '../misc/format.js';
import { Var } from '../vars/var.js';
import { Bp, BpKind, BpType } from './bp.js';

export class BpReplacement extends Bp {
  private static readonly BP_REPLACEMENT_LENGTH: number = 16;

  readonly type: BpType = BpType.Replacement;
  readonly kind: BpKind = BpKind.Replacement;
  readonly supports_commands: boolean = false;

  protected target: Var;
  public trampoline: Var | null = null;

  public constructor(index: number, address: Var, target: Var) {
    super(index, address, BpReplacement.BP_REPLACEMENT_LENGTH, null);
    this.target = target;
  }

  protected formatLength(): string {
    return '';
  }

  enable(): void {
    if (this.address === null) return;
    try {
      const ptr = Interceptor.replaceFast(
        this.address.toPointer(),
        this.target.toPointer(),
      );
      this.trampoline = new Var(uint64(ptr.toString()));
    } catch (error) {
      throw new Error(
        `failed to replace ${Format.toHexString(this.address.toPointer())} with ${Format.toHexString(this.target.toPointer())}, ${error}`,
      );
    }
  }

  disable(): void {
    if (this.address === null) return;
    Interceptor.revert(this.address.toPointer());
  }

  public override toString(): string {
    const idxString = Output.green(`#${this.index.toString()}.`.padEnd(4, ' '));
    const targetString = `target: ${Output.blue(this.target.getLiteral())}`;
    const addressString = `address: ${Output.blue(this.literal)}`;
    return `${idxString} ${addressString} -> ${targetString}`;
  }
}
