import { Format } from '../../misc/format.js';
import { Block } from './block.js';
import { InputBuffer } from './input.js';
import { OutputBuffer } from './output.js';
import { Sz } from './sz.js';

export class Zmodem {
  private input: InputBuffer;
  private output: OutputBuffer;
  private debug: (msg: string) => void;

  public constructor(
    input: InputBuffer,
    output: OutputBuffer,
    debug: (msg: string) => void,
  ) {
    this.input = input;
    this.output = output;
    this.debug = debug;
  }

  public async send(filePath: string) {
    const file = new File(filePath, 'rb');
    file.seek(0, File.SEEK_END);
    const size = file.tell();
    file.seek(0, File.SEEK_SET);
    this.debug(`File Size: ${Format.toSize(size)}`);

    const sz = new Sz(this.input, this.output, this.debug);
    const fileName = filePath.substring(filePath.lastIndexOf('/') + 1);
    await sz.start(fileName);

    let written = 0;
    while (true) {
      this.debug(`Wrote: ${Format.toSize(written)}`);
      const block = file.readBytes(Block.MAX_BLOCK_SIZE);
      if (block.byteLength === 0) {
        this.debug('EOF');
        break;
      }
      written += block.byteLength;
      await sz.write(block);
    }
    this.debug('Transmission complete');

    await sz.end(written);
  }
}
