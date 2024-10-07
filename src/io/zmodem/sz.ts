import { Format } from '../../misc/format.js';
import { Block } from './block.js';
import {
  Conv,
  Ext,
  FileOpts,
  FrameType,
  Trans,
  Zdle,
  ZrinitFlags,
} from './constants.js';
import { Frame } from './frame.js';
import { InputBuffer } from './input.js';
import { OutputBuffer } from './output.js';

type ZrInitFlags = { [key in ZrinitFlags]: boolean };
type ZrinitData = [number, ZrInitFlags];

export class Sz {
  private static readonly DEFAULT_FRAME_READ_TIMEOUT: number = 500;
  public static readonly BLOCK_SIZE: number = 1024;
  private static readonly MAX_ERRORS: number = 10;

  public static async sleep(ms: number): Promise<void> {
    return new Promise<void>(resolve => {
      setTimeout(() => {
        resolve();
      }, ms);
    });
  }

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

  public async start(fileName: string) {
    this.debug(`start: ${fileName}`);
    this.writeZrqInit();
    await Sz.sleep(500);

    let numErrors = 0;
    let gotZrInit = false;

    while (numErrors < Sz.MAX_ERRORS) {
      const frame = await this.readFrame();
      if (frame === null) {
        numErrors++;
        if (!gotZrInit) {
          this.writeZrqInit();
        }
      } else if (frame.type === FrameType.ZRINIT) {
        if (gotZrInit) {
          numErrors++;
        } else {
          gotZrInit = true;
          const [bufferLength, flags] = this.parseZrInit(frame);
          if (bufferLength !== 0) {
            throw new Error(
              `Non-stop I/O required, remote reported buffer length: ${bufferLength}`,
            );
          }
          if (flags[ZrinitFlags.ESC8]) {
            throw new Error('ESC8 not supported');
          }
          if (flags[ZrinitFlags.ESCCTL]) {
            throw new Error('ESCCTL not supported');
          }
          if (!flags[ZrinitFlags.CANOVIO]) {
            throw new Error(`CANOVIO required`);
          }
          this.writeZFile(fileName);
        }
      } else if (frame.type === FrameType.ZRPOS) {
        const pos = this.parseZrPos(frame);
        if (pos !== 0) {
          throw new Error(`Invalid position: ${pos}`);
        }
        return;
      }
    }
  }

  private writeZrqInit() {
    const zrqInit = new Frame(FrameType.ZRQINIT, 0, 0, 0, 0);
    this.output.write(zrqInit.data);
    this.debug('wrote ZRQINIT');
  }

  private async readFrame(
    timeout: number = Sz.DEFAULT_FRAME_READ_TIMEOUT,
  ): Promise<Frame | null> {
    try {
      const bytes = await this.input.read(Frame.FRAME_SIZE, timeout);
      const frame = Frame.fromBytes(bytes);
      this.debug(`FRAME: ${frame}`);
      return frame;
    } catch {
      return null;
    }
  }

  private parseZrInit(frame: Frame): ZrinitData {
    this.debug('read ZRINIT');

    const bufferLength = (frame.p0 << 16) | frame.p1;
    this.debug(`\tbufferLength: ${bufferLength}`);

    const flags = (frame.p2 << 8) | frame.p3;
    this.debug(`\tflags: ${flags}`);

    const lookup: [ZrinitFlags, string][] = [
      [ZrinitFlags.CANFDX, 'CANFDX'],
      [ZrinitFlags.CANOVIO, 'CANOVIO'],
      [ZrinitFlags.CANBRK, 'CANBRK'],
      [ZrinitFlags.CANCRY, 'CANCRY'],
      [ZrinitFlags.CANLZW, 'CANLZW'],
      [ZrinitFlags.CANFC32, 'CANFC32'],
      [ZrinitFlags.ESCCTL, 'ESCCTL'],
      [ZrinitFlags.ESC8, 'ESC8'],
    ];
    lookup.forEach(([flag, name]) => {
      const isSet = (flags & flag) !== 0;
      this.debug(`\t${name} [${isSet ? 'X' : ' '}]`);
    });

    const flagsDict: ZrInitFlags = lookup.reduce<ZrInitFlags>((acc, [flag]) => {
      acc[flag] = (flags & flag) !== 0;
      return acc;
    }, {} as ZrInitFlags);

    return [bufferLength, flagsDict];
  }

  private writeZFile(fileName: string) {
    const zFile = new Frame(
      FrameType.ZFILE,
      Ext.ZXNONE,
      Trans.ZTNONE,
      FileOpts.ZMCLOB,
      Conv.ZCBIN,
    );
    this.output.write(zFile.data);

    const nameBytes = Format.toByteArray(fileName + '\0');
    const block = new Block(nameBytes, Zdle.ZCRCW);
    this.output.write(block.data);
    this.debug('wrote ZFILE');

    const zData = new Frame(FrameType.ZDATA, 0, 0, 0, 0);
    this.output.write(zData.data);
    this.debug('wrote ZDATA');
  }

  private parseZrPos(frame: Frame): number {
    this.debug('read ZRPOS');
    const pos =
      (frame.p0 << 24) | (frame.p1 << 16) | (frame.p2 << 8) | frame.p3;
    this.debug(`pos: ${pos}`);
    return pos;
  }

  public async write(data: ArrayBuffer) {
    try {
      this.debug(`write: ${data.byteLength}`);
      for (let i = 0; i < data.byteLength; i += Sz.BLOCK_SIZE) {
        const chunk = data.slice(i, i + Sz.BLOCK_SIZE);
        this.writeCrcG(chunk);

        const frame = await this.readFrame(0);
        if (frame === null) {
          this.debug('no response to ZCRCG');
          continue;
        } else if (frame.type === FrameType.ZRPOS) {
          const pos = this.parseZrPos(frame);
          throw new Error(`Received error response: ${pos}`);
        } else {
          throw new Error(`Received unexpected frame after ZCRCG: ${frame}`);
        }
      }
    } catch (e) {
      this.debug(`error: ${e}`);
      throw e;
    }
  }

  private writeCrcG(data: ArrayBuffer) {
    const block = new Block(data, Zdle.ZCRCG);
    this.output.write(block.data);
  }

  public async end(length: number) {
    try {
      this.debug(`end: ${length}`);
      this.writeCrce();
      await this.readCrce();

      this.writeZEof(length);
      await this.readZEof();

      this.writeZFin();
      await this.readZFin();

      this.writeOO();
    } catch (e) {
      this.debug(`error: ${e}`);
      throw e;
    }
    this.debug('all done');
  }

  private writeCrce() {
    const block = new Block(null, Zdle.ZCRCE);
    this.output.write(block.data);

    this.debug('wrote ZCRCE');
  }

  private async readCrce(): Promise<void> {
    const frame = await this.readFrame();
    if (frame === null) {
      this.debug('no response to ZCRCE');
    } else {
      throw new Error(`Received unexpected frame after ZCRCE: ${frame}`);
    }
    this.debug('read ZCRCE');
  }

  private writeZEof(length: number) {
    const p0 = length & 0xff;
    const p1 = (length >> 8) & 0xff;
    const p2 = (length >> 16) & 0xff;
    const p3 = (length >> 24) & 0xff;
    const zEof = new Frame(FrameType.ZEOF, p0, p1, p2, p3);
    this.output.write(zEof.data);

    this.debug('wrote ZEOF');
  }

  private async readZEof(): Promise<void> {
    const frame = await this.readFrame();
    if (frame === null) {
      throw new Error('no response to ZEOF');
    } else if (frame.type !== FrameType.ZRINIT) {
      throw new Error(`Received unexpected frame after ZEOF: ${frame}`);
    }
    this.debug('read ZEOF');
  }

  private writeZFin() {
    const zFin = new Frame(FrameType.ZFIN, 0, 0, 0, 0);
    this.output.write(zFin.data);
    this.debug('wrote ZFIN');
  }

  private async readZFin(): Promise<void> {
    const bytes = await this.input.read(
      Frame.ZFIN_FRAME_SIZE,
      Sz.DEFAULT_FRAME_READ_TIMEOUT,
    );
    const frame = Frame.fromBytes(bytes);
    this.debug(`frame: ${frame}`);
    if (frame === null) {
      throw new Error('no response to ZFIN');
    } else if (frame.type !== FrameType.ZFIN) {
      throw new Error(`Received unexpected frame after ZEOF: ${frame}`);
    }
    this.debug('read ZFIN');
  }

  private async writeOO() {
    const oo = Format.toByteArray('OO');
    this.output.write(oo);
  }
}
