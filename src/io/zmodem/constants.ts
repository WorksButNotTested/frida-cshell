export enum Escape {
  ESCAPE_ALWAYS = 'always',
  ESCAPE_NEVER = 'never',
  ESCAPE_AFTER_AT = 'after',
}

export enum Chars {
  NUL = 0x00,
  LF = 0x0a,
  CR = 0x0d,
  DLE = 0x10,
  XON = 0x11,
  XOFF = 0x13,
  ZDLE = 0x18,
  ZPAD = 0x2a,
  AT = 0x40,
}

export enum Header {
  ZBIN = 0x41,
  ZHEX = 0x42,
  ZBIN32 = 0x43,
}

export enum Conv {
  ZCNONE = 0,
  ZCBIN = 1,
  ZCNL = 2,
  ZCRESUM = 3,
}

export enum FileOpts {
  NONE = 0,
  ZMKSNOLOC = 0x80,
  ZMNEWL = 1,
  ZMCRC = 2,
  ZMAPND = 3,
  ZMCLOB = 4,
  ZMNEW = 5,
  ZMDIFF = 6,
  ZMPROT = 7,
  ZMCHNG = 8,
}

export enum Trans {
  ZTNONE = 0,
  ZTLZW = 1,
  ZTCRYPT = 2,
  ZTRLE = 3,
}

export enum Ext {
  ZXNONE = 0,
  ZXSPARS = 64,
}

export enum FrameType {
  ZRQINIT = 0,
  ZRINIT = 1,
  SZINIT = 2,
  ZACK = 3,
  ZFILE = 4,
  ZSKIP = 5,
  ZNAK = 6,
  ZABORT = 7,
  ZFIN = 8,
  ZRPOS = 9,
  ZDATA = 10,
  ZEOF = 11,
  ZFERR = 12,
  ZCRC = 13,
  ZCHALLENGE = 14,
  ZCOMPL = 15,
  ZCAN = 16,
  ZFREECNT = 17,
  ZCOMMAND = 18,
  ZSTDERR = 19,
}

export enum Zdle {
  ZCRCE = 0x68,
  ZCRCG = 0x69,
  ZCRCQ = 0x6a,
  ZCRCW = 0x6b,
  ZRUB0 = 0x6c,
  ZRUB1 = 0x6d,
}

export enum ZrinitFlags {
  CANFDX = 1 /* Rx can send and receive true	FDX */,
  CANOVIO = 2 /* Rx can receive data during disk I/O */,
  CANBRK = 4 /* Rx can send a break signal */,
  CANCRY = 8 /* Receiver can	decrypt	*/,
  CANLZW = 0x10 /* Receiver can	uncompress */,
  CANFC32 = 0x20 /* Receiver can	use 32 bit Frame Check */,
  ESCCTL = 0x40 /* Receiver expects ctl	chars to be escaped */,
  ESC8 = 0x80,
}
