function dumpStuff(tokens, name, length) {
  if (tokens.length !== 1) throw new Error("expected 1 argument");
  const address = tokens[0].toVar().toPointer();
  Output.writeln(`${name}: ${address}`);

  const bytes = Mem.readBytes(address, length);
  const dump = hexdump(bytes.buffer, {
      length: length,
      header: true,
      ansi: true,
      address: address,
    });
  const prefixed = dump.split('\n').join(`\n${Output.green("0x")}`);
  Output.writeln(`  ${prefixed}`);
}

return [
  {
    name: "test1",

    runSync: function(tokens) {
      try {
        dumpStuff(tokens, "test1", 16);
        return Var.ZERO;
      } catch {
        return this.usage();
      }
    },
  },
  {
    name: "test2",

    runSync: function(tokens) {
      try {
        dumpStuff(tokens, "test2", 32);
        return Var.ZERO;
      } catch {
        return this.usage();
      }
    },
  },
]
