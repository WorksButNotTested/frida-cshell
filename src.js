return {
  category: "adhoc",
  name: "test",
  help: "test command",

  usage: function() {
    Output.writeln("test command usage");
    return Var.ZERO;
  },

  run: function(tokens) {
    return this.runSync(tokens);
  },

  runSync: function(tokens) {
    if (tokens.length !== 1) return this.usage();
    const address = tokens[0].toVar().toPointer();
    Output.writeln(`test: ${address}`);

    const length = 32;
    const bytes = Mem.readBytes(address, length);
    const dump = hexdump(bytes.buffer, {
        length: length,
        header: true,
        ansi: true,
        address: address,
      });
    const prefixed = dump.split('\n').join(`\n${Output.green("0x")}`);
    Output.writeln(`  ${prefixed}`);
  },

  isSupported: function() {
    return true;
  }
}
