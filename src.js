return {
  category: "adhoc",
  name: "test",
  help: "test command",

  usage: function() {
    Output.writeln("USAGE");
    return Var.ZERO;
  },

  run: function(tokens) {
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
    Output.writeln(dump);
  },

  isSupported: function() {
    return true;
  }
}