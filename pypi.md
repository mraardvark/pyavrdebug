# pyavrdebug
pyavrdebug is a GDB RSP server for connecting GDB debug clients to AVR target devices through pymcuprog.

## Usage
pyavrdebug can be used to debug AVR UPDI devices via GDB

For example:

1. Program code using pymcuprog:
```bash
pymcuprog write --erase -d atmega4808 -f firmware.hex
```

2. Attach GDB session to the AVR
```bash
pyavrdebug -d atmega4808
```

3. Start a GDB debugging session on localhost:4712