# Hollow

**Hollow** is a messy, proof-of-concept text-based user interface (TUI) decompiler written in C++ using `capstone` for disassembly and `ncurses` for rendering. This project was thrown together in **5 minutes**, so don't expect a fully-fledged Ghidra clone—but it does demonstrate basic disassembly, control flow graph (CFG) visualization, and pseudocode generation.

## Features

- **Disassembly**: View disassembled machine code for the given binary.
- **Control Flow Graph (CFG)**: Basic block representation of the binary's control flow.
- **Pseudocode Generation**: Simple decompilation of assembly instructions into pseudocode.
- **TUI**: Navigate through the disassembly, CFG, and pseudocode with a basic terminal UI.
- **Keyboard Shortcuts**:
  - **`q`**: Quit the application.
  - **`UP`**: Scroll up disassembled instructions.
  - **`DOWN`**: Scroll down disassembled instructions.
  - **`c`**: Scroll through the CFG.
  - **`d`**: Scroll through decompiled pseudocode.

## Prerequisites

- **Capstone**: The disassembly engine. Install it with:
  ```bash
  sudo apt-get install libcapstone-dev  # For Debian/Ubuntu
  ```
- **Ncurses**: Used for creating the TUI. Install it with:
  ```bash
  sudo apt-get install libncurses-dev  # For Debian/Ubuntu
  ```

## Build Instructions

```bash
g++ -std=c++17 -o hollow main.cpp -lncurses -lcapstone
```

## Usage

```bash
./hollow <binary_file>
```

Example:
```bash
./hollow file.exe
```

This will load the specified binary file, disassemble it, generate a control flow graph, and decompile it into pseudocode, displaying all three in a simple TUI.

## Limitations

- **Quick Project**: This was cobbled together in **5 minutes**, so don't expect robust error handling, performance optimizations, or sophisticated features.
- **Basic Decompilation**: The pseudocode generator is **extremely simple** and barely scratches the surface of actual decompilation.
- **Minimal CFG**: Control flow graph is basic and doesn’t include advanced optimizations.
- **No File Format Support**: This project assumes the input is a raw binary executable. No parsing of complex binary formats like ELF or PE is implemented.

## Future Work (Maybe)

- Implement more detailed file format parsing (e.g., PE or ELF).
- Improve the TUI for a better user experience (better scrolling, search, etc.).
- Expand pseudocode generation for better human readability.

## License

This project has no license—use it however you wish
