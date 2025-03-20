# AVR Stack Analyzer

A sophisticated tool for analyzing stack usage in AVR microcontroller binaries through cycle-accurate instruction simulation.

## Overview

AVR Stack Analyzer helps you figure out how much stack your AVR microcontroller programs are using. It works by looking at your compiled ELF files and actually simulating the AVR instructions to track stack operations in real-time. This is super helpful for embedded developers who want to avoid those nasty stack overflows that can make AVR-based systems go haywire.

## Credits

Created by Gary Scott (Dazed_N_Confused)

## Key Features

### 1. Real AVR Instruction Simulation
- We've implemented the full AVR instruction set including:
  - All the stack stuff (PUSH/POP)
  - Function calls (CALL/RCALL)
  - Returns (RET/RETI)
  - Those tricky indirect jumps and calls (IJMP/ICALL)
  - Every branch instruction you can think of
- Tracks the stack accurately for each cycle
- Smart enough to understand compiler function patterns
- Recognizes different compiler-specific code styles

### 2. Smart Control Flow Analysis
- Builds a complete map of function calls
- Keeps tabs on both direct and indirect function calls
- Handles all those jumps and branches
- Checks multiple possible execution paths
- Catches recursive calls before they bite you
- Works with both relative and absolute addresses
- Can handle address wrapping at 0 (if you need it)

### 3. Interrupt Service Routine (ISR) Analysis
- Support for up to 32 interrupt vectors
- ISR stack usage validation
- Detection of calls from interrupt contexts
- Analysis of interrupt nesting implications
- Special handling of bad_interrupt vector
- ISR safety verification

### 4. Memory-Aware Design
- Precise RAM usage tracking
- Program memory (flash) analysis
- Stack underflow detection
- Memory safety bounds checking
- Multi-space memory management (RAM, flash, EEPROM)
- Maximum stack depth calculation

### 5. ELF Binary Integration
- Complete ELF file parsing
- Symbol table processing
- Debug information handling
- Relocation processing
- Text section analysis
- Function entry point detection

### 6. Pattern Recognition
- Standard function prologue detection
- Epilogue pattern identification
- Support for multiple compiler versions
- Optimization level awareness
- Variable-length pattern matching
- Compiler-specific pattern handling

### 7. Output and Reporting
- Multiple output formats:
  - Human-readable default format
  - JSON structured output (pretty or compact)
  - v4 and v19 compatibility modes
- Detailed reporting options:
  - Per-function stack usage
  - Maximum call chain depths
  - Interrupt stack requirements
  - Memory utilization statistics
  - Call graph visualization

## Requirements

- Rust and Cargo (latest stable version recommended)
- Dependencies (automatically installed via Cargo):
  - clap - Command-line argument parsing
  - object - ELF file parsing
  - serde - JSON serialization
  - serde_json - JSON formatting and manipulation

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-username/avr_stack_analyzer.git
   cd avr_stack_analyzer
   ```

2. Build the project:
   ```
   cargo build --release
   ```

3. The compiled binary will be available at `target/release/avr_stack`

## Usage

Basic usage:
```
avr_stack [OPTIONS] <INPUT_FILE>
```

### Command-line Options

- `--format <FORMAT>` - Output format (v4, v19, or json)
- `--total-only` - Print only total stack usage
- `--allow-calls-from-isr` - Don't error on calls from ISRs
- `--wrap0` - Allow wrapped addresses at address 0
- `--include-bad-interrupt` - Include bad_interrupt in analysis
- `--ignore-icall` - Ignore all indirect calls
- `--memory-report` - Show memory statistics
- `--json` - Output in JSON format
- `--json-compact` - Output compact JSON format

### Advanced Usage Examples

Analyze with full memory reporting:
```
avr_stack --memory-report path/to/firmware.elf
```

Generate detailed JSON output:
```
avr_stack --json --format v19 path/to/firmware.elf
```

Analyze with ISR call validation disabled:
```
avr_stack --allow-calls-from-isr path/to/firmware.elf
```

## Understanding the Output

The analysis output includes:

1. Function-level Information:
   - Function names and addresses
   - Maximum stack usage per function
   - Call chains leading to maximum stack usage
   - ISR interactions and implications

2. Global Analysis:
   - Total maximum stack usage
   - Critical call paths
   - Potential stack overflow points
   - Memory utilization statistics

3. Safety Warnings:
   - Stack underflow risks
   - Dangerous ISR calls
   - Recursive call detection
   - Memory boundary issues

## Development Notes

- The project uses comprehensive error handling and validation
- Includes extensive safety checks for memory operations
- Employs efficient data structures for performance
- Supports debugging and detailed logging capabilities

## Troubleshooting

If you encounter compilation errors:

1. Make sure you have the latest stable Rust toolchain installed
2. Try cleaning the build and rebuilding:
   ```
   cargo clean
   cargo build --release
   ```
3. Check for specific error messages in the build output
4. Verify your AVR ELF file format is supported

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. When contributing:

1. Follow the existing code style
2. Add tests for new features
3. Update documentation for significant changes
4. Ensure all tests pass

## License

This project is licensed under the [MIT License](LICENSE).

## Version History

Current version: 1.4
