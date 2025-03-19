# AVR Stack Analyzer

A specialized tool for analyzing stack usage in AVR microcontroller binaries.

## Overview

AVR Stack Analyzer examines ELF binary files targeting AVR microcontrollers to determine the maximum stack usage of functions at runtime. This helps embedded systems developers prevent stack overflows which can lead to unpredictable behavior in AVR-based applications.

The tool performs:
- Static analysis of ELF binaries
- CPU simulation to track stack operations
- Call graph construction
- Maximum stack usage calculation for each function and interrupt service routine
- Detection of potential issues like calls from ISRs and recursion

## Features

- Analyzes ELF binaries for AVR microcontrollers
- Calculates maximum stack usage for each function
- Detects recursive calls and calls from interrupt handlers
- Multiple output formats (default, v4, v19, JSON)
- Terminal-friendly, human-readable output
- Color-coded JSON display in the terminal
- Detailed or summary reports
- Customizable analysis options

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

Where `INPUT_FILE` is the path to your AVR ELF binary file.

### Command-line Options

- `--format <FORMAT>` - Output format (v4, v19, or json)
- `--total-only` - Print only total stack usage
- `--allow-calls-from-isr` - Don't error on calls from ISRs
- `--wrap0` - Allow wrapped addresses at address 0
- `--include-bad-interrupt` - Include bad_interrupt in analysis
- `--ignore-icall` - Ignore all indirect calls
- `--memory-report` - Show memory statistics
- `--json` - Output in JSON format

### Examples

Analyze an AVR binary with default settings:
```
avr_stack path/to/firmware.elf
```

Generate a JSON report:
```
avr_stack --json path/to/firmware.elf
```

Show only the total stack usage:
```
avr_stack --total-only path/to/firmware.elf
```

## Understanding the Output

The standard output format includes:

1. Function names and their addresses
2. Maximum stack usage (in bytes)
3. Call chains that lead to the maximum stack usage
4. Total maximum stack usage across all functions

JSON output provides the same information in a structured format suitable for further processing or integration with other tools.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).

## Version History

Current version: 1.4
