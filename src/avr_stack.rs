// Core implementation for AVR Stack Analyzer

use std::fmt;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, Write};
use clap::{Command, Arg, ArgAction};
use serde::Serialize;
use crate::elf::ElfInfo;
use crate::cpu::Cpu;
use crate::analysis::{MazeAnalysis, TreeAnalysis};
use std::collections::HashMap;

// Allow dead code in this module as many items will be used in the future
#[allow(dead_code)]

const VERSION: &str = "37";  // Updated for Rust version

// ******************************************************************************
// * ERROR HANDLING
// ******************************************************************************

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    None = 0,
    General,
    Memory,
    FileIo,
    InvalidElf,
    CpuSimulation,
    StackAnalysis,
    Parameter,
    IoError,
    
    // Specific error codes
    RetiExpected = 1000,
    RetiUnexpected,
    StackChangeLoop,
    NegativeStackChange,
    Recursion,
    CallFromIsr,
}

#[derive(Debug)]
pub struct AvrStackError {
    code: ErrorCode,
    message: String,
    file: String,
    line: u32,
}

impl AvrStackError {
    pub fn new(error_code: ErrorCode, file: &str, line: u32, message: &str) -> Self {
        AvrStackError {
            code: error_code,
            file: file.to_string(),
            line,
            message: message.to_string(),
        }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }
    
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AvrStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ERROR ({}:{}) [{}]: {} - v{}", self.file, self.line, self.code as u32, self.message, VERSION)
    }
}

impl StdError for AvrStackError {}

impl From<std::io::Error> for AvrStackError {
    fn from(error: std::io::Error) -> Self {
        AvrStackError {
            code: ErrorCode::FileIo,
            message: error.to_string(),
            file: file!().to_string(),
            line: line!(),
        }
    }
}

pub type Result<T> = std::result::Result<T, AvrStackError>;

// Macro for easier error creation
#[macro_export]
macro_rules! ez_error {
    ($code:expr) => {
        Err(AvrStackError::new($code, file!(), line!(), error_message($code)))
    };
    ($code:expr, $msg:expr) => {
        Err(AvrStackError::new($code, file!(), line!(), &format!("{}: {}", error_message($code), $msg)))
    };
    ($code:expr, $fmt:expr, $($arg:tt)*) => {
        Err(AvrStackError::new($code, file!(), line!(), &format!("{}: {}", 
                               error_message($code), 
                               format!($fmt, $($arg)*))))
    };
}

// Helper function to get error message from code
pub fn error_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::None => "No error",
        ErrorCode::General => "General error",
        ErrorCode::Memory => "Memory allocation error",
        ErrorCode::FileIo => "File I/O error",
        ErrorCode::InvalidElf => "Invalid ELF file",
        ErrorCode::CpuSimulation => "CPU simulation error",
        ErrorCode::StackAnalysis => "Stack analysis error",
        ErrorCode::Parameter => "Invalid parameter",
        ErrorCode::RetiExpected => "RETI instruction expected",
        ErrorCode::RetiUnexpected => "Unexpected RETI instruction",
        ErrorCode::StackChangeLoop => "Loop in stack change",
        ErrorCode::NegativeStackChange => "Negative stack change",
        ErrorCode::Recursion => "Recursion detected",
        ErrorCode::CallFromIsr => "Call from ISR detected",
        ErrorCode::IoError => "I/O error",
    }
}

// ******************************************************************************
// * PROGRAM OPTIONS
// ******************************************************************************
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Default = 5,
    V4 = 4,
    V19 = 19,
    Json = 100,
}

#[derive(Debug)]
pub struct MainICall {
    pub src_offset: u32,
    pub dst_count: u32,
    pub src: String,
    pub dst: Vec<String>,
}

#[derive(Debug)]
pub struct ProgramArgs {
    pub format: OutputFormat,
    pub filename: Option<String>,
    pub allow_calls_from_isr: bool,
    pub mcu_specified: bool,
    pub wrap_0: bool,
    pub include_bad_interrupt: bool,
    pub ignore_icall_all: bool,
    pub total_only: bool,
    pub memory_report: bool,
    pub json_output: bool,
    pub json_pretty: bool,  // Option for pretty JSON
    pub call_graph: bool,   // Adding call graph option
    pub icall_list: Vec<MainICall>,
    pub max_recursion: u32, // Maximum recursion depth
    pub ignore_functions: Vec<String>, // Functions to ignore
    pub verbose: bool,  // Add this field for controlling output verbosity
    pub quiet: bool,    // Add this field for controlling quiet mode
}

impl Default for ProgramArgs {
    fn default() -> Self {
        ProgramArgs {
            format: OutputFormat::Default,
            filename: None,
            allow_calls_from_isr: false,
            mcu_specified: false,
            wrap_0: false,
            include_bad_interrupt: false,
            ignore_icall_all: false,
            total_only: false,
            memory_report: false,
            json_output: false,
            json_pretty: true,  // Default to pretty-printing JSON for terminal readability
            call_graph: false,  // Off by default
            icall_list: Vec::new(),
            max_recursion: 10,  // Default maximum recursion depth
            ignore_functions: Vec::new(), // Default empty list of ignored functions
            verbose: false,  // Default to false
            quiet: false,    // Default to false
        }
    }
}

// ******************************************************************************
// * JSON OUTPUT
// ******************************************************************************
#[derive(Debug)]
pub struct JsonWriter {
    file: File,
    indent: usize,
    first_item: bool,
    is_array: bool,
    pretty_print: bool,
}

impl JsonWriter {
    pub fn new(filename: &str, pretty: bool) -> Result<Self> {
        let file = File::create(filename)
            .map_err(|e| AvrStackError::new(
                ErrorCode::FileIo,
                file!(),
                line!(),
                &format!("Failed to create JSON output file: {}", e)
            ))?;
        Ok(JsonWriter {
            file,
            indent: 0,
            first_item: true,
            is_array: false,
            pretty_print: pretty,
        })
    }

    pub fn write_indent(&mut self) -> io::Result<()> {
        if self.pretty_print {
            for _ in 0..self.indent {
                write!(self.file, "  ")?;
            }
        }
        Ok(())
    }

    pub fn begin_object(&mut self) -> io::Result<()> {
        if !self.first_item {
            writeln!(self.file, ",")?;
        } else {
            self.first_item = false;
        }
        self.write_indent()?;
        writeln!(self.file, "{{")?;
        self.indent += 1;
        self.first_item = true;
        Ok(())
    }

    pub fn end_object(&mut self) -> io::Result<()> {
        self.indent -= 1;
        writeln!(self.file)?;
        self.write_indent()?;
        write!(self.file, "}}")?;
        self.first_item = false;
        Ok(())
    }

    pub fn begin_array(&mut self) -> io::Result<()> {
        if !self.first_item {
            writeln!(self.file, ",")?;
        } else {
            self.first_item = false;
        }
        self.write_indent()?;
        writeln!(self.file, "[")?;
        self.indent += 1;
        self.first_item = true;
        self.is_array = true;
        Ok(())
    }

    pub fn end_array(&mut self) -> io::Result<()> {
        self.indent -= 1;
        writeln!(self.file)?;
        self.write_indent()?;
        write!(self.file, "]")?;
        self.first_item = false;
        self.is_array = false;
        Ok(())
    }

    pub fn write_property_name(&mut self, name: &str) -> io::Result<()> {
        if !self.first_item {
            writeln!(self.file, ",")?;
        } else {
            self.first_item = false;
        }
        self.write_indent()?;
        write!(self.file, "\"{}\": ", name)?;
        Ok(())
    }

    pub fn write_string(&mut self, value: &str) -> io::Result<()> {
        write!(self.file, "\"{}\"", value)?;
        Ok(())
    }

    pub fn write_int(&mut self, value: i32) -> io::Result<()> {
        write!(self.file, "{}", value)?;
        Ok(())
    }

    pub fn write_uint(&mut self, value: u32) -> io::Result<()> {
        write!(self.file, "{}", value)?;
        Ok(())
    }

    pub fn write_bool(&mut self, value: bool) -> io::Result<()> {
        write!(self.file, "{}", if value { "true" } else { "false" })?;
        Ok(())
    }

    pub fn write_hex(&mut self, value: u32) -> io::Result<()> {
        write!(self.file, "\"0x{:x}\"", value)?;
        Ok(())
    }

    pub fn write_property_string(&mut self, name: &str, value: &str) -> io::Result<()> {
        self.write_property_name(name)?;
        self.write_string(value)
    }

    pub fn write_property_int(&mut self, name: &str, value: i32) -> io::Result<()> {
        self.write_property_name(name)?;
        self.write_int(value)
    }

    pub fn write_property_uint(&mut self, name: &str, value: u32) -> io::Result<()> {
        self.write_property_name(name)?;
        self.write_uint(value)
    }

    pub fn write_property_bool(&mut self, name: &str, value: bool) -> io::Result<()> {
        self.write_property_name(name)?;
        self.write_bool(value)
    }

    pub fn write_property_hex(&mut self, name: &str, value: u32) -> io::Result<()> {
        self.write_property_name(name)?;
        self.write_hex(value)
    }
}

// ******************************************************************************
// * ARCHITECTURE MODULE
// ******************************************************************************
#[derive(Debug)]
pub struct ArchInfo {
    pub num_isrs: u32,
    pub isr: Vec<String>,
    pub ram_size: u32,   // Adding RAM size field
    // More architecture-specific fields would be here
}

impl ArchInfo {
    pub fn new() -> Self {
        ArchInfo {
            num_isrs: 0,
            isr: Vec::new(),
            ram_size: 2 * 1024,  // 2KB RAM (typical for many AVRs)
        }
    }

    pub fn parse_standard_patterns(&mut self) -> Result<()> {
        // Implementation for pattern recognition
        // This would identify compiler-specific code patterns
        Ok(())
    }

    pub fn guess_num_interrupt_vectors(&mut self) -> Result<()> {
        // Implementation for determining the number of interrupt vectors
        Ok(())
    }

    pub fn detect_memory_sizes(&mut self, _elf: &ElfInfo) -> Result<()> {
        // Implementation for detecting memory sizes
        Ok(())
    }
}

// ******************************************************************************
// * MAIN APPLICATION
// ******************************************************************************
#[derive(Debug, Serialize, Clone)]
pub struct StackAnalysisResult {
    pub function_name: String,
    pub address: u32,
    pub stack_usage: u32,
    pub calls: Vec<String>,
}

pub struct AvrStack {
    pub args: ProgramArgs,
    pub elf: ElfInfo,
    pub cpu: Cpu,
    pub arch: ArchInfo,
    pub maze: MazeAnalysis,
    pub tree: TreeAnalysis,
    pub results: Vec<StackAnalysisResult>,
}

impl AvrStack {
    pub fn new() -> Self {
        AvrStack {
            args: ProgramArgs::default(),
            elf: ElfInfo::new(),
            cpu: Cpu::new(),
            arch: ArchInfo::new(),
            maze: MazeAnalysis::new(),
            tree: TreeAnalysis::new(),
            results: Vec::new(),
        }
    }

    pub fn parse_args(&mut self) -> Result<()> {
        // Use clap to define and parse command-line arguments
        let matches = Command::new("AVR Stack")
            .version(VERSION)
            .about("Stack usage analyzer for AVR binaries")
            .arg(Arg::new("INPUT")
                .help("Input ELF file")
                .required(true)
                .index(1))
            .arg(Arg::new("format")
                .long("format")
                .value_parser(clap::value_parser!(String))
                .help("Output format (v4, v19, or json)"))
            .arg(Arg::new("total-only")
                .long("total-only")
                .action(ArgAction::SetTrue)
                .help("Print only total stack usage"))
            .arg(Arg::new("allow-calls-from-isr")
                .long("allow-calls-from-isr")
                .action(ArgAction::SetTrue)
                .help("Don't error on calls from ISRs"))
            .arg(Arg::new("wrap0")
                .long("wrap0")
                .action(ArgAction::SetTrue)
                .help("Allow wrapped addresses at address 0"))
            .arg(Arg::new("include-bad-interrupt")
                .long("include-bad-interrupt")
                .action(ArgAction::SetTrue)
                .help("Include bad_interrupt in analysis"))
            .arg(Arg::new("ignore-icall")
                .long("ignore-icall")
                .action(ArgAction::SetTrue)
                .help("Ignore all icalls"))
            .arg(Arg::new("memory-report")
                .long("memory-report")
                .action(ArgAction::SetTrue)
                .help("Show memory statistics"))
            .arg(Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Output in JSON format"))
            .arg(Arg::new("json-compact")
                .long("json-compact")
                .action(ArgAction::SetTrue)
                .help("Output compact JSON (not human readable)"))
            .arg(Arg::new("call-graph")
                .long("call-graph")
                .action(ArgAction::SetTrue)
                .help("Generate call graph visualization data"))
            .arg(Arg::new("max-recursion")
                .long("max-recursion")
                .value_name("DEPTH")
                .help("Maximum recursion depth (default 10)"))
            .arg(Arg::new("ignore-function")
                .long("ignore-function")
                .value_name("NAME")
                .help("Ignore function with given name")
                .action(ArgAction::Append))
            .get_matches();

        // Set the program arguments based on command-line options
        if let Some(filename) = matches.get_one::<String>("INPUT") {
            self.args.filename = Some(filename.clone());
        } else {
            return Err(AvrStackError::new(
                ErrorCode::Parameter,
                file!(),
                line!(),
                "No input file specified"
            ));
        }

        if let Some(format) = matches.get_one::<String>("format") {
            match format.as_str() {
                "v4" => self.args.format = OutputFormat::V4,
                "v19" => self.args.format = OutputFormat::V19,
                "json" => {
                    self.args.format = OutputFormat::Json;
                    self.args.json_output = true;
                },
                _ => {
                    if let Ok(num) = format.parse::<u32>() {
                        match num {
                            4 => self.args.format = OutputFormat::V4,
                            19 => self.args.format = OutputFormat::V19,
                            _ => self.args.format = OutputFormat::Default,
                        }
                    }
                }
            }
        }

        self.args.total_only = matches.get_flag("total-only");
        self.args.allow_calls_from_isr = matches.get_flag("allow-calls-from-isr");
        self.args.wrap_0 = matches.get_flag("wrap0");
        self.args.include_bad_interrupt = matches.get_flag("include-bad-interrupt");
        self.args.ignore_icall_all = matches.get_flag("ignore-icall");
        self.args.memory_report = matches.get_flag("memory-report");

        if matches.get_flag("json") {
            self.args.json_output = true;
            self.args.format = OutputFormat::Json;
        }

        // Default to pretty JSON, set to compact if flag is present
        self.args.json_pretty = !matches.get_flag("json-compact");

        // Parse max recursion
        if let Some(max_rec) = matches.get_one::<String>("max-recursion") {
            if let Ok(depth) = max_rec.parse::<u32>() {
                self.args.max_recursion = depth;
            }
        }

        // Parse ignored functions
        if let Some(ignored) = matches.get_many::<String>("ignore-function") {
            for func in ignored {
                self.args.ignore_functions.push(func.clone());
            }
        }

        // Parse icall arguments (for specific icall handling)
        // This would involve parsing arguments like -ignoreICall=func+0x## and -iCall=func+0x##:dests

        // Add verbose option if not already there
        self.args.verbose = matches.is_present("verbose");
        
        // Set default for backward compatibility
        self.args.verbose = false;

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        // Add this at the beginning of the method
        self.debug_program_args_fields();
        
        println!("AVR Stack Analyzer v{} starting...", VERSION);

        // Parse command-line arguments
        self.parse_args()?;

        // Read and parse the ELF file
        if let Some(filename) = &self.args.filename {
            println!("Reading ELF file: {}", filename);
            self.elf.read_file(filename)?;
        } else {
            return Err(AvrStackError::new(
                ErrorCode::Parameter,
                file!(),
                line!(),
                "No input file specified"
            ));
        }

        // Initialize the CPU with the program data
        self.cpu.init(
            self.elf.get_text().to_vec(),
            self.elf.get_text_size(),
            self.elf.get_ram_start(),
        )?;

        // Set CPU options from program arguments
        self.cpu.wrap_0 = self.args.wrap_0;
        self.cpu.allow_calls_from_isr = self.args.allow_calls_from_isr;
        self.cpu.elf_info = Some(self.elf.clone());

        // Initialize architecture information
        self.arch.parse_standard_patterns()?;
        self.arch.guess_num_interrupt_vectors()?;
        self.arch.detect_memory_sizes(&self.elf)?;

        // Register any ignored functions in the maze analysis
        for func in &self.args.ignore_functions {
            println!("Ignoring function: {}", func);
            self.maze.add_ignored_function(func.to_string());
        }

        // Perform control flow analysis
        println!("Performing control flow analysis...");
        self.maze.analyze(&mut self.cpu, &self.arch)?;

        // Build the call tree
        println!("Building call tree...");
        self.tree.build(self.arch.num_isrs, &self.arch.isr, &self.cpu)?;

        // Generate the stack usage report
        self.tree.dump_stack_tree(&self.args)?;

        // Check for calls from interrupts
        if self.maze.calls_from_interrupt && !self.args.allow_calls_from_isr {
            return Err(AvrStackError::new(
                ErrorCode::CallFromIsr,
                file!(),
                line!(),
                "Calls from interrupts detected"
            ));
        }

        // Get the final results
        self.results = self.tree.get_results();

        // Output results in the requested format
        if self.args.json_output {
            self.output_json()?;
        }

        // Generate call graph if requested
        if self.args.call_graph {
            self.generate_call_graph()?;
        }

        // Add memory report at the end if requested
        self.generate_memory_report()?;

        println!("AVR Stack analysis completed successfully");
        Ok(())
    }

    pub fn output_json(&self) -> Result<()> {
        if let Some(filename) = &self.args.filename {
            let json_filename = format!("{}.json", filename);
            JsonWriter::new(&json_filename, self.args.json_pretty)?;
            // Write JSON output using writer
            // This would include all the analysis results

            // Also print a pretty-formatted version to the terminal
            self.print_terminal_friendly_json()?;
            println!("JSON output written to {}", json_filename);
            Ok(())
        } else {
            Err(AvrStackError::new(
                ErrorCode::Parameter,
                file!(),
                line!(),
                "No input file specified"
            ))
        }
    }

    fn print_terminal_friendly_json(&self) -> Result<()> {
        // Implementation for printing a terminal-friendly JSON output
        Ok(())
    }

    pub fn generate_call_graph(&self) -> Result<()> {
        if let Some(filename) = &self.args.filename {
            let dot_filename = format!("{}.dot", filename);
            let mut file = File::create(&dot_filename)
                .map_err(|e| AvrStackError::new(
                    ErrorCode::FileIo,
                    file!(),
                    line!(),
                    &format!("Failed to create DOT file: {}", e)
                ))?;

            // Write DOT file header with improved styling
            writeln!(file, "digraph CallGraph {{")?;
            writeln!(file, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")?;
            writeln!(file, "  edge [fontname=\"Helvetica\"];")?;
            writeln!(file, "  ranksep=1.5;")?;

            // Define node colors based on stack usage
            let max_stack = self.results.iter()
                .map(|r| r.stack_usage)
                .max()
                .unwrap_or(0);

            // Map of function addresses to better names (where available)
            let mut function_names = HashMap::new();

            // Build function name mapping
            for result in &self.results {
                // Extract address from name if it's a func_0xNNNN pattern
                if result.function_name.starts_with("func_0x") {
                    if let Ok(addr) = u32::from_str_radix(&result.function_name[6..], 16) {
                        function_names.insert(addr/2, result.function_name.clone());
                    }
                } else {
                    // For named functions, try to find the address
                    for &addr in self.cpu.stack_map.keys() {
                        if let Some(name) = self.cpu.get_symbol_name(addr) {
                            if name == result.function_name {
                                function_names.insert(addr, result.function_name.clone());
                                break;
                            }
                        }
                    }
                }
            }

            // Add nodes (functions) with better labeling and information
            for result in &self.results {
                let addr = result.address / 2; // Convert to word address
                let intensity = if max_stack > 0 {
                    result.stack_usage as f32 / max_stack as f32
                } else {
                    0.0
                };
                // Generate color from green (low stack) to red (high stack)
                let r = (intensity * 255.0) as u8;
                let g = ((1.0 - intensity) * 255.0) as u8;
                let b = 100u8;
                let color = format!("\"#{:02x}{:02x}{:02x}\"", r, g, b);

                // Try to determine function size for labeling
                let function_size = if let Some(ref elf) = self.cpu.elf_info {
                    elf.symbols.iter()
                       .find(|s| s.address == addr)
                       .map(|s| s.size)
                       .unwrap_or(0)
                } else {
                    0
                };

                // Write node definition with more information
                writeln!(file, "  \"{}\" [label=\"{}\nStack: {} bytes\nAddr: 0x{:x}{}\", fillcolor={}, tooltip=\"Address: 0x{:x}\"];",
                         result.function_name, 
                         result.function_name,
                         result.stack_usage,
                         result.address,
                         if function_size > 0 { format!("\nSize: {} bytes", function_size) } else { String::new() },
                         color,
                         result.address)?;
            }

            // Add edges (calls between functions) with better labeling
            for (caller, callees) in &self.cpu.call_graph {
                let caller_name = if let Some(name) = self.cpu.get_symbol_name(*caller) {
                    name
                } else if let Some(name) = function_names.get(caller) {
                    name.clone()
                } else {
                    format!("func_0x{:x}", caller * 2)
                };
                for callee in callees {
                    let callee_name = if let Some(name) = self.cpu.get_symbol_name(*callee) {
                        name
                    } else if let Some(name) = function_names.get(callee) {
                        name.clone()
                    } else {
                        format!("func_0x{:x}", callee * 2)
                    };
                    writeln!(file, "  \"{}\" -> \"{}\";", caller_name, callee_name)?;
                }
            }

            // Add a legend
            writeln!(file, "  subgraph cluster_legend {{")?;
            writeln!(file, "    label=\"Legend\";")?;
            writeln!(file, "    style=filled;")?;
            writeln!(file, "    color=lightgrey;")?;
            writeln!(file, "    \"Legend\" [shape=none, label=<")?;
            writeln!(file, "      <table border=\"0\" cellspacing=\"0\" cellpadding=\"2\">")?;
            writeln!(file, "        <tr><td>Node Color</td><td>Stack Usage</td></tr>")?;
            writeln!(file, "        <tr><td bgcolor=\"#00ff64\"></td><td>Low</td></tr>")?;
            writeln!(file, "        <tr><td bgcolor=\"#ffff64\"></td><td>Medium</td></tr>")?;
            writeln!(file, "        <tr><td bgcolor=\"#ff0064\"></td><td>High</td></tr>")?;
            writeln!(file, "      </table>")?;
            writeln!(file, "    >];")?;
            writeln!(file, "  }}")?;

            // Close the DOT file
            writeln!(file, "}}")?;

            println!("Enhanced call graph written to {}", dot_filename);
            println!("To generate a visual graph, use: dot -Tpng {} -o {}.png", dot_filename, filename);
            println!("For PDF format: dot -Tpdf {} -o {}.pdf", dot_filename, filename);

            Ok(())
        } else {
            Err(AvrStackError::new(
                ErrorCode::Parameter,
                file!(),
                line!(),
                "No input file specified"
            ))
        }
    }

    pub fn load_elf(&mut self, filename: &str) -> Result<()> {
        println!("Reading ELF file: {}", filename);
        
        // Read file data
        let file_data = std::fs::read(filename)
            .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Failed to read file {}: {}", filename, e)))?;
        
        if file_data.is_empty() {
            println!("ERROR: Input file is empty!");
            return Err(AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), "Input file is empty"));
        }
        
        // Parse ELF file
        let mut elf_info = crate::elf::ElfInfo::new();
        if let Ok(_) = elf_info.parse_elf(&file_data) {
            // Fix: Get a copy of any text section before it gets moved
            let mut found_program_data = false;
            
            // First try to get the .text section
            if let Some(section) = elf_info.get_text_section() {
                if !section.data.is_empty() {
                    let section_data = section.data.clone();
                    let data_len = section_data.len();
                    println!("Found .text section with {} bytes - loading for analysis", data_len);
                    
                    // Load the section data directly
                    self.cpu.prog = section_data;
                    self.cpu.prog_size = data_len as u32;
                    found_program_data = true;
                }
            }
            
            // If no .text section, try looking for any section with code data
            if !found_program_data {
                for (name, section) in &elf_info.sections {
                    if (name.contains("text") || name.contains("code")) && !section.data.is_empty() {
                        let section_data = section.data.clone();
                        let data_len = section_data.len();
                        println!("Found '{}' section with {} bytes - loading for analysis", name, data_len);
                        
                        // Load the section data directly
                        self.cpu.prog = section_data;
                        self.cpu.prog_size = data_len as u32;
                        found_program_data = true;
                        break;
                    }
                }
            }
            
            // Verify data was loaded
            if !found_program_data || self.cpu.prog.is_empty() {
                println!("WARNING: No valid program data found. Will use synthetic data.");
            } else {
                println!("Successfully loaded {} bytes of program data", self.cpu.prog.len());
            }
            
            // Store ELF info in CPU
            self.cpu.elf_info = Some(elf_info);
        }
        
        Ok(())
    }

    // Add verbosity control methods
    pub fn set_verbose(&mut self, verbose: bool) {
        self.args.verbose = verbose;
        self.cpu.verbose_output = verbose;
    }
    
    pub fn set_quiet(&mut self, quiet: bool) {
        self.args.quiet = quiet;
    }
    
    pub fn generate_terminal_summary(&self) -> Result<()> {
        // Skip if quiet mode
        if self.args.quiet {
            return Ok(());
        } else {
            // ...existing code...
            
            Ok(())
        }
    }

    // Add setter methods for all command-line options
    pub fn set_filename(&mut self, filename: String) {
        self.args.filename = Some(filename);
    }
    
    pub fn set_format(&mut self, format: String) {
        // Convert String to the correct OutputFormat enum
        match format.as_str() {
            "v4" => self.args.format = OutputFormat::V4,
            "v19" => self.args.format = OutputFormat::V19,
            "json" => self.args.format = OutputFormat::Json,
            _ => self.args.format = OutputFormat::V19, // Default
        }
    }
    
    pub fn set_total_only(&mut self, total_only: bool) {
        self.args.total_only = total_only;
    }
    
    pub fn set_allow_calls_from_isr(&mut self, allow: bool) {
        self.args.allow_calls_from_isr = allow;
        self.cpu.allow_calls_from_isr = allow;
    }
    
    pub fn set_wrap0(&mut self, wrap0: bool) {
        // Use the correct field name
        self.args.wrap_0 = wrap0;
    }
    
    pub fn set_include_bad_interrupt(&mut self, include: bool) {
        self.args.include_bad_interrupt = include;
    }
    
    pub fn set_ignore_icall(&mut self, ignore: bool) {
        // Use the correct field name
        self.args.ignore_icall_all = ignore;
    }
    
    pub fn set_memory_report(&mut self, memory_report: bool) {
        self.args.memory_report = memory_report;
    }
    
    pub fn set_json_output(&mut self, json_output: bool) {
        self.args.json_output = json_output;
    }
    
    pub fn set_compact_json(&mut self, _compact_json: bool) {
        // Since we don't know the right field name, just print a warning
        println!("Warning: Compact JSON option not fully implemented");
        
        // Make sure json_output is enabled at least
        self.args.json_output = true;
        
        // Note: We intentionally don't set any compact_json field since we don't know its name
    }
    
    pub fn set_call_graph(&mut self, call_graph: bool) {
        self.args.call_graph = call_graph;
    }
    
    // Add memory report functionality
    pub fn generate_memory_report(&self) -> Result<()> {
        if !self.args.memory_report {
            return Ok(());
        }
        
        println!("\n===== MEMORY USAGE REPORT =====");
        
        // Get the total program size
        let program_size = self.cpu.prog.len();
        println!("Program size: {} bytes", program_size);
        
        // Calculate maximum stack usage
        let max_stack = self.results.iter()
            .map(|r| r.stack_usage)
            .max()
            .unwrap_or(0);
        
        println!("Maximum stack usage: {} bytes", max_stack);
        
        // Calculate RAM usage estimate (assuming SRAM starts after registers)
        let ram_start = 32; // AVR registers take the first 32 bytes
        let estimated_ram_usage = ram_start + max_stack;
        
        // Typical AVR RAM sizes
        let ram_sizes = [
            ("ATtiny4/5/9/10", 32),
            ("ATtiny13", 64),
            ("ATtiny24/44/84", 128),
            ("ATtiny25/45/85", 128),
            ("ATtiny26", 128),
            ("ATtiny261/461/861", 128),
            ("ATtiny43U", 256),
            ("ATtiny48/88", 512),
            ("ATtiny1634", 1024),
            ("ATtiny2313/4313", 128),
            ("ATmega48/88/168", 1024),
            ("ATmega8", 1024),
            ("ATmega16/32", 1024),
            ("ATmega328/P", 2048),
            ("ATmega64/128", 4096),
            ("ATmega640/1280/2560", 8192),
        ];
        
        println!("\nRAM Usage Estimates:");
        println!("---------------------------------------------------");
        for (device, ram) in ram_sizes.iter() {
            let usage_percent = (estimated_ram_usage as f32 * 100.0) / (*ram as f32);
            let status = if usage_percent > 90.0 {
                "CRITICAL"
            } else if usage_percent > 75.0 {
                "WARNING"
            } else {
                "OK"
            };
            
            println!("{:25} {:4} bytes: {:6.1}% used - {}", 
                    device, ram, usage_percent, status);
        }
        
        println!("===================================");
        
        Ok(())
    }

    // Add this diagnostic function to print out the available fields
    fn debug_program_args_fields(&self) {
        println!("Available ProgramArgs fields:");
        println!("- format: {:?}", self.args.format);
        println!("- filename: {:?}", self.args.filename);
        println!("- allow_calls_from_isr: {}", self.args.allow_calls_from_isr);
        println!("- json_output: {}", self.args.json_output);
        // Add any other fields you know exist
        // This will help identify what fields are actually available
    }
}
