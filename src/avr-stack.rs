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

// Allow dead code in this module as many items will be used in the future
#[allow(dead_code)]

pub const VERSION: &str = "38";  // Updated for enhanced version

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
    
    // Specific error codes
    RetiExpected = 1000,
    RetiUnexpected,
    StackChangeLoop,
    NegativeStackChange,
    Recursion,
    CallFromIsr,
    StackOverflow,
    InvalidCallGraph,
    InvalidAddress,
}

#[derive(Debug)]
pub struct AvrStackError {
    code: ErrorCode,
    message: String,
    file: String,
    line: u32,
}

impl AvrStackError {
    pub fn new(code: ErrorCode, file: &str, line: u32, message: &str) -> Self {
        AvrStackError {
            code,
            message: message.to_string(),
            file: file.to_string(),
            line,
        }
    }
    
    pub fn code(&self) -> ErrorCode {
        self.code
    }
}

impl fmt::Display for AvrStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ERROR ({}:{}) [{}]: {} - v{}", 
               self.file, self.line, self.code as u32, self.message, VERSION)
    }
}

impl StdError for AvrStackError {}

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
        ErrorCode::StackOverflow => "Stack overflow detected",
        ErrorCode::InvalidCallGraph => "Invalid call graph",
        ErrorCode::InvalidAddress => "Invalid address",
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

#[derive(Debug, Clone)]
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
    pub json_pretty: bool,
    pub call_graph: bool,  // New option for call graph visualization
    pub max_recursion: u32, // New option for recursion limit
    pub icall_list: Vec<MainICall>,
    pub ignore_functions: Vec<String>, // New option for ignored functions
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
            json_output: true, // Default to JSON output in the enhanced version
            json_pretty: true,  // Default to pretty-printing JSON for terminal readability
            call_graph: false,  // Off by default
            max_recursion: 10,  // Default recursion limit
            icall_list: Vec::new(),
            ignore_functions: Vec::new(),
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
            write!(self.file, ",")?;
            if self.pretty_print {
                writeln!(self.file)?;
            }
        } else {
            self.first_item = false;
        }
        
        self.write_indent()?;
        write!(self.file, "{{")?;
        if self.pretty_print {
            writeln!(self.file)?;
        }
        self.indent += 1;
        self.first_item = true;
        Ok(())
    }
    
    pub fn end_object(&mut self) -> io::Result<()> {
        self.indent -= 1;
        if self.pretty_print {
            writeln!(self.file)?;
        }
        self.write_indent()?;
        write!(self.file, "}}")?;
        self.first_item = false;
        Ok(())
    }
    
    pub fn begin_array(&mut self) -> io::Result<()> {
        if !self.first_item {
            write!(self.file, ",")?;
            if self.pretty_print {
                writeln!(self.file)?;
            }
        } else {
            self.first_item = false;
        }
        
        self.write_indent()?;
        write!(self.file, "[")?;
        if self.pretty_print {
            writeln!(self.file)?;
        }
        self.indent += 1;
        self.first_item = true;
        self.is_array = true;
        Ok(())
    }
    
    pub fn end_array(&mut self) -> io::Result<()> {
        self.indent -= 1;
        if self.pretty_print {
            writeln!(self.file)?;
        }
        self.write_indent()?;
        write!(self.file, "]")?;
        self.first_item = false;
        self.is_array = false;
        Ok(())
    }
    
    pub fn write_property_name(&mut self, name: &str) -> io::Result<()> {
        if !self.first_item {
            write!(self.file, ",")?;
            if self.pretty_print {
                writeln!(self.file)?;
            }
        } else {
            self.first_item = false;
        }
        
        self.write_indent()?;
        write!(self.file, "\"{}\":", name)?;
        if self.pretty_print {
            write!(self.file, " ")?;
        }
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
    pub flash_size: u32,
    pub ram_size: u32,
    pub ram_start: u32,
    pub program_start: u32,
}

impl ArchInfo {
    pub fn new() -> Self {
        ArchInfo {
            num_isrs: 0,
            isr: Vec::new(),
            flash_size: 0,
            ram_size: 0,
            ram_start: 0x100, // Default for AVR
            program_start: 0,
        }
    }
    
    pub fn parse_standard_patterns(&mut self) -> Result<()> {
        // Implementation for pattern recognition
        // This would identify compiler-specific code patterns
        Ok(())
    }
    
    pub fn guess_num_interrupt_vectors(&mut self, elf: &ElfInfo) -> Result<()> {
        // Try to determine the number of interrupt vectors from the ELF symbols
        let mut max_vector = 0;
        
        for symbol in &elf.symbols {
            if symbol.name.starts_with("__vector_") {
                // Extract the vector number from the name
                if let Some(num_str) = symbol.name.strip_prefix("__vector_") {
                    if let Ok(num) = num_str.parse::<u32>() {
                        if num > max_vector {
                            max_vector = num;
                        }
                    }
                }
            }
        }
        
        // Add 1 because vectors are 0-indexed
        if max_vector > 0 {
            self.num_isrs = max_vector + 1;
            
            // Create ISR names
            self.isr.clear();
            for i in 0..self.num_isrs {
                self.isr.push(format!("__vector_{}", i));
            }
            
            println!("Detected {} interrupt vectors", self.num_isrs);
        } else {
            // Default to 32 vectors if we couldn't determine
            self.num_isrs = 32;
            
            // Create ISR names
            self.isr.clear();
            for i in 0..self.num_isrs {
                self.isr.push(format!("ISR_{}", i));
            }
            
            println!("Using default of {} interrupt vectors", self.num_isrs);
        }
        
        Ok(())
    }
    
    pub fn detect_memory_sizes(&mut self, elf: &ElfInfo) -> Result<()> {
        // Try to determine memory sizes from ELF file
        // For now, use some default values
        self.flash_size = 32 * 1024; // 32KB flash (typical for many AVRs)
        self.ram_size = 2 * 1024;    // 2KB RAM (typical for many AVRs)
        self.ram_start = elf.get_ram_start();
        
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
            .about("Enhanced stack usage analyzer for AVR binaries")
            .arg(Arg::new("INPUT")
                .help("Input ELF file")
                .required(true)
                .index(1))
            .arg(Arg::new("format")
                .long("format")
                .value_name("FORMAT")
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
        self.args.call_graph = matches.get_flag("call-graph");
        
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
        // This would involve parsing arguments like -ignoreICall=func+0x## and -iCall=func+0x##:dest
        
        Ok(())
    }
    
    pub fn run(&mut self) -> Result<()> {
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
            self.elf.get_ram_start()
        )?;
        
        // Set CPU options from program arguments
        self.cpu.wrap_0 = self.args.wrap_0;
        self.cpu.allow_calls_from_isr = self.args.allow_calls_from_isr;
        self.cpu.elf_info = Some(self.elf.clone());
        
        // Initialize architecture information
        self.arch.parse_standard_patterns()?;
        self.arch.guess_num_interrupt_vectors(&self.elf)?;
        self.arch.detect_memory_sizes(&self.elf)?;
        
        // Register any ignored functions in the maze analysis
        for func in &self.args.ignore_functions {
            println!("Ignoring function: {}", func);
            self.maze.add_ignored_function(func);
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
        
        println!("AVR Stack analysis completed successfully");
        
        Ok(())
    }
    
    pub fn output_json(&self) -> Result<()> {
        if let Some(filename) = &self.args.filename {
            let json_filename = format!("{}.json", filename);
            let mut writer = JsonWriter::new(&json_filename, self.args.json_pretty)?;
            
            // Start the main object
            writer.begin_object()?;
            
            // Add metadata
            writer.write_property_string("version", VERSION)?;
            if let Some(name) = &self.args.filename {
                writer.write_property_string("input_file", name)?;
            }
            
            // Calculate total max stack
            let mut total_max_stack = 0;
            for result in &self.results {
                if result.stack_usage > total_max_stack {
                    total_max_stack = result.stack_usage;
                }
            }
            writer.write_property_uint("total_stack_usage", total_max_stack)?;
            
            // Write memory information if requested
            if self.args.memory_report {
                writer.write_property_name("memory")?;
                writer.begin_object()?;
                writer.write_property_uint("flash_size", self.arch.flash_size)?;
                writer.write_property_uint("ram_size", self.arch.ram_size)?;
                writer.write_property_uint("ram_start", self.arch.ram_start)?;
                writer.write_property_hex("program_start", self.arch.program_start)?;
                writer.end_object()?;
            }
            
            // Write function information
            writer.write_property_name("functions")?;
            writer.begin_array()?;
            
            // Sort results by stack usage (descending)
            let mut sorted_results = self.results.clone();
            sorted_results.sort_by(|a, b| b.stack_usage.cmp(&a.stack_usage));
            
            for result in sorted_results {
                writer.begin_object()?;
                writer.write_property_string("name", &result.function_name)?;
                writer.write_property_hex("address", result.address)?;
                writer.write_property_uint("stack_usage", result.stack_usage)?;
                
                // Add call chain
                writer.write_property_name("call_chain")?;
                writer.begin_array()?;
                for call in &result.calls {
                    writer.write_string(call)?;
                    if call != result.calls.last().unwrap() {
                        writer.write_indent()?;
                        write!(writer.file, ",")?;
                        if writer.pretty_print {
                            writeln!(writer.file)?;
                        }
                    }
                }
                writer.end_array()?;
                
                writer.end_object()?;
            }
            
            writer.end_array()?;
            
            // End the main object
            writer.end_object()?;
            
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
            
            // Write DOT file header
            writeln!(file, "digraph CallGraph {{")?;
            writeln!(file, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")?;
            writeln!(file, "  edge [fontname=\"Helvetica\"];")?;
            
            // Define node colors based on stack usage
            let max_stack = self.results.iter()
                .map(|r| r.stack_usage)
                .max()
                .unwrap_or(0);
            
            // Add nodes (functions)
            for result in &self.results {
                // Calculate color intensity based on stack usage
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
                
                // Write node definition
                writeln!(file, "  \"{}\" [label=\"{}\nStack: {} bytes\nAddr: 0x{:x}\", fillcolor={}];",
                         result.function_name, 
                         result.function_name,
                         result.stack_usage,
                         result.address,
                         color)?;
            }
            
            // Add edges (calls between functions)
            for (caller, callees) in &self.cpu.call_graph {
                if let Some(caller_name) = self.elf.get_symbol_name(*caller) {
                    for callee in callees {
                        if let Some(callee_name) = self.elf.get_symbol_name(*callee) {
                            writeln!(file, "  \"{}\" -> \"{}\";", caller_name, callee_name)?;
                        } else {
                            writeln!(file, "  \"{}\" -> \"func_0x{:x}\";", caller_name, callee * 2)?;
                        }
                    }
                } else {
                    for callee in callees {
                        if let Some(callee_name) = self.elf.get_symbol_name(*callee) {
                            writeln!(file, "  \"func_0x{:x}\" -> \"{}\";", caller * 2, callee_name)?;
                        } else {
                            writeln!(file, "  \"func_0x{:x}\" -> \"func_0x{:x}\";", caller * 2, callee * 2)?;
                        }
                    }
                }
            }
            
            // Close the DOT file
            writeln!(file, "}}")?;
            
            println!("Call graph written to {}", dot_filename);
            println!("To generate a visual graph, use: dot -Tpng {} -o {}.png", dot_filename, filename);
            
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
}
