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
    
    pub fn detect_memory_sizes(&mut self, elf: &ElfInfo) -> Result<()> {
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
        self.arch.guess_num_interrupt_vectors()?;
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
            let mut file = File::create(&dot_filename)?;
            
            writeln!(file, "digraph call_graph {{")?;
            
            // Generate the call graph in DOT format
            for (caller, callees) in &self.cpu.call_graph {
                for callee in callees {
                    writeln!(file, "  \"func_0x{:x}\" -> \"func_0x{:x}\";", caller * 2, callee * 2)?;
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
