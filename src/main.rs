// AVR Stack - Enhanced stack analyzer for AVR chips
// Version 38
// Original by Gary Scott (Dazed_N_Confused)
// Enhanced for comprehensive stack usage analysis
// 

#[allow(unused_imports)]
use std::io;
#[allow(unused_imports)]
use std::fs::File;
#[allow(unused_imports)]
use std::path::Path;
use std::time::Instant;
use std::process;
use clap::{App, Arg};

mod avr_stack;
mod cpu;
mod elf;
mod analysis;
mod utils;

use avr_stack::AvrStack;

fn main() {
    let matches = App::new("AVR Stack Analyzer")
        .version("1.6.0")
        .author("Gary Scott (Dazed_N_Confused)")
        .about("Analyzes AVR ELF files to determine maximum stack usage")
        .arg(Arg::with_name("INPUT")
            .help("Sets the input ELF file to analyze")
            .required(true)
            .index(1))
        .arg(Arg::with_name("format")
            .long("format")
            .help("Output format (v4, v19, or json)")
            .takes_value(true))
        .arg(Arg::with_name("total-only")
            .long("total-only")
            .help("Print only total stack usage"))
        .arg(Arg::with_name("allow-calls-from-isr")
            .long("allow-calls-from-isr")
            .help("Don't error on calls from ISRs"))
        .arg(Arg::with_name("wrap0")
            .long("wrap0")
            .help("Allow wrapped addresses at address 0"))
        .arg(Arg::with_name("include-bad-interrupt")
            .long("include-bad-interrupt")
            .help("Include bad_interrupt in analysis"))
        .arg(Arg::with_name("ignore-icall")
            .long("ignore-icall")
            .help("Ignore all indirect calls"))
        .arg(Arg::with_name("memory-report")
            .long("memory-report")
            .help("Show memory statistics"))
        .arg(Arg::with_name("json")
            .long("json")
            .help("Output in JSON format"))
        .arg(Arg::with_name("json-compact")
            .long("json-compact")
            .help("Output compact JSON format"))
        .arg(Arg::with_name("verbose")
            .long("verbose")
            .help("Show detailed warnings and analysis messages"))
        .arg(Arg::with_name("quiet")
            .long("quiet")
            .help("Suppress non-essential output"))
        .get_matches();

    // Check data type sizes for cross-platform consistency
    assert_eq!(std::mem::size_of::<u32>(), 4);
    assert_eq!(std::mem::size_of::<i32>(), 4);
    assert_eq!(std::mem::size_of::<u16>(), 2);
    assert_eq!(std::mem::size_of::<i16>(), 2);
    assert_eq!(std::mem::size_of::<u8>(), 1);
    assert_eq!(std::mem::size_of::<i8>(), 1);
    
    println!("AVR Stack Analyzer starting...");
    
    // Parse all command line arguments and set them in the app
    if let Some(input_file) = matches.value_of("INPUT") {
        let mut app = AvrStackAnalyzer::new();
        app.app.set_filename(input_file.to_string());
        
        // Set options based on command-line flags
        if matches.is_present("total-only") {
            app.app.set_total_only(true);
        }
        
        if matches.is_present("allow-calls-from-isr") {
            app.app.set_allow_calls_from_isr(true);
        }
        
        if matches.is_present("wrap0") {
            app.app.set_wrap0(true);
        }
        
        if matches.is_present("include-bad-interrupt") {
            app.app.set_include_bad_interrupt(true);
        }
        
        if matches.is_present("ignore-icall") {
            app.app.set_ignore_icall(true);
        }
        
        if matches.is_present("memory-report") {
            app.app.set_memory_report(true);
        }
        
        if matches.is_present("json") {
            app.app.set_json_output(true);
        }
        
        if matches.is_present("json-compact") {
            app.app.set_compact_json(true);
        }
        
        if let Some(format_val) = matches.value_of("format") {
            app.app.set_format(format_val.to_string());
        }
        
        // Set verbosity options
        app.app.set_verbose(matches.is_present("verbose"));
        app.app.set_quiet(matches.is_present("quiet"));
        
        // Run the analysis with properly set options
        let start_time = Instant::now();
        
        if let Err(e) = app.run() {
            println!("Error: {}", e);
            process::exit(1);
        }
        
        let duration = start_time.elapsed();
        println!("Analysis completed in {:.2} seconds", duration.as_secs_f32());
    }
}

struct AvrStackAnalyzer {
    app: AvrStack,
}

impl AvrStackAnalyzer {
    fn new() -> Self {
        AvrStackAnalyzer {
            app: AvrStack::new(),
        }
    }
    
    fn run(&mut self) -> avr_stack::Result<()> {
        // Parse command-line arguments
        self.app.parse_args()?;
        
        // Run the analysis
        match self.app.run() {
            Ok(_) => {},
            Err(e) => {
                // Fix: Use accessor methods instead of direct field access
                if e.code() == avr_stack::ErrorCode::InvalidElf && e.message().contains("No program data") {
                    println!("\nERROR: No program data found in the input file.");
                    println!("This usually happens when the ELF file is corrupted or in an unsupported format.");
                    println!("Try using the original ELF file from your compiler rather than a stripped/converted version.");
                    return Err(e);
                }
                return Err(e);
            }
        }
        
        // Generate summary report
        self.generate_terminal_summary()?;
        
        Ok(())
    }
    
    fn generate_terminal_summary(&self) -> avr_stack::Result<()> {
        // Calculate some statistics
        let total_functions = self.app.results.len();
        let _total_stack = 0;  // Add underscore to mark as intentionally unused
        let mut max_stack = 0;
        let mut max_stack_func = "";
        let mut stack_over_100 = 0;
        let mut stack_over_50 = 0;
        let mut stack_under_10 = 0;
        
        for result in &self.app.results {
            if result.stack_usage > max_stack {
                max_stack = result.stack_usage;
                max_stack_func = &result.function_name;
            }
            
            if result.stack_usage > 100 {
                stack_over_100 += 1;
            } else if result.stack_usage > 50 {
                stack_over_50 += 1;
            } else if result.stack_usage < 10 {
                stack_under_10 += 1;
            }
        }
        
        println!("\n===== STACK ANALYSIS SUMMARY =====");
        println!("Total functions analyzed: {}", total_functions);
        println!("Maximum stack usage: {} bytes (in function: {})", max_stack, max_stack_func);
        
        if self.app.maze.calls_from_interrupt {
            if self.app.args.allow_calls_from_isr {
                println!("WARNING: Calls from ISRs detected (allowed by command-line option)");
            } else {
                println!("ERROR: Calls from ISRs detected");
            }
        }
        
        println!("\nStack usage statistics:");
        println!("- Functions using > 100 bytes: {}", stack_over_100);
        println!("- Functions using 50-100 bytes: {}", stack_over_50);
        println!("- Functions using < 10 bytes: {}", stack_under_10);
        
        println!("\nRecommendations:");
        if max_stack > self.app.arch.ram_size / 2 {
            println!("! CRITICAL: Maximum stack usage is over 50% of available RAM");
            println!("  Consider refactoring {} to use less stack", max_stack_func);
        } else if max_stack > self.app.arch.ram_size / 4 {
            println!("! WARNING: Maximum stack usage is over 25% of available RAM");
            println!("  Consider monitoring stack usage in large functions");
        } else {
            println!("✓ Stack usage appears to be within reasonable limits");
        }
        
        if self.app.args.json_output {
            if let Some(filename) = &self.app.args.filename {
                println!("\nDetailed results saved to {}.json", filename);
            }
        }
        
        println!("=================================");
        
        Ok(())
    }
}
