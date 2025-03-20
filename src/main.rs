// AVR Stack - Enhanced stack analyzer for AVR chips
// Version 38
// Original by Gary Scott (Dazed_N_Confused)
// Enhanced for comprehensive stack usage analysis
// 

use std::io;
use std::fs::File;
use std::path::Path;
use std::time::Instant;  // Add this for Instant
use std::process;        // Add this for process::exit
use clap::{App, Arg};    // Remove ArgMatches since it's unused

mod avr_stack;
mod cpu;
mod elf;
mod analysis;
mod utils;

use avr_stack::AvrStack;

fn main() {
    // Fix the syntax error with arg parsing
    let matches = App::new("AVR Stack Analyzer")
        .version("1.6.0")
        .author("Gary Scott (Dazed_N_Confused)")
        .about("Analyzes AVR ELF files to determine maximum stack usage")
        .arg(Arg::with_name("INPUT")
            .help("Sets the input ELF file to analyze")
            .required(true)
            .index(1))
        // Add other arguments
        // Add the verbose flag properly
        .arg(Arg::with_name("verbose")
            .long("verbose")
            .help("Show detailed warnings and analysis messages")
            .takes_value(false))
        .arg(Arg::with_name("quiet")
            .long("quiet")
            .help("Suppress all non-essential output")
            .takes_value(false))
        .get_matches();
        
    // Check data type sizes for cross-platform consistency
    assert_eq!(std::mem::size_of::<u32>(), 4);
    assert_eq!(std::mem::size_of::<i32>(), 4);
    assert_eq!(std::mem::size_of::<u16>(), 2);
    assert_eq!(std::mem::size_of::<i16>(), 2);
    assert_eq!(std::mem::size_of::<u8>(), 1);
    assert_eq!(std::mem::size_of::<i8>(), 1);
    
    println!("AVR Stack Analyzer starting...");
    
    // Create the analyzer and start timing
    let mut app = AvrStackAnalyzer::new();
    let start_time = Instant::now();
    
    // Set verbosity based on command line
    app.app.set_verbose(matches.is_present("verbose"));
    app.app.set_quiet(matches.is_present("quiet"));
    
    if let Err(e) = app.run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
    
    let elapsed = start_time.elapsed();
    println!("Analysis completed in {:.2} seconds", elapsed.as_secs_f64());
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
        
        if self.app.args.call_graph {
            if let Some(filename) = &self.app.args.filename {
                println!("Call graph saved to {}.dot", filename);
                println!("To visualize: dot -Tpng {}.dot -o {}.png", filename, filename);
            }
        }
        
        println!("=================================");
        
        Ok(())
    }
}
