// AVR Stack - My fancy stack analyzer for AVR chips
// Version 37 (Finally rewrote the whole thing in Rust!)
// Created by Gary Scott (Dazed_N_Confused)

use std::process;
use std::path::Path;
use std::fs::File;
use std::io::Write;

mod avr_stack;
mod cpu;
mod elf;
mod analysis;
mod utils;

use avr_stack::{AvrStack, ErrorCode};
use serde_json::{json, to_string_pretty};

fn main() {
    // Just double-checking our data types work as expected...
    // (not taking any chances with cross-platform issues)
    assert_eq!(std::mem::size_of::<u32>(), 4);
    assert_eq!(std::mem::size_of::<i32>(), 4);
    assert_eq!(std::mem::size_of::<u16>(), 2);
    assert_eq!(std::mem::size_of::<i16>(), 2);
    assert_eq!(std::mem::size_of::<u8>(), 1);
    assert_eq!(std::mem::size_of::<i8>(), 1);
    
    // Let's fire this thing up!
    let mut app = AvrStackAnalyzer::new();
    
    if let Err(e) = app.run() {
        eprintln!("{}", e);
        process::exit(1);
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
        // First things first - parse those command line args
        self.app.parse_args()?;
        
        // Now let's grab the ELF file and see what we're working with
        if let Some(filename) = &self.app.args.filename {
            self.app.elf.read_file(filename)?;
        } else {
            return Err(avr_stack::AvrStackError::new(
                ErrorCode::Parameter,
                file!(),
                line!(),
                "No input file specified"
            ));
        }
        
        // Feed that binary data into our CPU simulator
        self.app.cpu.init(
            self.app.elf.get_text().to_vec(),
            self.app.elf.get_text_size(),
            self.app.elf.get_ram_start()
        )?;
        
        // Setup any special CPU options from command line
        self.app.cpu.wrap_0 = self.app.args.wrap_0;
        self.app.cpu.elf_info = Some(self.app.elf.clone());
        
        // Setup our interrupt vectors - keeping it simple with 32
        // TODO: Maybe detect this from the ELF data someday?
        self.app.arch.num_isrs = 32;
        for i in 0..self.app.arch.num_isrs {
            self.app.arch.isr.push(format!("ISR_{}", i));
        }
        
        // OK, time for the magic - analyze all the control flows!
        self.app.maze.analyze(&mut self.app.cpu, &self.app.arch)?;
        
        // Now build up our call tree for stack depth analysis
        self.app.tree.build(self.app.arch.num_isrs, &self.app.arch.isr, &self.app.cpu)?;
        
        // Grab the final results
        self.app.results = self.app.tree.get_results();
        
        // Don't allow calls from ISRs unless explicitly permitted
        // (that's a common source of stack overflow disasters)
        if self.app.maze.calls_from_interrupt && !self.app.args.allow_calls_from_isr {
            return Err(avr_stack::AvrStackError::new(
                ErrorCode::CallFromIsr,
                file!(),
                line!(),
                "Calls from interrupts detected"
            ));
        }
        
        // Time to show what we found!
        self.output_results()?;
        
        println!("AVR Stack analysis completed successfully");
        
        Ok(())
    }
    
    fn output_results(&self) -> avr_stack::Result<()> {
        // Always show terminal output - it's nice to see results right away
        self.output_terminal_report()?;
        
        // We'll also save JSON if requested (or by default)
        if self.app.args.json_output {
            self.output_json_file()?;
        }
        
        Ok(())
    }
    
    fn output_terminal_report(&self) -> avr_stack::Result<()> {
        println!("\n===== STACK ANALYSIS RESULTS =====");
        
        // Find the biggest stack user - that's our limiting factor
        let mut total_max_stack = 0;
        for result in &self.app.results {
            if result.stack_usage > total_max_stack {
                total_max_stack = result.stack_usage;
            }
        }
        
        println!("Total maximum stack usage: {} bytes", total_max_stack);
        
        if !self.app.args.total_only {
            // Let's show details for each function too
            println!("\nFunction stack usage:");
            println!("{:<40} {:<10} {}", "FUNCTION", "ADDRESS", "STACK USAGE");
            println!("{:-<40} {:-<10} {:-<10}", "", "", "");
            
            // Sort by usage so the biggest offenders are at the top
            let mut sorted_results = self.app.results.clone();
            sorted_results.sort_by(|a, b| b.stack_usage.cmp(&a.stack_usage));
            
            for result in sorted_results {
                println!("{:<40} {:<10} {}", 
                         truncate_string(&result.function_name, 39), 
                         format!("0x{:x}", result.address),
                         format!("{}", result.stack_usage));
            }
        }
        
        println!("=================================");
        
        Ok(())
    }
    
    fn output_json_file(&self) -> avr_stack::Result<()> {
        if let Some(filename) = &self.app.args.filename {
            let json_filename = format!("{}.json", filename);
            
            // Build a nice data structure for the JSON output
            let mut functions = Vec::new();
            for result in &self.app.results {
                let function = json!({
                    "name": result.function_name,
                    "address": format!("0x{:x}", result.address),
                    "stack_usage": result.stack_usage,
                    "calls": result.calls
                });
                functions.push(function);
            }
            
            // Calculate max stack usage again - could refactor this
            // but it's cleaner to keep output functions independent
            let mut total_max_stack = 0;
            for result in &self.app.results {
                if result.stack_usage > total_max_stack {
                    total_max_stack = result.stack_usage;
                }
            }
            
            let json_data = json!({
                "total_stack_usage": total_max_stack,
                "functions": functions
            });
            
            // Save the file - either pretty or compact JSON
            let json_str = if self.app.args.json_pretty {
                to_string_pretty(&json_data).unwrap_or_else(|_| "{}".to_string())
            } else {
                json_data.to_string()
            };
            
            let mut file = File::create(Path::new(&json_filename))
                .map_err(|e| avr_stack::AvrStackError::new(
                    ErrorCode::FileIo,
                    file!(),
                    line!(),
                    &format!("Failed to create JSON file: {}", e)
                ))?;
            
            file.write_all(json_str.as_bytes())
                .map_err(|e| avr_stack::AvrStackError::new(
                    ErrorCode::FileIo,
                    file!(),
                    line!(),
                    &format!("Failed to write to JSON file: {}", e)
                ))?;
            
            println!("JSON output written to {}", json_filename);
        }
        
        Ok(())
    }
}

// Just a little helper to keep long function names from breaking the formatting
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[0..max_len-3])
    }
}
