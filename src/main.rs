// AVR Stack - Stack Usage Analyzer for AVR Binaries
// Version 37 (Rust Rewrite)

use std::process;

mod avr_stack;
mod cpu;
mod elf;
mod analysis;

use avr_stack::AvrStack;

fn main() {
    // Verify architecture assumptions
    assert_eq!(std::mem::size_of::<u32>(), 4);
    assert_eq!(std::mem::size_of::<i32>(), 4);
    assert_eq!(std::mem::size_of::<u16>(), 2);
    assert_eq!(std::mem::size_of::<i16>(), 2);
    assert_eq!(std::mem::size_of::<u8>(), 1);
    assert_eq!(std::mem::size_of::<i8>(), 1);
    
    // Initialize and run the application
    let mut app = AvrStack::new();
    
    if let Err(e) = app.run() {
        eprintln!("{}", e);
        process::exit(1);
    }
}
