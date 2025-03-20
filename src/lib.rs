//! AVR Stack Analyzer Library
//!
//! A specialized tool for analyzing stack usage in AVR microcontroller binaries.

// Suppress dead code warnings for incomplete parts of the implementation
#![allow(dead_code)]

// Re-export main modules
pub mod avr_stack;
pub mod cpu;
pub mod elf;
pub mod analysis;
pub mod utils;
pub mod debug_utils;
// Remove binary_loader module since we integrated it directly

// Re-export key items for easier usage
pub use avr_stack::AvrStack;
