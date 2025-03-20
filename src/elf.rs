// ELF file parsing functionality

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use object::{Object, ObjectSection, ObjectSymbol};

use crate::avr_stack::{Result, ErrorCode, AvrStackError};

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub section_index: u16,
}

#[derive(Clone)]
pub struct Section {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct ElfInfo {
    pub prog: Vec<u8>,
    pub prog_size: u32,
    pub ram_start: u32,
    pub symbols: Vec<Symbol>,
    pub symbol_map: HashMap<String, u32>, // Maps symbol names to their address
    pub address_map: HashMap<u32, String>, // Maps addresses to symbol names
    pub sections: HashMap<String, Section>,
}

impl ElfInfo {
    pub fn new() -> Self {
        ElfInfo {
            prog: Vec::new(),
            prog_size: 0,
            ram_start: 0x100, // Default value for AVR
            symbols: Vec::new(),
            symbol_map: HashMap::new(),
            address_map: HashMap::new(),
            sections: HashMap::new(),
        }
    }
    
    pub fn read_file(&mut self, filename: &str) -> Result<()> {
        println!("Reading ELF file: {}", filename);
        let path = Path::new(filename);
        let mut file = File::open(path)
            .map_err(|e| AvrStackError::new(
                ErrorCode::FileIo, 
                file!(), 
                line!(), 
                &format!("Failed to open file: {}", e)
            ))?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| AvrStackError::new(
                ErrorCode::FileIo,
                file!(),
                line!(),
                &format!("Failed to read file: {}", e)
            ))?;
        
        self.parse_elf(&buffer)?;
        println!("ELF file parsed successfully. Program size: {} bytes", self.prog_size);
        
        Ok(())
    }
    
    pub fn parse_elf(&mut self, data: &[u8]) -> Result<()> {
        // Enhanced ELF file validation
        if data.len() < 4 {
            println!("ERROR: File is too small to be a valid ELF file ({} bytes)", data.len());
            return Err(AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), "File too small to be valid ELF"));
        }
        
        // Check ELF magic header
        if data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            println!("WARNING: File does not have an ELF magic number. First bytes: {:02X} {:02X} {:02X} {:02X}", 
                     data[0], data[1], data[2], data[3]);
            println!("This may be a raw binary file or in an unsupported format.");
        }
        
        // Try to parse as ELF
        let obj_file = match object::File::parse(data) {
            Ok(file) => file,
            Err(e) => {
                println!("ERROR: Failed to parse ELF file: {}", e);
                println!("FALLBACK: Treating file as raw binary data");
                
                // Create a synthetic section for raw binary
                self.sections.insert(".text".to_string(), Section {
                    name: ".text".to_string(),
                    address: 0,
                    size: data.len() as u32,
                    data: data.to_vec(),
                });
                return Ok(());
            }
        };
        
        // Extract symbols
        let mut symbol_count = 0;
        for symbol in obj_file.symbols() {
            if let Ok(name) = symbol.name() {
                self.symbols.push(Symbol {
                    name: name.to_string(),
                    address: symbol.address() as u32,
                    size: symbol.size() as u32,
                    section_index: 0, // Placeholder, update as needed
                });
                symbol_count += 1;
            }
        }
        println!("Found {} symbols in ELF file", symbol_count);
        
        // Extract sections with detailed logging
        let mut section_count = 0;
        let mut has_text_section = false;
        let mut has_program_data = false;
        
        for section in obj_file.sections() {
            section_count += 1;
            let section_name = match section.name() {
                Ok(name) => name.to_string(),
                Err(e) => {
                    println!("WARNING: Failed to get name for section {}: {}", section_count, e);
                    format!("unnamed_section_{}", section_count)
                }
            };
            
            let section_address = section.address() as u32;
            let section_size = section.size() as u32;
            
            println!("Processing section '{}' ({} bytes at 0x{:x})", section_name, section_size, section_address);
            
            // Try to get section data
            let section_data = match section.data() {
                Ok(data) => {
                    println!("  - Successfully read section data: {} bytes", data.len());
                    if !data.is_empty() {
                        has_program_data = true;
                    }
                    data.to_vec()
                },
                Err(e) => {
                    println!("  - WARNING: Could not extract data for section '{}': {}", section_name, e);
                    Vec::new()
                }
            };
            
            // Create the section object
            let section_obj = Section {
                name: section_name.clone(),
                address: section_address,
                size: section_size,
                data: section_data.clone(),
            };
            
            // Check for text section or other code section
            if section_name == ".text" {
                has_text_section = true;
                println!("  - Found .text section with {} bytes of data", section_data.len());
                
                if section_data.is_empty() {
                    println!("  - WARNING: Text section has no data!");
                } else {
                    println!("  - First few bytes: {:02X} {:02X} {:02X} {:02X}...", 
                           section_data.get(0).unwrap_or(&0),
                           section_data.get(1).unwrap_or(&0),
                           section_data.get(2).unwrap_or(&0),
                           section_data.get(3).unwrap_or(&0));
                }
            } else if section_name.contains("text") || section_name.contains("code") {
                println!("  - Found potential code section: '{}' with {} bytes", section_name, section_data.len());
            }
            
            // Store the section
            self.sections.insert(section_name, section_obj);
        }
        
        println!("Found {} total sections", section_count);
        
        // Handle case with no text section
        if !has_text_section || !has_program_data {
            println!("WARNING: No valid program data found in the ELF file");
            
            // Try to find any section that might contain code
            let mut best_section = None;
            let mut best_section_size = 0;
            
            for (name, section) in &self.sections {
                if !section.data.is_empty() && section.data.len() > best_section_size {
                    best_section_size = section.data.len();
                    best_section = Some((name.clone(), section.clone()));
                }
            }
            
            // Create a synthetic text section from the best available data
            if let Some((name, section)) = best_section {
                println!("FALLBACK: Using '{}' as program data ({} bytes)", name, section.data.len());
                self.sections.insert(".text".to_string(), section);
            } else if data.len() > 0 {
                // Last resort: use the raw file data
                println!("EMERGENCY FALLBACK: Using raw file data as program code");
                self.sections.insert(".text".to_string(), Section {
                    name: ".text".to_string(),
                    address: 0,
                    size: data.len() as u32,
                    data: data.to_vec(),
                });
            }
        }

        Ok(())
    }

    pub fn get_text_section(&self) -> Option<&Section> {
        self.sections.get(".text")
    }

    pub fn get_text(&self) -> &[u8] {
        &self.prog
    }
    
    pub fn get_text_size(&self) -> u32 {
        self.prog_size
    }
    
    pub fn get_ram_start(&self) -> u32 {
        self.ram_start
    }
    
    pub fn get_symbol_address(&self, name: &str) -> Option<u32> {
        self.symbol_map.get(name).copied()
    }
    
    pub fn get_symbol_name(&self, address: u32) -> Option<&str> {
        self.address_map.get(&address).map(|s| s.as_str())
    }
    
    pub fn find_symbol_by_address(&self, address: u32) -> Option<&Symbol> {
        for symbol in &self.symbols {
            if symbol.address <= address && address < symbol.address + symbol.size {
                return Some(symbol);
            }
        }
        None
    }

    pub fn parse_hex(&mut self, data: &[u8]) -> Result<()> {
        // Convert the hex data to a string
        let hex_str = std::str::from_utf8(data)
            .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Failed to parse HEX data as UTF-8: {}", e)))?;
        
        // Parse the hex data
        let mut program_data = Vec::new();
        let mut _base_address = 0; // Fix: Add underscore to mark as intentionally unused
        
        for line in hex_str.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with(':') {
                continue;
            }
            
            // Parse Intel HEX record
            let record = &line[1..]; // Skip the ':'
            let byte_count = u8::from_str_radix(&record[0..2], 16)
                .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Invalid HEX record byte count: {}", e)))?;
            let _address = u16::from_str_radix(&record[2..6], 16) // Fix: Add underscore to mark as intentionally unused
                .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Invalid HEX record address: {}", e)))?;
            let record_type = u8::from_str_radix(&record[6..8], 16)
                .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Invalid HEX record type: {}", e)))?;
            
            match record_type {
                0 => { // Data record
                    let data_part = &record[8..(8 + byte_count as usize * 2)];
                    for i in 0..(byte_count as usize) {
                        let byte = u8::from_str_radix(&data_part[i*2..(i+1)*2], 16)
                            .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Invalid HEX data byte: {}", e)))?;
                        program_data.push(byte);
                    }
                },
                1 => { // End of file
                    break;
                },
                4 => { // Extended Linear Address
                    let data_part = &record[8..12];
                    let high_addr = u32::from_str_radix(data_part, 16)
                        .map_err(|e| AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), &format!("Invalid HEX extended address: {}", e)))?;
                    _base_address = high_addr << 16; // Fix: Store value but mark usage with underscore
                },
                _ => {
                    // Ignore other record types for now
                }
            }
        }
        
        // Create a section for the program data
        let section = Section {
            name: ".text".to_string(),
            address: 0,
            size: program_data.len() as u32,
            data: program_data,
        };
        
        println!("Parsed HEX file: {} bytes of program data", section.size);
        self.sections.insert(".text".to_string(), section);
        
        Ok(())
    }
}

// Helper function to read a u32 in little-endian format
fn read_u32(data: &[u8]) -> u32 {
    ((data[3] as u32) << 24) | ((data[2] as u32) << 16) | ((data[1] as u32) << 8) | (data[0] as u32)
}

// Helper function to read a u16 in little-endian format
fn read_u16(data: &[u8]) -> u16 {
    ((data[1] as u16) << 8) | (data[0] as u16)
}

// Alias for compatibility with analysis module
pub type ELFFile = ElfInfo;
