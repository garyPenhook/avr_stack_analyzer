use std::fs;
use std::path::Path;
use crate::avr_stack::{Result, AvrStackError, ErrorCode};
use crate::elf::ElfInfo;

/// Types of binary files we can load
#[derive(Debug, PartialEq)]
pub enum BinaryType {
    Elf,
    Hex,
    Raw,
    Unknown,
}

pub struct BinaryLoader;

impl BinaryLoader {
    /// Load program data from a binary file, trying multiple strategies
    pub fn load_binary(filename: &str) -> Result<Vec<u8>> {
        println!("Loading binary file: {}", filename);
        
        // Read the raw file data
        let file_data = fs::read(filename)
            .map_err(|e| AvrStackError::new(ErrorCode::IoError, file!(), line!(), 
                                        &format!("Failed to read file {}: {}", filename, e)))?;
        
        if file_data.is_empty() {
            return Err(AvrStackError::new(ErrorCode::InvalidElf, file!(), line!(), 
                                      "File is empty"));
        }
        
        println!("File size: {} bytes", file_data.len());
        
        // Determine the file type
        let binary_type = Self::detect_binary_type(filename, &file_data);
        println!("Detected file type: {:?}", binary_type);
        
        // Try multiple strategies to extract program data
        let program_data = match binary_type {
            BinaryType::Elf => Self::extract_elf_program_data(filename, &file_data)?,
            BinaryType::Hex => Self::extract_hex_program_data(filename, &file_data)?,
            _ => {
                println!("WARNING: Using raw file data as program code. This may not be accurate.");
                file_data.clone()
            }
        };
        
        if program_data.is_empty() {
            println!("ERROR: Failed to extract program data from {}", filename);
            println!("Please ensure the file contains executable code and is not stripped.");
            
            // Last resort - just use the raw file
            println!("EMERGENCY FALLBACK: Using raw file contents as program data");
            return Ok(file_data);
        }
        
        println!("Successfully loaded {} bytes of program data", program_data.len());
        
        // Show the first few bytes for debugging
        if program_data.len() >= 8 {
            println!("First 8 bytes: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                     program_data[0], program_data[1], program_data[2], program_data[3],
                     program_data[4], program_data[5], program_data[6], program_data[7]);
        }
        
        Ok(program_data)
    }
    
    /// Detect the type of binary file
    fn detect_binary_type(filename: &str, data: &[u8]) -> BinaryType {
        // Check extension first
        let path = Path::new(filename);
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_lowercase();
            if ext == "hex" || ext == "ihx" {
                return BinaryType::Hex;
            }
            if ext == "elf" || ext == "o" {
                return BinaryType::Elf;
            }
            if ext == "bin" {
                return BinaryType::Raw;
            }
        }
        
        // Check file header
        if data.len() >= 4 {
            // ELF magic: 0x7F 'E' 'L' 'F'
            if data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
                return BinaryType::Elf;
            }
            
            // Intel HEX files start with ":"
            if data[0] == b':' {
                return BinaryType::Hex;
            }
        }
        
        BinaryType::Unknown
    }
    
    /// Extract program data from an ELF file, trying multiple strategies
    fn extract_elf_program_data(_filename: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Parse ELF file
        let mut elf_info = ElfInfo::new();
        match elf_info.parse_elf(data) {
            Ok(_) => {},
            Err(e) => {
                println!("WARNING: Error parsing ELF file: {}", e);
                return Ok(Vec::new());
            }
        }
        
        // Strategy 1: Get .text section directly
        if let Some(section) = elf_info.get_text_section() {
            if !section.data.is_empty() {
                println!("Found .text section with {} bytes", section.data.len());
                return Ok(section.data.clone());
            }
        }
        
        // Strategy 2: Look for any section with "text" or "code" in name
        for (name, section) in &elf_info.sections {
            if (name.contains("text") || name.contains("code")) && !section.data.is_empty() {
                println!("Using '{}' section with {} bytes", name, section.data.len());
                return Ok(section.data.clone());
            }
        }
        
        // Strategy 3: Find the largest non-empty section
        let mut largest_section = None;
        let mut largest_size = 0;
        
        for (name, section) in &elf_info.sections {
            if section.data.len() > largest_size {
                largest_size = section.data.len();
                largest_section = Some((name.clone(), section.clone()));
            }
        }
        
        if let Some((name, section)) = largest_section {
            println!("Using largest section '{}' with {} bytes", name, section.data.len());
            return Ok(section.data);
        }
        
        // No valid program data found
        println!("No valid program data found in ELF file");
        Ok(Vec::new())
    }
    
    /// Extract program data from a HEX file
    fn extract_hex_program_data(_filename: &str, data: &[u8]) -> Result<Vec<u8>> {
        // Basic HEX file parsing (Intel HEX format)
        let mut program_data = Vec::new();
        
        // Convert data to string
        let hex_str = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                println!("ERROR: HEX file is not valid UTF-8 text");
                return Ok(Vec::new());
            }
        };
        
        // Parse each line
        for line in hex_str.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with(':') {
                continue;
            }
            
            // Skip the leading ":"
            let line = &line[1..];
            if line.len() < 10 {
                continue; // Too short to be valid
            }
            
            // Parse record type
            let record_type = match u8::from_str_radix(&line[6..8], 16) {
                Ok(t) => t,
                Err(_) => continue,
            };
            
            // Only process data records (type 00)
            if record_type != 0 {
                continue;
            }
            
            // Parse byte count
            let byte_count = match u8::from_str_radix(&line[0..2], 16) {
                Ok(c) => c as usize,
                Err(_) => continue,
            };
            
            // Ensure line is long enough
            if line.len() < 8 + byte_count * 2 {
                continue;
            }
            
            // Extract data bytes
            for i in 0..byte_count {
                let start = 8 + i * 2;
                let end = start + 2;
                if end <= line.len() {
                    if let Ok(byte) = u8::from_str_radix(&line[start..end], 16) {
                        program_data.push(byte);
                    }
                }
            }
        }
        
        if program_data.is_empty() {
            println!("ERROR: No valid data found in HEX file");
        } else {
            println!("Parsed {} bytes from HEX file", program_data.len());
        }
        
        Ok(program_data)
    }
}
