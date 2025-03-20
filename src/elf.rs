// ELF file parsing functionality

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::avr_stack::{Result, ErrorCode, AvrStackError};

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u32,
    pub size: u32,
    pub section_index: u16,
}

#[derive(Clone)]
pub struct ElfInfo {
    pub prog: Vec<u8>,
    pub prog_size: u32,
    pub ram_start: u32,
    pub symbols: Vec<Symbol>,
    pub symbol_map: HashMap<String, u32>, // Maps symbol names to their address
    pub address_map: HashMap<u32, String>, // Maps addresses to symbol names
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
        // Check ELF magic number
        if data.len() < 16 || data[0] != 0x7F || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
            return Err(AvrStackError::new(
                ErrorCode::InvalidElf,
                file!(),
                line!(),
                "Not a valid ELF file"
            ));
        }
        
        // Simple parsing of ELF header for AVR
        let is_32bit = data[4] == 1;
        let is_little_endian = data[5] == 1;
        
        if !is_32bit || !is_little_endian {
            return Err(AvrStackError::new(
                ErrorCode::InvalidElf,
                file!(),
                line!(),
                "Only 32-bit little-endian ELF files are supported"
            ));
        }
        
        // Parse section header table
        let e_shoff = read_u32(&data[32..36]);
        let e_shentsize = read_u16(&data[46..48]);
        let e_shnum = read_u16(&data[48..50]);
        let e_shstrndx = read_u16(&data[50..52]);
        
        // Read section header string table
        let shstrtab_offset = e_shoff + (e_shentsize as u32 * e_shstrndx as u32);
        let shstrtab_offset_in_file = read_u32(&data[(shstrtab_offset + 16) as usize..(shstrtab_offset + 20) as usize]);
        
        // Find .text section and symbol table
        let mut text_section_offset = 0;
        let mut text_section_size = 0;
        let mut symtab_offset = 0;
        let mut symtab_size = 0;
        let mut symtab_entsize = 0;
        let mut strtab_offset = 0;
        
        for i in 0..e_shnum {
            let section_offset = e_shoff + (i as u32 * e_shentsize as u32);
            let section_name_offset = read_u32(&data[section_offset as usize..(section_offset + 4) as usize]);
            let section_name_index = shstrtab_offset_in_file + section_name_offset;
            
            // Read section name
            let mut section_name = String::new();
            let mut j = section_name_index as usize;
            while j < data.len() && data[j] != 0 {
                section_name.push(data[j] as char);
                j += 1;
            }
            
            let _section_type = read_u32(&data[(section_offset + 4) as usize..(section_offset + 8) as usize]);
            let section_offset_in_file = read_u32(&data[(section_offset + 16) as usize..(section_offset + 20) as usize]);
            let section_size_in_file = read_u32(&data[(section_offset + 20) as usize..(section_offset + 24) as usize]);
            
            if section_name == ".text" {
                text_section_offset = section_offset_in_file;
                text_section_size = section_size_in_file;
            } else if section_name == ".symtab" {
                symtab_offset = section_offset_in_file;
                symtab_size = section_size_in_file;
                symtab_entsize = read_u32(&data[(section_offset + 36) as usize..(section_offset + 40) as usize]);
            } else if section_name == ".strtab" {
                strtab_offset = section_offset_in_file;
            }
        }
        
        if text_section_offset == 0 || text_section_size == 0 {
            return Err(AvrStackError::new(
                ErrorCode::InvalidElf,
                file!(),
                line!(),
                "No .text section found"
            ));
        }
        
        // Extract .text section
        self.prog = data[text_section_offset as usize..(text_section_offset + text_section_size) as usize].to_vec();
        self.prog_size = text_section_size;
        
        // Parse symbol table if available
        if symtab_offset > 0 && symtab_size > 0 && strtab_offset > 0 {
            let num_symbols = symtab_size / symtab_entsize;
            
            for i in 0..num_symbols {
                let symbol_offset = symtab_offset + (i * symtab_entsize);
                
                let sym_name_offset = read_u32(&data[symbol_offset as usize..(symbol_offset + 4) as usize]);
                let sym_value = read_u32(&data[(symbol_offset + 4) as usize..(symbol_offset + 8) as usize]);
                let sym_size = read_u32(&data[(symbol_offset + 8) as usize..(symbol_offset + 12) as usize]);
                let sym_info = data[(symbol_offset + 12) as usize];
                let sym_section_idx = read_u16(&data[(symbol_offset + 14) as usize..(symbol_offset + 16) as usize]);
                
                // Only consider symbols that might be functions
                // 0x02 = STT_FUNC (function type)
                let sym_type = sym_info & 0xF;
                if sym_type == 0x2 { // STT_FUNC
                    // Read symbol name
                    let mut sym_name = String::new();
                    let mut j = (strtab_offset + sym_name_offset) as usize;
                    while j < data.len() && data[j] != 0 {
                        sym_name.push(data[j] as char);
                        j += 1;
                    }
                    
                    if !sym_name.is_empty() {
                        let symbol = Symbol {
                            name: sym_name.clone(),
                            address: sym_value,
                            size: sym_size,
                            section_index: sym_section_idx,
                        };
                        
                        self.symbols.push(symbol);
                        self.symbol_map.insert(sym_name.clone(), sym_value);
                        self.address_map.insert(sym_value, sym_name);
                    }
                }
            }
        }
        
        // Log some information about what we found
        println!("Found {} symbols", self.symbols.len());
        
        Ok(())
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
