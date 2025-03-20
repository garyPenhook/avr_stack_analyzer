use crate::elf::ElfInfo;
use std::fs::File;
use std::io::Write;

pub struct DebugUtils;

impl DebugUtils {
    pub fn dump_sections(elf_info: &ElfInfo, filename: &str) -> std::io::Result<()> {
        // Create a detailed report of all sections
        let mut report = String::new();
        report.push_str("=== AVR Stack Analyzer Section Debug Report ===\n\n");
        report.push_str(&format!("File: {}\n\n", filename));
        
        // List all sections
        report.push_str("SECTIONS:\n");
        report.push_str("---------------------------------------------------\n");
        report.push_str("Name                 | Address    | Size       | Data\n");
        report.push_str("-------------------- | ---------- | ---------- | ----\n");
        
        let mut has_executable_section = false;
        let mut largest_section_size = 0;
        let mut largest_section_name = String::new();
        
        if elf_info.sections.is_empty() {
            report.push_str("NO SECTIONS FOUND!\n");
            report.push_str("This is a critical error. The ELF parser was unable to extract any sections.\n");
        }
        
        for (name, section) in &elf_info.sections {
            // Mark executable sections
            let executable_marker = if name.contains("text") || name.contains("code") {
                has_executable_section = true;
                "*"
            } else {
                " "
            };
            
            // Track largest section
            if section.data.len() > largest_section_size {
                largest_section_size = section.data.len();
                largest_section_name = name.clone();
            }
            
            // Show first few bytes of data
            let data_preview = if section.data.is_empty() {
                "[empty]".to_string()
            } else {
                let mut preview = String::new();
                for i in 0..std::cmp::min(8, section.data.len()) {
                    preview.push_str(&format!("{:02X} ", section.data[i]));
                }
                preview.push_str("...");
                preview
            };
            
            report.push_str(&format!("{}{:<19} | 0x{:08x} | {:10} | {}\n", 
                              executable_marker, name, section.address, section.data.len(), data_preview));
        }
        
        // Add summary
        report.push_str("\nSUMMARY:\n");
        report.push_str("---------------------------------------------------\n");
        report.push_str(&format!("Total sections: {}\n", elf_info.sections.len()));
        report.push_str(&format!("Has executable section: {}\n", has_executable_section));
        report.push_str(&format!("Largest section: {} ({} bytes)\n", 
                            largest_section_name, largest_section_size));
        
        // Recommendation
        report.push_str("\nRECOMMENDATION:\n");
        report.push_str("---------------------------------------------------\n");
        if !has_executable_section && largest_section_size > 0 {
            report.push_str(&format!("No executable section found, but there is data in section '{}'.\n", 
                                largest_section_name));
            report.push_str("Try using this section as program data.\n");
        } else if largest_section_size == 0 {
            report.push_str("No section contains data. The ELF file may be corrupted or empty.\n");
            report.push_str("Try using a different file format or rebuilding the original binary.\n");
        }
        
        // Write report to file
        let debug_filename = format!("{}.sections.txt", filename);
        let mut file = File::create(&debug_filename)?;
        file.write_all(report.as_bytes())?;
        
        println!("Section debug info written to {}", debug_filename);
        Ok(())
    }
    
    pub fn extract_best_program_data(elf_info: &ElfInfo) -> Vec<u8> {
        // Try first to get the .text section
        if let Some(section) = elf_info.get_text_section() {
            if !section.data.is_empty() {
                println!("Using .text section: {} bytes", section.data.len());
                return section.data.clone();
            } else {
                println!("WARNING: .text section exists but has no data");
            }
        } else {
            println!("WARNING: No .text section found");
        }
        
        // Try to find any section containing code
        for (name, section) in &elf_info.sections {
            if (name.contains("text") || name.contains("code")) && !section.data.is_empty() {
                println!("Using '{}' section: {} bytes", name, section.data.len());
                return section.data.clone();
            }
        }
        
        // If all else fails, use the largest non-empty section
        let mut largest_section = None;
        let mut max_size = 0;
        
        for (name, section) in &elf_info.sections {
            if section.data.len() > max_size {
                max_size = section.data.len();
                largest_section = Some((name.clone(), section.clone()));
            }
        }
        
        if let Some((name, section)) = largest_section {
            println!("No code section found. Using largest section '{}': {} bytes", name, section.data.len());
            return section.data;
        }
        
        // If we get here, there's no data at all
        println!("ERROR: No program data found in any section");
        Vec::new()
    }
}
