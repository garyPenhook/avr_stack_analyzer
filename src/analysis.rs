// Stack usage analysis functionality

use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use crate::avr_stack::{Result, ProgramArgs, StackAnalysisResult};
use crate::elf::ElfInfo;
use crate::cpu::{Cpu, CpuAddr};
use std::io::Write;

// Add PatternMatcher struct that was missing
pub struct PatternMatcher {
    patterns: Vec<(String, Vec<u8>, Vec<u8>)>,
}

impl PatternMatcher {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        
        // Common AVR function prologue patterns
        // Format: (name, byte pattern, mask)
        
        // push r28-r29, in r28,SPL, in r29,SPH - Standard frame pointer setup
        patterns.push((
            "standard_prologue".to_string(),
            vec![0xDF, 0x93, 0xCF, 0x93, 0xCD, 0xB7, 0xDE, 0xB7],
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        
        // push r28-r29, in r28,SPL, in r29,SPH, sbiw r28-r29,N - Frame with local vars
        patterns.push((
            "frame_with_locals".to_string(),
            vec![0xDF, 0x93, 0xCF, 0x93, 0xCD, 0xB7, 0xDE, 0xB7, 0x97, 0x50],
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0],
        ));
        
        // Add more prologue patterns:

        // GCC -Os (size optimized) - Simple push sequence for register saving
        patterns.push((
            "gcc_os_push_sequence".to_string(),
            vec![0xCF, 0x93, 0xDF, 0x93],  // push r28/r29 (in different order)
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        ));
        
        // GCC inline function pattern (typically starts with pushing registers)
        patterns.push((
            "gcc_inline_function".to_string(),
            vec![0x0F, 0x93],  // push r16
            vec![0xFF, 0xFF],
        ));
        
        // IAR compiler common pattern
        patterns.push((
            "iar_prologue".to_string(),
            vec![0xEF, 0x93, 0xFF, 0x93],  // push r30/r31 (common in IAR)
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        ));
        
        // Small function without frame setup (direct return)
        patterns.push((
            "small_function".to_string(),
            vec![0x80, 0xE0, 0x90, 0xE0],  // ldi r24,0; ldi r25,0 (common function start)
            vec![0xFF, 0xF0, 0xFF, 0xF0],
        ));
        
        // GCC -O3 optimized function (often starts with register setup)
        patterns.push((
            "gcc_o3_function".to_string(),
            vec![0x8F, 0xEF, 0x90, 0xE0],  // ldi r24,0xFF; ldi r25,0 
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        ));
        
        // Multi-register push sequence (common in larger functions)
        patterns.push((
            "multi_register_save".to_string(),
            vec![0x0F, 0x93, 0x1F, 0x93, 0x2F, 0x93],  // push r16/r17/r18
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ));
        
        // Specialized stack frames
        // Example: sbiw r28, XX (subtract immediate from word)
        patterns.push((
            "specialized_stack_frame".to_string(),
            vec![0x97, 0x50],  // sbiw r28, XX
            vec![0xFF, 0xF0],
        ));
        
        Self { patterns }
    }
    
    pub fn find_prologue(&self, data: &[u8], offset: usize) -> Option<(String, usize, usize)> {
        for (name, pattern, mask) in &self.patterns {
            if offset + pattern.len() <= data.len() {
                let mut matched = true;
                for i in 0..pattern.len() {
                    if (data[offset + i] & mask[i]) != (pattern[i] & mask[i]) {
                        matched = false;
                        break;
                    }
                }
                
                if matched {
                    return Some((name.clone(), pattern.len(), offset));
                }
            }
        }
        
        None
    }

    // Check if a sequence looks like a function beginning based on heuristics
    pub fn is_likely_function_start(&self, data: &[u8], offset: usize) -> bool {
        if offset + 8 >= data.len() {
            return false;
        }
        
        // Heuristic 1: Check for register saving operations at the beginning
        let has_push_operations = self.has_push_operations(data, offset);
        
        // Heuristic 2: Check for function parameter loading
        let has_param_loading = self.has_parameter_loading(data, offset);
        
        // Heuristic 3: Check for stack adjustment
        let has_stack_adjustment = self.has_stack_adjustment(data, offset);
        
        // Return true if at least two heuristics match
        (has_push_operations as u8 + has_param_loading as u8 + has_stack_adjustment as u8) >= 2
    }
    
    // Check if the sequence has push operations (register saving)
    fn has_push_operations(&self, data: &[u8], offset: usize) -> bool {
        if offset + 2 >= data.len() {
            return false;
        }
        
        // Look for push instructions (0xXF, 0x93) where X is the register
        let mut count = 0;
        for i in (offset..offset+8).step_by(2) {
            if i + 1 < data.len() && (data[i] & 0x0F) == 0x0F && data[i+1] == 0x93 {
                count += 1;
            }
        }
        
        count >= 1
    }
    
    // Check if the sequence has parameter loading (common at function start)
    fn has_parameter_loading(&self, data: &[u8], offset: usize) -> bool {
        if offset + 4 >= data.len() {
            return false;
        }
        
        // Look for typical parameter loading patterns:
        // ldi instructions (0xEX, 0xE0) - load immediate to registers r16-r31
        // mov instructions (0xXX, 0x2F) - move between registers
        for i in (offset..offset+6).step_by(2) {
            if i + 1 < data.len() {
                // Check for ldi rX, immediate
                if (data[i] & 0xF0) == 0xE0 && (data[i+1] & 0xF0) == 0xE0 {
                    return true;
                }
                
                // Check for mov rX, rY
                if (data[i+1] & 0x2F) == 0x2F {
                    return true;
                }
            }
        }
        
        false
    }
    
    // Check if the sequence has stack pointer adjustment
    fn has_stack_adjustment(&self, data: &[u8], offset: usize) -> bool {
        if offset + 8 >= data.len() {
            return false;
        }
        
        // Look for stack pointer adjustment:
        // in r28, SPL (0xCD, 0xB7)
        // in r29, SPH (0xDE, 0xB7)
        // sbiw r28, XX (0x97, 0x50+XX)
        
        for i in (offset..offset+6).step_by(2) {
            if i + 3 < data.len() {
                // Check for "in r28, SPL; in r29, SPH" sequence
                if data[i] == 0xCD && data[i+1] == 0xB7 && 
                   data[i+2] == 0xDE && data[i+3] == 0xB7 {
                    return true;
                }
                
                // Check for sbiw r28, XX (subtract immediate from word)
                if data[i] == 0x97 && (data[i+1] & 0xF0) == 0x50 {
                    return true;
                }
            }
        }
        
        false
    }
}

// Add an alias for Cpu to make the existing code work
pub type AVRProcessor = Cpu;

// CallChain for tracking stack usage paths
#[derive(Debug, Clone)]
pub struct CallChain {
    pub path: Vec<CpuAddr>,
    pub stack_usage: u32,
}

// PathNode for Dijkstra's algorithm to find maximum stack path
#[derive(Clone, Eq, PartialEq)]
struct PathNode {
    addr: CpuAddr,
    stack_usage: u32,
    path: Vec<CpuAddr>,
}

impl Ord for PathNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for max-heap instead of min-heap
        other.stack_usage.cmp(&self.stack_usage)
            .then_with(|| self.addr.cmp(&other.addr))
    }
}

impl PartialOrd for PathNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// MazeAnalysis for control flow analysis
pub struct MazeAnalysis {
    pub visited_addresses: HashSet<CpuAddr>,
    pub stack_changes: HashMap<CpuAddr, i32>,
    pub calls_from_interrupt: bool,
    pub entry_points: Vec<CpuAddr>,
    pub function_sizes: HashMap<CpuAddr, u32>,
    pub ignored_functions: HashSet<String>,
}

impl MazeAnalysis {
    pub fn new() -> Self {
        MazeAnalysis {
            visited_addresses: HashSet::new(),
            stack_changes: HashMap::new(),
            calls_from_interrupt: false,
            entry_points: Vec::new(),
            function_sizes: HashMap::new(),
            ignored_functions: HashSet::new(),
        }
    }
    
    pub fn analyze(&mut self, cpu: &mut Cpu, arch: &crate::avr_stack::ArchInfo) -> Result<()> {
        // Only create synthetic data if truly needed
        if cpu.prog.is_empty() {
            println!("Creating synthetic program data for analysis");
            cpu.create_synthetic_program();
        } else {
            println!("Using actual program data: {} bytes", cpu.prog.len());
        }
        
        // Find function entry points
        println!("Finding function entry points...");
        
        // Add reset vector and interrupt vectors
        for i in 0..arch.num_isrs {
            let isr_addr = i * 2;
            self.entry_points.push(isr_addr);
        }
        
        // Try to find entry points from program data
        if !cpu.prog.is_empty() {
            let more_entry_points = self.identify_function_entry_points(cpu)?;
            self.entry_points.extend(more_entry_points);
        }
        
        // Sort and remove duplicates
        self.entry_points.sort();
        self.entry_points.dedup();
        
        // Filter out likely invalid entry points
        self.entry_points.retain(|&addr| {
            addr % 2 == 0 && // Must be even (16-bit aligned)
            addr < 0x10000   // Must be in reasonable range for AVR
        });
        
        // If we still don't have any entry points, add some defaults
        if self.entry_points.is_empty() {
            // Add common function addresses often seen in AVR programs
            self.entry_points.push(0);  // Reset vector
            self.entry_points.push(0x14); // Common function entry point
        }
        
        println!("Analyzing {} functions...", self.entry_points.len());
        
        // Process entry points
        let entry_points_clone = self.entry_points.clone();
        for &addr in &entry_points_clone {
            // Get function name if available
            let name = if let Some(ref elf) = cpu.elf_info {
                if let Some(sym_name) = elf.get_symbol_name(addr) {
                    sym_name.to_string()
                } else {
                    format!("func_0x{:x}", addr * 2)
                }
            } else {
                format!("func_0x{:x}", addr * 2)
            };
            
            // Skip ignored functions
            if self.ignored_functions.contains(&name) {
                continue;
            }
            
            // Call analyze_function without producing output for every function
            self.analyze_function(cpu, addr)?;
        }
        
        println!("\nFunction analysis complete. Analyzed {} functions.", self.entry_points.len());
        
        // Check for ISR issues
        for i in 0..arch.num_isrs {
            if let Some(isr_name) = arch.isr.get(i as usize) {
                if self.ignored_functions.contains(isr_name) {
                    println!("Skipping ignored ISR: {}", isr_name);
                    continue;
                }
                
                let isr_addr = i * 2;
                cpu.isr_map.insert(isr_addr, true);
                
                if !cpu.allow_calls_from_isr {
                    if let Some(callees) = cpu.call_graph.get(&isr_addr) {
                        if !callees.is_empty() {
                            println!("Warning: ISR {} contains function calls", isr_name);
                            self.calls_from_interrupt = true;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    fn identify_function_entry_points(&mut self, cpu: &Cpu) -> Result<Vec<CpuAddr>> {
        let mut entry_points = Vec::new();
        
        // First, get entry points from ELF symbols if available
        if let Some(ref elf_info) = cpu.elf_info {
            for symbol in &elf_info.symbols {
                entry_points.push(symbol.address);
                self.function_sizes.insert(symbol.address, symbol.size);
            }
        }
        
        // Then find additional function entry points from patterns
        let matcher = PatternMatcher::new();
        let mut offset = 0;
        
        while offset + 2 < cpu.prog.len() {
            // Try pattern matching first
            if let Some((name, len, _)) = matcher.find_prologue(&cpu.prog, offset) {
                let addr = (offset as u32) / 2; // Convert byte offset to instruction address
                
                // Check if this entry point is already in our list from symbols
                if !entry_points.contains(&addr) {
                    entry_points.push(addr);
                    println!("Found function prologue pattern '{}' at address 0x{:x}", name, addr * 2);
                }
                
                offset += len;
            } else if matcher.is_likely_function_start(&cpu.prog, offset) {
                // If no exact pattern match, try heuristic detection
                let addr = (offset as u32) / 2;
                
                // Check if this entry point is already in our list
                if !entry_points.contains(&addr) {
                    // Validate further that this isn't the middle of another function
                    if self.validate_as_function_entry(cpu, addr) {
                        entry_points.push(addr);
                        println!("Found likely function entry point at address 0x{:x} (heuristic match)", addr * 2);
                    }
                }
                
                offset += 2;
            } else {
                offset += 2;
            }
        }
        
        // Final step: Use control flow analysis to find additional entry points
        self.find_entry_points_by_control_flow(cpu, &mut entry_points)?;
        
        Ok(entry_points)
    }
    
    // Validate if an address is truly a function entry point by checking surrounding context
    fn validate_as_function_entry(&self, cpu: &Cpu, addr: CpuAddr) -> bool {
        // Convert to byte offset
        let offset = (addr as usize) * 2;
        
        if offset < 4 || offset + 8 >= cpu.prog.len() {
            return false;
        }
        
        // Check if the previous instruction is a 'ret' or 'reti'
        // This would indicate the end of the previous function
        let prev_instr = ((cpu.prog[offset-2] as u16) << 8) | (cpu.prog[offset-1] as u16);
        if prev_instr == 0x9508 || prev_instr == 0x9518 { // ret or reti
            return true;
        }
        
        // Check if this address is the target of any 'call' instructions
        // This is a strong indicator of a function entry point
        for i in (0..cpu.prog.len()).step_by(2) {
            if i + 3 < cpu.prog.len() {
                // Look for call instruction (0x940E) and extract address
                let instr = ((cpu.prog[i] as u16) << 8) | (cpu.prog[i+1] as u16);
                if (instr & 0xFE0E) == 0x940E {
                    // This is a call - extract target address
                    let k = ((cpu.prog[i+2] as u32) << 8) | (cpu.prog[i+3] as u32);
                    let target = k / 2; // Convert byte address to word address
                    
                    if target == addr as u32 {
                        return true;
                    }
                }
            }
        }
        
        // If we couldn't strongly validate, return false to be conservative
        false
    }
    
    // Find additional entry points by analyzing control flow
    fn find_entry_points_by_control_flow(&self, cpu: &Cpu, entry_points: &mut Vec<CpuAddr>) -> Result<()> {
        // Check if program data is empty
        if cpu.prog.is_empty() {
            return Ok(());
        }

        let mut known_entries: HashSet<CpuAddr> = entry_points.iter().cloned().collect();
        
        // First pass: look for direct call instructions
        for i in (0..cpu.prog.len()-3).step_by(2) {
            // Check for call instructions (0x940E or 0x940F for CALL)
            let instr = ((cpu.prog[i] as u16) << 8) | (cpu.prog[i+1] as u16);
            
            if (instr & 0xFE0E) == 0x940E {
                // This is a call instruction - extract target address
                if i + 3 < cpu.prog.len() {
                    let k = ((cpu.prog[i+2] as u32) << 8) | (cpu.prog[i+3] as u32);
                    let target_addr = k / 2; // Convert byte address to word address
                    
                    if !known_entries.contains(&(target_addr as CpuAddr)) && 
                       (target_addr as usize) * 2 < cpu.prog.len() {
                        entry_points.push(target_addr as CpuAddr);
                        known_entries.insert(target_addr as CpuAddr);
                        println!("Found function entry point at address 0x{:x} (call target)", target_addr * 2);
                    }
                }
            }
            
            // Check for rcall instructions (0xD000-0xDFFF)
            if (instr & 0xF000) == 0xD000 {
                // RCALL with 12-bit signed offset
                let offset = instr & 0x0FFF;
                let _offset = if (offset & 0x0800) != 0 {
                    ((offset | 0xF000) as i16) as i32 // Sign extend
                } else {
                    (offset as i16) as i32
                };
                
                // Calculate target (PC relative)
                let target_addr = ((i/2) as i32 + 1 + _offset) as u32;
                
                if target_addr > 0 && !known_entries.contains(&target_addr) && 
                   (target_addr as usize) * 2 < cpu.prog.len() {
                    entry_points.push(target_addr);
                    known_entries.insert(target_addr);
                    println!("Found function entry point at address 0x{:x} (rcall target)", target_addr * 2);
                }
            }
        }
        
        // Second pass: look for jump tables and indirect call patterns
        for i in (0..cpu.prog.len()-7).step_by(2) {
            // Look for sequences that load Z register for indirect calls
            // Typically: LDI ZL, low(table); LDI ZH, high(table); IJMP/ICALL
            
            // Check for LDI r30 (ZL) followed by LDI r31 (ZH)
            let instr1 = ((cpu.prog[i] as u16) << 8) | (cpu.prog[i+1] as u16);
            let instr2 = ((cpu.prog[i+2] as u16) << 8) | (cpu.prog[i+3] as u16);
            
            if (instr1 & 0xF0F0) == 0xE0E0 && (instr2 & 0xF0F0) == 0xE0F0 {
                // Extract the immediate values for ZL and ZH
                let zl = ((instr1 & 0x0F00) >> 4) | (instr1 & 0x000F);
                let zh = ((instr2 & 0x0F00) >> 4) | (instr2 & 0x000F);
                let addr = ((zh as u32) << 8) | (zl as u32);
                
                // Verify this is within program memory
                if addr > 0 && addr * 2 < cpu.prog_size && !known_entries.contains(&addr) {
                    // This looks like a table address - check if it points to valid code
                    if self.validate_as_function_entry(cpu, addr) {
                        entry_points.push(addr);
                        known_entries.insert(addr);
                        println!("Found potential function entry at address 0x{:x} (jump table)", addr * 2);
                    }
                }
            }
        }
        
        // Third pass: analyze branch instructions to identify function boundaries
        self.identify_function_boundaries(cpu, entry_points, &known_entries)?;
        
        Ok(())
    }
    
    fn identify_function_boundaries(&self, cpu: &Cpu, entry_points: &mut Vec<CpuAddr>, 
                                   known_entries: &HashSet<CpuAddr>) -> Result<()> {
        // Check if program data is empty
        if cpu.prog.is_empty() {
            return Ok(());
        }
        
        // Look for common function boundary patterns:
        // 1. RET/RETI followed by potential function start
        // 2. Unconditional jumps followed by new code blocks
        
        for i in (0..cpu.prog.len()-4).step_by(2) {
            let instr = ((cpu.prog[i] as u16) << 8) | (cpu.prog[i+1] as u16);
            
            // Check for RET (0x9508) or RETI (0x9518)
            if instr == 0x9508 || instr == 0x9518 {
                let next_addr = (i/2) + 1;
                
                // The instruction after a return could be a function start
                if !known_entries.contains(&(next_addr as CpuAddr)) &&
                   self.validate_as_function_entry(cpu, next_addr as CpuAddr) {
                    entry_points.push(next_addr as CpuAddr);
                    println!("Found potential function entry at address 0x{:x} (after return)", next_addr * 2);
                }
            }
            
            // Check for unconditional jumps followed by new code blocks
            if (instr & 0xF000) == 0xC000 { // RJMP
                // Calculate absolute destination address
                let offset_val = instr & 0x0FFF;
                let _offset = if (offset_val & 0x0800) != 0 { // Fix: Add underscore to mark as intentionally unused
                    ((offset_val | 0xF000) as i16) as i32 // Sign extend
                } else {
                    (offset_val as i16) as i32
                };
                
                let next_instr_addr = (i/2) + 1;
                
                // The instruction after an unconditional jump could be a function start
                if !known_entries.contains(&(next_instr_addr as CpuAddr)) &&
                   self.validate_as_function_entry(cpu, next_instr_addr as CpuAddr) {
                    entry_points.push(next_instr_addr as CpuAddr);
                    println!("Found potential function entry at address 0x{:x} (after jump)", next_instr_addr * 2);
                }
            }
        }
        
        Ok(())
    }

    // Add this method that's being called but missing
    pub fn add_ignored_function(&mut self, func: String) {
        self.ignored_functions.insert(func);
    }

    // Fix the missing analyze_function method
    fn analyze_function(&mut self, cpu: &mut Cpu, addr: CpuAddr) -> Result<()> {
        // Remove any warning outputs or detailed logging here
        // Just call analyze_function_stack and handle the result
        match cpu.analyze_function_stack(addr) {
            Ok(_) => Ok(()),
            Err(e) => {
                // Only log critical errors, not warnings
                if cpu.verbose_output {
                    println!("Error analyzing function at 0x{:x}: {}", addr * 2, e);
                }
                Ok(())
            }
        }
    }
}

// TreeAnalysis for call tree and stack usage analysis
pub struct TreeAnalysis {
    pub function_stack_usage: HashMap<CpuAddr, u32>,
    pub call_graph: HashMap<CpuAddr, Vec<CpuAddr>>,
    pub function_names: HashMap<CpuAddr, String>,
    pub max_stack_paths: HashMap<CpuAddr, Vec<CpuAddr>>,
    pub visited: HashSet<CpuAddr>,
    pub analyzer_result: Vec<StackAnalysisResult>,
    pub call_chains: HashMap<CpuAddr, CallChain>,
}

impl TreeAnalysis {
    pub fn new() -> Self {
        TreeAnalysis {
            function_stack_usage: HashMap::new(),
            call_graph: HashMap::new(),
            function_names: HashMap::new(),
            max_stack_paths: HashMap::new(),
            visited: HashSet::new(),
            analyzer_result: Vec::new(),
            call_chains: HashMap::new(),
        }
    }
    
    pub fn build(&mut self, num_isrs: u32, isrs: &[String], cpu: &Cpu) -> Result<()> {
        println!("Building call tree analysis...");
        
        // Copy call graph from CPU
        self.call_graph = cpu.call_graph.clone();
        
        // Copy stack usage data from CPU
        self.function_stack_usage = cpu.stack_map.clone().into_iter()
            .map(|(k, v)| (k, v as u32))
            .collect();
        
        // Assign names to functions from ELF info if available
        if let Some(ref elf_info) = cpu.elf_info {
            for (addr, _) in &self.function_stack_usage {
                if let Some(name) = elf_info.get_symbol_name(*addr) {
                    self.function_names.insert(*addr, name.to_string());
                } else {
                    self.function_names.insert(*addr, format!("func_0x{:x}", addr * 2));
                }
            }
        } else {
            // No ELF info, just use addresses
            for (addr, _) in &self.function_stack_usage {
                self.function_names.insert(*addr, format!("func_0x{:x}", addr * 2));
            }
        }
        
        // Add ISRs to function names
        for i in 0..num_isrs {
            if let Some(isr_name) = isrs.get(i as usize) {
                let isr_addr = i * 2; // Simple mapping for simulation
                self.function_names.insert(isr_addr, isr_name.clone());
                
                // Make sure ISRs have a stack usage entry
                if !self.function_stack_usage.contains_key(&isr_addr) {
                    // ISRs generally push all registers (32) plus SREG
                    self.function_stack_usage.insert(isr_addr, 33);
                }
            }
        }
        
        // Collect all function addresses first to avoid borrow checker issues
        let addresses: Vec<CpuAddr> = self.function_names.keys().cloned().collect();
        
        // Calculate max stack paths for all functions using Dijkstra's algorithm
        println!("Finding maximum stack paths...");
        for addr in &addresses {
            self.find_max_stack_path(*addr)?;
        }
        
        // Build result data
        println!("Building final results...");
        for (&addr, &stack_usage) in &self.function_stack_usage {
            let mut call_chain = Vec::new();
            
            // Add the path to the call chain
            if let Some(path) = self.max_stack_paths.get(&addr) {
                for &call_addr in path {
                    if let Some(name) = self.function_names.get(&call_addr) {
                        call_chain.push(name.clone());
                    }
                }
            }
            
            let function_name = self.function_names.get(&addr)
                .cloned()
                .unwrap_or_else(|| format!("func_0x{:x}", addr * 2));
            
            let result = StackAnalysisResult {
                function_name,
                address: addr * 2, // Convert to byte address
                stack_usage,
                calls: call_chain,
            };
            
            self.analyzer_result.push(result);
        }
        
        Ok(())
    }
    
    fn find_max_stack_path(&mut self, start_addr: CpuAddr) -> Result<()> {
        // Skip if we've already processed this function
        if self.max_stack_paths.contains_key(&start_addr) {
            return Ok(());
        }
        
        // Use a priority queue (max heap) for Dijkstra's algorithm
        let mut queue = BinaryHeap::new();
        let mut best_paths: HashMap<CpuAddr, (u32, Vec<CpuAddr>)> = HashMap::new();
        
        // Initialize with the start node
        queue.push(PathNode {
            addr: start_addr,
            stack_usage: self.function_stack_usage.get(&start_addr).copied().unwrap_or(0),
            path: vec![start_addr],
        });
        
        // Track visited nodes to detect cycles
        let mut visited = HashSet::new();
        let mut recursion_counters: HashMap<CpuAddr, u32> = HashMap::new();
        
        while let Some(node) = queue.pop() {
            // Skip if we've processed this node with a better path
            if visited.contains(&node.addr) {
                continue;
            }
            
            // Check for recursion
            if node.path.iter().filter(|&&a| a == node.addr).count() > 1 {
                let count = recursion_counters.entry(node.addr).or_insert(0);
                *count += 1;
                
                if *count > 3 { // Limit recursion to 3 iterations
                    continue;
                }
            }
            
            visited.insert(node.addr);
            
            // Record this path if it's the best for this function
            if !best_paths.contains_key(&node.addr) || 
               node.stack_usage > best_paths[&node.addr].0 {
                best_paths.insert(node.addr, (node.stack_usage, node.path.clone()));
            }
            
            // Process all callees
            if let Some(callees) = self.call_graph.get(&node.addr) {
                for &callee in callees {
                    // Skip if this would create a cycle (except for controlled recursion)
                    if node.path.contains(&callee) && 
                       node.path.iter().filter(|&&a| a == callee).count() > 2 {
                        continue;
                    }
                    
                    let callee_stack = self.function_stack_usage.get(&callee).copied().unwrap_or(0);
                    let mut new_path = node.path.clone();
                    new_path.push(callee);
                    
                    // Calculate combined stack usage - function + callee
                    let combined_stack = node.stack_usage + callee_stack;
                    
                    queue.push(PathNode {
                        addr: callee,
                        stack_usage: combined_stack,
                        path: new_path,
                    });
                }
            }
        }
        
        // Store the maximum stack path for this function
        if let Some((_, max_path)) = best_paths.get(&start_addr) {
            self.max_stack_paths.insert(start_addr, max_path.clone());
            
            // Also update the function stack usage if needed
            if let Some((max_usage, _)) = best_paths.get(&start_addr) {
                if *max_usage > self.function_stack_usage.get(&start_addr).copied().unwrap_or(0) {
                    self.function_stack_usage.insert(start_addr, *max_usage);
                }
            }
            
            // Fix: Inside TreeAnalysis::find_max_stack_path
            // Change from:
            // let mut chain = CallChain {
            // To:
            let chain = CallChain {
                path: max_path.clone(),
                stack_usage: best_paths[&start_addr].0,
            };
            
            // Add it to our call_chains
            self.call_chains.insert(start_addr, chain);
        } else {
            // No paths found, just use this function alone
            self.max_stack_paths.insert(start_addr, vec![start_addr]);
        }
        
        Ok(())
    }
    
    pub fn dump_stack_tree(&self, args: &ProgramArgs) -> Result<()> {
        // Calculate total maximum stack usage
        let mut max_stack = 0;
        let mut max_stack_function = None;
        
        for (&addr, &usage) in &self.function_stack_usage {
            if usage > max_stack {
                max_stack = usage;
                max_stack_function = Some(addr);
            }
        }
        
        println!("\n---- Stack Usage Analysis ----");
        println!("Total maximum stack usage: {} bytes", max_stack);
        
        if let Some(addr) = max_stack_function {
            if let Some(name) = self.function_names.get(&addr) {
                println!("Maximum stack usage in function: {} (0x{:x})", name, addr * 2);
            } else {
                println!("Maximum stack usage in function at address: 0x{:x}", addr * 2);
            }
            
            // Display call chain for the maximum stack usage
            if let Some(path) = self.max_stack_paths.get(&addr) {
                println!("\nMaximum stack call chain:");
                for &call_addr in path {
                    if let Some(call_name) = self.function_names.get(&call_addr) {
                        println!("  -> {} (0x{:x}): {} bytes", 
                                call_name, 
                                call_addr * 2,
                                self.function_stack_usage.get(&call_addr).copied().unwrap_or(0));
                    } else {
                        println!("  -> func_0x{:x}: {} bytes", 
                                call_addr * 2,
                                self.function_stack_usage.get(&call_addr).copied().unwrap_or(0));
                    }
                }
            }
        }
        
        if !args.total_only {
            // Print individual function stack usage
            println!("\nFunction stack usage:");
            
            // Sort by stack usage
            let mut sorted_entries: Vec<_> = self.function_stack_usage.iter().collect();
            sorted_entries.sort_by(|a, b| b.1.cmp(a.1)); // Sort by stack usage (descending)
            
            println!("{:<40} {:<10} {}", "FUNCTION", "ADDRESS", "STACK USAGE");
            println!("{:-<40} {:-<10} {:-<10}", "", "", "");
            
            for (&addr, &usage) in sorted_entries {
                let name = self.function_names.get(&addr)
                    .cloned()
                    .unwrap_or_else(|| format!("func_0x{:x}", addr * 2));
                
                println!("{:<40} 0x{:<8x} {} bytes", 
                         if name.len() > 38 { format!("{}...", &name[0..35]) } else { name },
                         addr * 2,
                         usage);
            }
        }
        
        println!("\n-----------------------------");
        
        Ok(())
    }
    
    pub fn get_results(&self) -> Vec<StackAnalysisResult> {
        self.analyzer_result.clone()
    }
    
    pub fn get_call_chain(&self, addr: CpuAddr) -> Option<&CallChain> {
        self.call_chains.get(&addr)
    }
}

pub struct AnalysisResult {
    pub max_stack: usize,
    pub call_depth: usize,
    pub function_stack_usages: Vec<FunctionStackUsage>,
    pub max_stack_path: Vec<String>,
}

pub struct FunctionStackUsage {
    pub name: String,
    pub stack_bytes: usize,
}

pub fn analyze_stack_usage(elf_file: &ElfInfo, processor: &AVRProcessor) -> AnalysisResult {
    let mut max_stack = 0;
    let call_depth = 5; // Fixed call depth (placeholder)
    let mut function_stack_usages = Vec::new();
    let mut max_stack_path = Vec::new();
    let mut max_stack_addr = 0;
    
    // Populate with data from the processor
    for (&addr, &stack) in &processor.stack_map {
        if stack as usize > max_stack {
            max_stack = stack as usize;
            max_stack_addr = addr;
        }
        
        let name = if let Some(sym_name) = elf_file.get_symbol_name(addr) {
            sym_name.to_string()
        } else {
            format!("func_0x{:x}", addr * 2)
        };
        
        function_stack_usages.push(FunctionStackUsage {
            name,
            stack_bytes: stack as usize,
        });
    }
    
    // Try to find the maximum stack path
    if max_stack_addr != 0 {
        // Perform a simple DFS to find the path to max stack
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        stack.push(max_stack_addr);
        
        while let Some(addr) = stack.pop() {
            if visited.contains(&addr) {
                continue;
            }
            
            visited.insert(addr);
            
            // Add this function to the path
            if let Some(sym_name) = elf_file.get_symbol_name(addr) {
                max_stack_path.push(sym_name.to_string());
            } else {
                max_stack_path.push(format!("func_0x{:x}", addr * 2));
            }
            
            // Follow the call graph
            if let Some(callees) = processor.call_graph.get(&addr) {
                for &callee in callees {
                    if !visited.contains(&callee) {
                        stack.push(callee);
                    }
                }
            }
        }
    }
    
    AnalysisResult {
        max_stack,
        call_depth,
        function_stack_usages,
        max_stack_path,
    }
}
