// Stack usage analysis functionality

use std::collections::{HashMap, HashSet};
use crate::avr_stack::{Result, ErrorCode, AvrStackError, ProgramArgs, StackAnalysisResult};
use crate::elf::ElfInfo;
use crate::cpu::{Cpu, AVRProcessor, CpuAddr, PatternMatcher};

// MazeAnalysis for control flow analysis
pub struct MazeAnalysis {
    pub visited_addresses: HashSet<CpuAddr>,
    pub stack_changes: HashMap<CpuAddr, i32>,
    pub calls_from_interrupt: bool,
}

impl MazeAnalysis {
    pub fn new() -> Self {
        MazeAnalysis {
            visited_addresses: HashSet::new(),
            stack_changes: HashMap::new(),
            calls_from_interrupt: false,
        }
    }
    
    pub fn analyze(&mut self, cpu: &mut Cpu, arch: &crate::avr_stack::ArchInfo) -> Result<()> {
        // Find all function entry points from symbols and patterns
        let entry_points = self.identify_function_entry_points(cpu)?;
        println!("Found {} function entry points", entry_points.len());
        
        // Analyze each function's stack usage
        for &addr in &entry_points {
            self.analyze_function(cpu, addr)?;
        }
        
        // Check for ISRs
        for i in 0..arch.num_isrs {
            if let Some(isr_name) = arch.isr.get(i as usize) {
                println!("Analyzing ISR: {}", isr_name);
                
                // ISRs in AVR typically have addresses in a vector table
                // For simulation, we'll use a simple approach of assuming they're at specific addresses
                let isr_addr = i * 2; // Simple mapping for simulation
                self.analyze_function(cpu, isr_addr)?;
            }
        }
        
        Ok(())
    }
    
    fn identify_function_entry_points(&self, cpu: &Cpu) -> Result<Vec<CpuAddr>> {
        let mut entry_points = Vec::new();
        
        // Find function entry points from patterns
        let matcher = PatternMatcher::new();
        let mut offset = 0;
        
        while offset + 2 < cpu.prog.len() {
            if let Some((name, len, _)) = matcher.find_prologue(&cpu.prog, offset) {
                let addr = (offset as u32) / 2; // Convert byte offset to instruction address
                entry_points.push(addr);
                
                println!("Found function prologue pattern '{}' at address 0x{:x}", name, addr * 2);
                offset += len;
            } else {
                offset += 2;
            }
        }
        
        Ok(entry_points)
    }
    
    fn analyze_function(&mut self, cpu: &mut Cpu, addr: CpuAddr) -> Result<u32> {
        // Check if we've already visited this address
        if self.visited_addresses.contains(&addr) {
            return Ok(self.stack_changes.get(&addr).copied().unwrap_or(0) as u32);
        }
        
        self.visited_addresses.insert(addr);
        
        // Use the CPU to analyze this function's stack usage
        let stack_usage = cpu.analyze_function_stack(addr)?;
        
        // Store the stack usage
        self.stack_changes.insert(addr, stack_usage as i32);
        
        Ok(stack_usage)
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
        }
    }
    
    pub fn build(&mut self, num_isrs: u32, isrs: &[String], cpu: &Cpu) -> Result<()> {
        // Copy call graph from CPU
        self.call_graph = cpu.call_graph.clone();
        
        // Copy stack usage data from CPU
        self.function_stack_usage = cpu.stack_map.clone().into_iter()
            .map(|(k, v)| (k, v as u32))
            .collect();
        
        // Assign names to functions
        for (addr, _) in &self.function_stack_usage {
            self.function_names.insert(*addr, format!("func_0x{:x}", addr * 2));
        }
        
        // Add ISRs to function names
        for i in 0..num_isrs {
            if let Some(isr_name) = isrs.get(i as usize) {
                let isr_addr = i * 2; // Simple mapping for simulation
                self.function_names.insert(isr_addr, isr_name.clone());
            }
        }
        
        // Collect all function addresses first to avoid borrow checker issues
        let addresses: Vec<CpuAddr> = self.function_names.keys().cloned().collect();
        
        // Calculate max stack paths for all functions
        for addr in addresses {
            if !self.visited.contains(&addr) {
                // Clear the visited set for this calculation
                self.visited.clear();
                
                let stack_usage = self.calculate_max_stack_path(addr)?;
                self.function_stack_usage.insert(addr, stack_usage);
            }
        }
        
        // Build result data
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
    
    fn calculate_max_stack_path(&mut self, addr: CpuAddr) -> Result<u32> {
        // Check for recursion
        if self.visited.contains(&addr) {
            return Err(AvrStackError::new(
                ErrorCode::Recursion,
                file!(),
                line!(),
                &format!("Recursion detected at address 0x{:x}", addr * 2)
            ));
        }
        
        self.visited.insert(addr);
        
        let mut max_path = Vec::new();
        let mut max_stack = self.function_stack_usage.get(&addr).copied().unwrap_or(0);
        
        // Get callees from the call graph but clone them to avoid borrow issues
        let callees = if let Some(call_list) = self.call_graph.get(&addr) {
            call_list.clone()
        } else {
            Vec::new()
        };
        
        // Check all callees of this function
        for callee in callees {
            let callee_stack = self.calculate_max_stack_path(callee)?;
            
            if callee_stack > max_stack {
                max_stack = callee_stack;
                
                // Update the max path
                max_path = if let Some(path) = self.max_stack_paths.get(&callee) {
                    let mut new_path = vec![addr];
                    new_path.extend_from_slice(path);
                    new_path
                } else {
                    vec![addr, callee]
                };
            }
        }
        
        // Update the max stack path
        if max_path.is_empty() {
            max_path = vec![addr];
        }
        self.max_stack_paths.insert(addr, max_path);
        
        self.visited.remove(&addr);
        
        Ok(max_stack)
    }
    
    pub fn dump_stack_tree(&self, _args: &ProgramArgs) -> Result<()> {
        // This function would generate the stack usage report
        // The report is now generated in the AvrStack::output_json and output_text methods
        Ok(())
    }
    
    pub fn get_results(&self) -> Vec<StackAnalysisResult> {
        self.analyzer_result.clone()
    }
}

pub struct AnalysisResult {
    pub max_stack: usize,
    pub call_depth: usize,
    pub function_stack_usages: Vec<FunctionStackUsage>,
}

pub struct FunctionStackUsage {
    pub name: String,
    pub stack_bytes: usize,
}

pub fn analyze_stack_usage(elf_file: &ElfInfo, processor: &AVRProcessor) -> AnalysisResult {
    let mut max_stack = 0;
    // Use a non-mutable variable to avoid the unused warning
    let call_depth = 5; // Fixed call depth (placeholder)
    let mut function_stack_usages = Vec::new();
    
    // Populate with data from the processor
    for (&addr, &stack) in &processor.stack_map {
        if stack as usize > max_stack {
            max_stack = stack as usize;
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
    
    AnalysisResult {
        max_stack,
        call_depth,
        function_stack_usages,
    }
}
