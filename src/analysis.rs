// Stack usage analysis functionality

use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use crate::avr_stack::{Result, ProgramArgs, StackAnalysisResult};
use crate::elf::ElfInfo;
use crate::cpu::{Cpu, CpuAddr};

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
        // Find all function entry points from symbols and patterns
        self.entry_points = self.identify_function_entry_points(cpu)?;
        println!("Found {} function entry points", self.entry_points.len());
        
        // Fix: Clone the entry points first to prevent borrowing conflict
        let entry_points_clone = self.entry_points.clone();
        
        // Analyze each function's stack usage
        for &addr in &entry_points_clone {
            if let Some(name_opt) = cpu.get_symbol_name(addr) {
                if self.ignored_functions.contains(&name_opt) {
                    println!("Skipping ignored function: {}", name_opt);
                    continue;
                }
                println!("Analyzing function at 0x{:x}: {}", addr * 2, name_opt);
            } else {
                println!("Analyzing function at 0x{:x}", addr * 2);
            }
            
            self.analyze_function(cpu, addr)?;
        }
        
        // Check for ISRs
        for i in 0..arch.num_isrs {
            if let Some(isr_name) = arch.isr.get(i as usize) {
                if self.ignored_functions.contains(isr_name) {
                    println!("Skipping ignored ISR: {}", isr_name);
                    continue;
                }
                
                println!("Analyzing ISR: {}", isr_name);
                
                // ISRs in AVR typically have addresses in a vector table
                // Each vector is 2 words (4 bytes), and there's a vector 0 at the start
                let isr_addr = i * 2;
                
                // Mark this as an ISR for the CPU
                cpu.isr_map.insert(isr_addr, true);
                
                self.analyze_function(cpu, isr_addr)?;
                
                // Check if there are function calls from this ISR
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
            if let Some((name, len, _)) = matcher.find_prologue(&cpu.prog, offset) {
                let addr = (offset as u32) / 2; // Convert byte offset to instruction address
                
                // Check if this entry point is already in our list from symbols
                if !entry_points.contains(&addr) {
                    entry_points.push(addr);
                    
                    println!("Found function prologue pattern '{}' at address 0x{:x}", name, addr * 2);
                }
                
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
            return Ok(cpu.stack_map.get(&addr).copied().unwrap_or(0));
        }
        
        self.visited_addresses.insert(addr);
        
        // Use the CPU to analyze this function's stack usage
        let stack_usage = cpu.analyze_function_stack(addr)?;
        
        // Store the stack usage
        self.stack_changes.insert(addr, stack_usage as i32);
        
        Ok(stack_usage)
    }
    
    pub fn add_ignored_function(&mut self, name: &str) {
        self.ignored_functions.insert(name.to_string());
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
