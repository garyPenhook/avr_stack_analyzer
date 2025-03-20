// CPU simulation for AVR architecture

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use crate::avr_stack::{Result, ErrorCode, AvrStackError};

pub type CpuAddr = u32;

// Constants for CPU flags
pub const CPU_F_STACK: u32 = 0x004;
pub const CPU_F_CALL: u32 = 0x008;
pub const CPU_F_COND_JUMP: u32 = 0x010;
pub const CPU_F_UNCOND_JUMP: u32 = 0x020;
pub const CPU_F_RET: u32 = 0x040;
pub const CPU_F_INSTR: u32 = 0x080;
pub const CPU_F_IJMP: u32 = 0x100;
pub const CPU_F_RETI: u32 = 0x200;
pub const CPU_F_LONGJMP: u32 = 0x400;
pub const CPU_F_UNKNOWN_DEST: u32 = 0x800;
pub const CPU_F_ISR: u32 = 0x1000;
pub const CPU_F_SKIP: u32 = 0x2000;

pub const CPU_FF_FLOW: u32 = CPU_F_RET | CPU_F_CALL | CPU_F_IJMP | CPU_F_COND_JUMP | CPU_F_UNCOND_JUMP;
pub const CPU_MIN_INSTR_SIZE: u32 = 2;

// Maximum recursion depth to prevent infinite recursion
pub const MAX_RECURSION_DEPTH: u32 = 10;
// Maximum number of branches to follow to prevent combinatorial explosion
pub const MAX_BRANCHES: usize = 1000;
// Reasonable stack bound for AVRs
pub const MAX_STACK_SIZE: u32 = 4096;

#[derive(Debug)]
pub struct CpuICallListEntry {
    pub src: CpuAddr,
    pub dst: Vec<CpuAddr>,
}

#[derive(Debug)]
pub struct IjmpInfo {
    pub table_size: u32,
    pub data_size: u32,
    pub addr: u32,
}

#[derive(Debug, Clone)]
pub struct AvrInstruction {
    pub opcode: u16,
    pub mask: u16,
    pub mnemonic: String,
    pub flags: u32,
    pub stack_change: i32,
}

impl fmt::Display for AvrInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (stack: {})", self.mnemonic, self.stack_change)
    }
}

// Status register (SREG) flags for AVR
#[derive(Debug, Clone, Copy)]
pub struct StatusRegister {
    pub carry: bool,      // C flag
    pub zero: bool,       // Z flag
    pub negative: bool,   // N flag
    pub overflow: bool,   // V flag
    pub sign: bool,       // S flag
    pub half_carry: bool, // H flag
    pub bit_copy: bool,   // T flag
    pub interrupt: bool,  // I flag
}

impl StatusRegister {
    pub fn new() -> Self {
        StatusRegister {
            carry: false,
            zero: false,
            negative: false,
            overflow: false,
            sign: false,
            half_carry: false,
            bit_copy: false,
            interrupt: false,
        }
    }

    pub fn to_byte(&self) -> u8 {
        let mut value = 0u8;
        if self.carry { value |= 0x01; }
        if self.zero { value |= 0x02; }
        if self.negative { value |= 0x04; }
        if self.overflow { value |= 0x08; }
        if self.sign { value |= 0x10; }
        if self.half_carry { value |= 0x20; }
        if self.bit_copy { value |= 0x40; }
        if self.interrupt { value |= 0x80; }
        value
    }

    pub fn from_byte(&mut self, value: u8) {
        self.carry = (value & 0x01) != 0;
        self.zero = (value & 0x02) != 0;
        self.negative = (value & 0x04) != 0;
        self.overflow = (value & 0x08) != 0;
        self.sign = (value & 0x10) != 0;
        self.half_carry = (value & 0x20) != 0;
        self.bit_copy = (value & 0x40) != 0;
        self.interrupt = (value & 0x80) != 0;
    }
}

// Execution path for analysis
#[derive(Clone)]
struct ExecutionPath {
    addr: CpuAddr,
    stack_depth: i32,
    visited: HashSet<CpuAddr>,
    recursion_counts: HashMap<CpuAddr, u32>,
    is_isr: bool,
}

// A struct to represent the AVR CPU for simulation
pub struct Cpu {
    pub instruction_set: Vec<AvrInstruction>,
    pub pc: CpuAddr,
    pub pc_prev: CpuAddr,
    pub pc_first_stack_out: CpuAddr,
    pub jump_table: HashMap<CpuAddr, Vec<CpuAddr>>,
    
    pub prog: Vec<u8>,
    pub prog_size: u32,
    pub ram_start: u32,
    
    pub stack_change: i32,
    pub max_stack_usage: u32,
    
    pub wrap_0: bool,
    pub allow_calls_from_isr: bool,
    
    pub icall_list: Vec<CpuICallListEntry>,
    pub visited: HashSet<CpuAddr>,
    pub stack_map: HashMap<CpuAddr, u32>,      // Map function address to stack usage
    pub call_graph: HashMap<CpuAddr, Vec<CpuAddr>>, // Call graph for functions
    pub isr_map: HashMap<CpuAddr, bool>,      // Map of addresses to ISR status
    
    pub last_opcode: u16,
    pub sreg: StatusRegister,
    
    // Registers for jump table analysis
    pub registers: [u8; 32],
    
    // Add an optional ElfInfo field for symbol lookup
    pub elf_info: Option<crate::elf::ElfInfo>,
}

impl Cpu {
    pub fn new() -> Self {
        Cpu {
            instruction_set: Self::init_instruction_set(),
            pc: 0,
            pc_prev: 0,
            pc_first_stack_out: 0,
            jump_table: HashMap::new(),
            
            prog: Vec::new(),
            prog_size: 0,
            ram_start: 0,
            
            stack_change: 0,
            max_stack_usage: 0,
            
            wrap_0: false,
            allow_calls_from_isr: false,
            
            icall_list: Vec::new(),
            visited: HashSet::new(),
            stack_map: HashMap::new(),
            call_graph: HashMap::new(),
            isr_map: HashMap::new(),
            
            last_opcode: 0,
            sreg: StatusRegister::new(),
            
            registers: [0; 32],
            
            elf_info: None,
        }
    }
    
    fn init_instruction_set() -> Vec<AvrInstruction> {
        let mut instructions = Vec::new();
        
        // Stack operations
        instructions.push(AvrInstruction {
            opcode: 0x920F,
            mask: 0xFE0F,
            mnemonic: "PUSH".to_string(),
            flags: CPU_F_STACK | CPU_F_INSTR,
            stack_change: -1,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x900F,
            mask: 0xFE0F,
            mnemonic: "POP".to_string(),
            flags: CPU_F_STACK | CPU_F_INSTR,
            stack_change: 1,
        });
        
        // Call instructions
        instructions.push(AvrInstruction {
            opcode: 0x940E,
            mask: 0xFE0E,
            mnemonic: "CALL".to_string(),
            flags: CPU_F_CALL | CPU_F_INSTR,
            stack_change: -2,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xD000,
            mask: 0xF000,
            mnemonic: "RCALL".to_string(),
            flags: CPU_F_CALL | CPU_F_INSTR,
            stack_change: -2,
        });
        
        // Return instructions
        instructions.push(AvrInstruction {
            opcode: 0x9508,
            mask: 0xFFFF,
            mnemonic: "RET".to_string(),
            flags: CPU_F_RET | CPU_F_INSTR,
            stack_change: 2,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x9518,
            mask: 0xFFFF,
            mnemonic: "RETI".to_string(),
            flags: CPU_F_RETI | CPU_F_INSTR,
            stack_change: 2,
        });
        
        // Indirect jumps and calls
        instructions.push(AvrInstruction {
            opcode: 0x9409,
            mask: 0xFFFF,
            mnemonic: "IJMP".to_string(),
            flags: CPU_F_IJMP | CPU_F_UNCOND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x9509,
            mask: 0xFFFF,
            mnemonic: "ICALL".to_string(),
            flags: CPU_F_CALL | CPU_F_IJMP | CPU_F_INSTR,
            stack_change: -2,
        });
        
        // Direct jumps
        instructions.push(AvrInstruction {
            opcode: 0x940C,
            mask: 0xFE0E,
            mnemonic: "JMP".to_string(),
            flags: CPU_F_UNCOND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xC000,
            mask: 0xF000,
            mnemonic: "RJMP".to_string(),
            flags: CPU_F_UNCOND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Branch instructions
        instructions.push(AvrInstruction {
            opcode: 0xF000,
            mask: 0xFC00,
            mnemonic: "BRBS".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xF400,
            mask: 0xFC00,
            mnemonic: "BRBC".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Common branch conditions
        instructions.push(AvrInstruction {
            opcode: 0xF001,
            mask: 0xFC07,
            mnemonic: "BREQ".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xF401,
            mask: 0xFC07,
            mnemonic: "BRNE".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xF000,
            mask: 0xFC07,
            mnemonic: "BRCS/BRLO".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xF400,
            mask: 0xFC07,
            mnemonic: "BRCC/BRSH".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Skip instructions
        instructions.push(AvrInstruction {
            opcode: 0x9900,
            mask: 0xFF00,
            mnemonic: "SBIC".to_string(),
            flags: CPU_F_SKIP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x9A00,
            mask: 0xFF00,
            mnemonic: "SBIS".to_string(),
            flags: CPU_F_SKIP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xFC00,
            mask: 0xFE00,
            mnemonic: "SBRC".to_string(),
            flags: CPU_F_SKIP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xFE00,
            mask: 0xFE00,
            mnemonic: "SBRS".to_string(),
            flags: CPU_F_SKIP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Compare and skip if equal
        instructions.push(AvrInstruction {
            opcode: 0x1000,
            mask: 0xF000,
            mnemonic: "CPSE".to_string(),
            flags: CPU_F_SKIP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Additional instructions needed for register tracking
        instructions.push(AvrInstruction {
            opcode: 0x2C00,
            mask: 0xFC00,
            mnemonic: "MOV".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0xE000,
            mask: 0xF000,
            mnemonic: "LDI".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x9000,
            mask: 0xF000,
            mnemonic: "LDS/STS".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x0000,
            mask: 0xF000,
            mnemonic: "ADD/SUB".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        // Interrupt related
        instructions.push(AvrInstruction {
            opcode: 0x9478,
            mask: 0xFFFF,
            mnemonic: "SEI".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions.push(AvrInstruction {
            opcode: 0x94F8,
            mask: 0xFFFF,
            mnemonic: "CLI".to_string(),
            flags: CPU_F_INSTR,
            stack_change: 0,
        });
        
        instructions
    }

    pub fn find_instruction(&self, opcode: u16) -> Option<&AvrInstruction> {
        for instr in &self.instruction_set {
            if (opcode & instr.mask) == instr.opcode {
                return Some(instr);
            }
        }
        None
    }
    
    pub fn init(&mut self, prog: Vec<u8>, prog_size: u32, ram_start: u32) -> Result<()> {
        self.prog = prog;
        self.prog_size = prog_size;
        self.ram_start = ram_start;
        
        Ok(())
    }
    
    pub fn read_opcode(&self, addr: CpuAddr) -> u16 {
        let offset = (addr * CPU_MIN_INSTR_SIZE) as usize;
        if offset + 1 >= self.prog.len() {
            return 0; // Return 0 for invalid addresses
        }
        
        ((self.prog[offset + 1] as u16) << 8) | (self.prog[offset] as u16)
    }
    
    pub fn process_instruction(&mut self, addr: CpuAddr) -> Result<()> {
        // Check bounds
        if addr * CPU_MIN_INSTR_SIZE >= self.prog_size {
            return Err(AvrStackError::new(
                ErrorCode::CpuSimulation,
                file!(),
                line!(),
                &format!("Address out of bounds: 0x{:x}", addr * CPU_MIN_INSTR_SIZE)
            ));
        }
        
        let opcode = self.read_opcode(addr);
        self.last_opcode = opcode;
        
        // Find the instruction
        let instruction = match self.find_instruction(opcode) {
            Some(instr) => instr.clone(),
            None => {
                // Unknown instruction, just skip it
                return Ok(());
            }
        };
        
        self.stack_change += instruction.stack_change;
        
        // Process based on instruction flags
        if (instruction.flags & CPU_F_CALL) != 0 {
            // Call instruction - extract target address
            if let Some(target) = self.get_call_target(addr, opcode, &instruction) {
                // Add to call graph
                if let Some(targets) = self.call_graph.get_mut(&addr) {
                    if !targets.contains(&target) {
                        targets.push(target);
                    }
                } else {
                    self.call_graph.insert(addr, vec![target]);
                }
                
                // Check if calling from ISR
                if *self.isr_map.get(&addr).unwrap_or(&false) && !self.allow_calls_from_isr {
                    return Err(AvrStackError::new(
                        ErrorCode::CallFromIsr,
                        file!(),
                        line!(),
                        &format!("Call from ISR detected at 0x{:x}", addr * CPU_MIN_INSTR_SIZE)
                    ));
                }
            }
        } else if (instruction.flags & CPU_F_IJMP) != 0 {
            // Indirect jump - try to determine target(s)
            let targets = self.analyze_indirect_jump(addr);
            for target in targets {
                if let Some(jump_targets) = self.jump_table.get_mut(&addr) {
                    if !jump_targets.contains(&target) {
                        jump_targets.push(target);
                    }
                } else {
                    self.jump_table.insert(addr, vec![target]);
                }
            }
        }
        
        // Emulate register operations if needed for jump table analysis
        if instruction.mnemonic.starts_with("LDI") {
            // LDI Rd, K - Load immediate
            let rd = ((opcode >> 4) & 0x1F) + 16; // Registers r16-r31
            let k = ((opcode & 0x0F00) >> 4) | (opcode & 0x0F);
            self.registers[rd as usize] = k as u8;
        } else if instruction.mnemonic.starts_with("MOV") {
            // MOV Rd, Rr - Copy register
            let rd = (opcode >> 4) & 0x1F;
            let rr = ((opcode & 0x0200) >> 5) | (opcode & 0x0F);
            self.registers[rd as usize] = self.registers[rr as usize];
        }
        
        Ok(())
    }
    
    fn get_call_target(&self, addr: CpuAddr, opcode: u16, instr: &AvrInstruction) -> Option<CpuAddr> {
        match instr.mnemonic.as_str() {
            "CALL" => {
                // 32-bit instruction, need to read the next word
                let next_addr = addr + 1;
                if next_addr * CPU_MIN_INSTR_SIZE < self.prog_size {
                    let next_word = self.read_opcode(next_addr);
                    let target = ((opcode & 0x01F0) as u32) << 17 | 
                                 ((opcode & 0x0001) as u32) << 16 | 
                                 (next_word as u32);
                    Some(target)
                } else {
                    None
                }
            },
            "RCALL" => {
                // 12-bit signed offset
                let offset = opcode & 0x0FFF;
                let offset = if (offset & 0x0800) != 0 {
                    // Sign extend
                    (offset | 0xF000) as i16
                } else {
                    offset as i16
                };
                
                // Calculate target address (PC relative)
                let target = addr as i32 + 1 + offset as i32;
                if target >= 0 {
                    Some(target as u32)
                } else {
                    None
                }
            },
            "ICALL" => {
                // Check if this ICALL is already in our icall_list
                for entry in &self.icall_list {
                    if entry.src == addr {
                        return entry.dst.first().copied();
                    }
                }
                
                // Try to determine from Z register (r30:r31)
                let z_low = self.registers[30] as u32;
                let z_high = self.registers[31] as u32;
                let z = (z_high << 8) | z_low;
                
                if z > 0 && z * CPU_MIN_INSTR_SIZE < self.prog_size {
                    return Some(z);
                }
                
                // Check if we have a symbol for this address to help with virtual method tables
                if let Some(ref elf) = self.elf_info {
                    if let Some(sym) = elf.find_symbol_by_address(addr) {
                        // Check if we can guess the target based on common patterns in the symbol name
                        if sym.name.contains("virtual") || sym.name.contains("vtable") {
                            // This is likely a virtual method call
                            // Try to find the implementation by searching for symbols with "_impl" suffix
                            for other_sym in &elf.symbols {
                                if other_sym.name.contains("_impl") {
                                    return Some(other_sym.address);
                                }
                            }
                        }
                    }
                }
                
                None
            },
            _ => None,
        }
    }
    
    // Methods for stack analysis
    pub fn analyze_function_stack(&mut self, start_addr: CpuAddr) -> Result<u32> {
        if self.visited.contains(&start_addr) {
            return Ok(self.stack_map.get(&start_addr).copied().unwrap_or(0));
        }
        
        self.visited.insert(start_addr);
        self.pc = start_addr;
        self.stack_change = 0;
        
        // Check if this is an ISR
        let is_isr = if let Some(ref elf) = self.elf_info {
            if let Some(sym_name) = elf.get_symbol_name(start_addr) {
                sym_name.contains("__vector") || sym_name.starts_with("ISR_")
            } else {
                false
            }
        } else {
            false
        };
        
        if is_isr {
            self.isr_map.insert(start_addr, true);
        }
        
        // Use the improved execution simulation
        let stack_usage = self.simulate_execution_paths(start_addr, is_isr)?;
        
        // Store the maximum stack usage for this function
        self.stack_map.insert(start_addr, stack_usage);
        
        Ok(stack_usage)
    }
    
    fn simulate_execution_paths(&mut self, start_addr: CpuAddr, is_isr: bool) -> Result<u32> {
        let mut max_stack = 0;
        let mut queue = VecDeque::new();
        
        // Initial path
        let initial_path = ExecutionPath {
            addr: start_addr,
            stack_depth: 0,
            visited: HashSet::new(),
            recursion_counts: HashMap::new(),
            is_isr,
        };
        
        queue.push_back(initial_path);
        
        // Process all paths using breadth-first search
        while let Some(mut path) = queue.pop_front() {
            if queue.len() > MAX_BRANCHES {
                // Too many branches, this could be a pathological case
                println!("Warning: Maximum number of branches ({}) exceeded at 0x{:x}", 
                         MAX_BRANCHES, path.addr * CPU_MIN_INSTR_SIZE);
                continue;
            }
            
            // Check for previously visited address in this path
            if path.visited.contains(&path.addr) {
                // Handle recursion
                if let Some(count) = path.recursion_counts.get_mut(&path.addr) {
                    *count += 1;
                    if *count > MAX_RECURSION_DEPTH {
                        // Recursion too deep, stop this path
                        continue;
                    }
                } else {
                    path.recursion_counts.insert(path.addr, 1);
                }
            }
            
            path.visited.insert(path.addr);
            
            // Process the current instruction
            let opcode = self.read_opcode(path.addr);
            
            // We must fix the mutable borrow conflict by handling the instruction lookup first
            // and only keeping what we need from it
            let instr_flags;
            let instr_mnemonic;
            let instr_stack_change;
            
            if let Some(instr) = self.find_instruction(opcode) {
                // Store all the information we need from the instruction
                instr_flags = instr.flags;
                instr_mnemonic = instr.mnemonic.clone();
                instr_stack_change = instr.stack_change;
                
                // Update stack depth for this instruction
                path.stack_depth -= instr_stack_change;
                
                if path.stack_depth < 0 {
                    return Err(AvrStackError::new(
                        ErrorCode::NegativeStackChange,
                        file!(),
                        line!(),
                        &format!("Negative stack change at address 0x{:x}", path.addr * CPU_MIN_INSTR_SIZE)
                    ));
                }
                
                if path.stack_depth > max_stack as i32 {
                    max_stack = path.stack_depth as u32;
                }
                
                if path.stack_depth > MAX_STACK_SIZE as i32 {
                    return Err(AvrStackError::new(
                        ErrorCode::StackAnalysis,
                        file!(),
                        line!(),
                        &format!("Stack usage exceeds maximum at address 0x{:x}", path.addr * CPU_MIN_INSTR_SIZE)
                    ));
                }
                
                // Process based on instruction type
                if (instr_flags & CPU_F_RET) != 0 {
                    // End of function, don't continue this path
                    continue;
                }
                
                if (instr_flags & CPU_F_CALL) != 0 {
                    if let Some(target) = self.get_call_target(path.addr, opcode, instr) {
                        // For a call, we need to account for the called function's stack usage
                        
                        // ENHANCEMENT: Always add to call graph, even if we've already visited 
                        // the target (this captures all call paths)
                        if let Some(targets) = self.call_graph.get_mut(&path.addr) {
                            if !targets.contains(&target) {
                                targets.push(target);
                            }
                        } else {
                            self.call_graph.insert(path.addr, vec![target]);
                        }
                        
                        if !self.visited.contains(&target) {
                            // Recursively analyze the called function
                            self.analyze_function_stack(target)?;
                        }
                        
                        if let Some(&callee_stack) = self.stack_map.get(&target) {
                            path.stack_depth += callee_stack as i32;
                            if path.stack_depth > max_stack as i32 {
                                max_stack = path.stack_depth as u32;
                            }
                        }
                        
                        // Continue execution after the call
                        let next_addr = if instr_mnemonic == "CALL" || instr_mnemonic == "JMP" {
                            path.addr + 2
                        } else {
                            path.addr + 1
                        };
                        
                        path.addr = next_addr;
                        queue.push_back(path);
                    }
                } else if (instr_flags & CPU_F_COND_JUMP) != 0 {
                    // For conditional jumps, we need to follow both paths
                    let target = self.get_branch_target(path.addr, opcode);
                    
                    if let Some(branch_addr) = target {
                        // Follow the branch
                        let mut branch_path = path.clone();
                        branch_path.addr = branch_addr;
                        queue.push_back(branch_path);
                    }
                    
                    // Also follow the next instruction
                    path.addr += 1;
                    queue.push_back(path);
                } else if (instr_flags & CPU_F_SKIP) != 0 {
                    // Skip instructions can skip the next instruction
                    // We need to follow both paths (skip and no skip)
                    
                    // Path 1: No skip
                    let mut no_skip_path = path.clone();
                    no_skip_path.addr += 1;
                    queue.push_back(no_skip_path);
                    
                    // Path 2: Skip the next instruction
                    // Need to check if the next instruction is a 2-word instruction
                    let next_opcode = self.read_opcode(path.addr + 1);
                    let next_instr = self.find_instruction(next_opcode);
                    let skip_size = if let Some(next_i) = next_instr {
                        if next_i.mnemonic == "CALL" || next_i.mnemonic == "JMP" {
                            2 // These are 2-word instructions
                        } else {
                            1
                        }
                    } else {
                        1 // Default to 1-word if unknown
                    };
                    
                    path.addr += 1 + skip_size;
                    queue.push_back(path);
                } else if (instr_flags & CPU_F_UNCOND_JUMP) != 0 {
                    if instr_mnemonic == "RJMP" {
                        let offset = opcode & 0x0FFF;
                        let offset = if (offset & 0x0800) != 0 {
                            ((offset | 0xF000) as i16) as i32
                        } else {
                            (offset as i16) as i32
                        };
                        
                        let target = (path.addr as i32 + 1 + offset) as u32;
                        path.addr = target;
                        queue.push_back(path);
                    } else if (instr_flags & CPU_F_IJMP) != 0 {
                        // ENHANCEMENT: Improved indirect jump handling
                        let targets = if self.jump_table.contains_key(&path.addr) {
                            self.jump_table[&path.addr].clone()
                        } else {
                            self.analyze_indirect_jump(path.addr)
                        };
                        
                        // If no targets found through analysis, try pattern-based detection
                        let targets = if targets.is_empty() {
                            self.detect_jump_targets_by_pattern(path.addr)
                        } else {
                            targets
                        };
                        
                        // Fix the moved value error by iterating over references
                        for target in &targets {
                            // Add to call graph for ICALL (indirect function calls)
                            if instr_mnemonic == "ICALL" {
                                if let Some(call_targets) = self.call_graph.get_mut(&path.addr) {
                                    if !call_targets.contains(target) {
                                        call_targets.push(*target);
                                    }
                                } else {
                                    self.call_graph.insert(path.addr, vec![*target]);
                                }
                            }
                            
                            let mut jump_path = path.clone();
                            jump_path.addr = *target;
                            queue.push_back(jump_path);
                        }
                        
                        // If no targets found, just assume it's a return or end of path
                        if targets.is_empty() {
                            continue;
                        }
                    } else if instr_mnemonic == "JMP" {
                        let next_word = self.read_opcode(path.addr + 1);
                        let target = ((opcode & 0x01F0) as u32) << 17 | 
                                     ((opcode & 0x0001) as u32) << 16 | 
                                     (next_word as u32);
                        
                        path.addr = target;
                        queue.push_back(path);
                    } else {
                        // Unknown jump type, just move to next instruction
                        path.addr += 1;
                        queue.push_back(path);
                    }
                } else {
                    // Standard instruction, just move to next instruction
                    let instr_size = if instr_mnemonic == "CALL" || instr_mnemonic == "JMP" || 
                                       instr_mnemonic == "LDS" || instr_mnemonic == "STS" {
                        2 // These are 2-word instructions
                    } else {
                        1
                    };
                    
                    path.addr += instr_size;
                    queue.push_back(path);
                }
            }
        }
        
        Ok(max_stack)
    }
    
    // Add method to analyze indirect jumps
    pub fn analyze_indirect_jump(&self, addr: CpuAddr) -> Vec<CpuAddr> {
        let mut targets = Vec::new();
        
        // Try to determine jump targets based on Z registers
        let z_low = self.registers[30] as u32;
        let z_high = self.registers[31] as u32;
        let z = (z_high << 8) | z_low;
        
        if z > 0 && z * CPU_MIN_INSTR_SIZE < self.prog_size {
            targets.push(z);
        }
        
        // Check if we have any ELF info that might help determine targets
        if let Some(ref elf) = self.elf_info {
            if let Some(sym) = elf.find_symbol_by_address(addr) {
                // If this is a virtual method call or switch table jump
                if sym.name.contains("virtual") || sym.name.contains("switch") || sym.name.contains("table") {
                    // Try to find likely targets from the symbol table
                    for other_sym in &elf.symbols {
                        if other_sym.name.contains("case_") || other_sym.name.contains("_impl") {
                            targets.push(other_sym.address);
                        }
                    }
                }
            }
        }
        
        targets
    }
    
    // Get the target address for a branch instruction
    pub fn get_branch_target(&self, addr: CpuAddr, opcode: u16) -> Option<CpuAddr> {
        // Determine branch type from opcode
        if (opcode & 0xF000) == 0xF000 || (opcode & 0xF000) == 0xF400 {
            // BRBS/BRBC - Branch if bit in status register is set/cleared
            let offset = (opcode & 0x03F8) >> 3;
            let offset = if (offset & 0x40) != 0 {
                // Sign extend for negative offsets
                offset | 0xFF80
            } else {
                offset
            };
            
            // Target is PC + offset + 1 (PC points to next instruction after branch)
            let target = addr as i32 + 1 + offset as i32;
            if target >= 0 {
                Some(target as u32)
            } else {
                None
            }
        } else {
            // Unknown branch type
            None
        }
    }
    
    // Get symbol name for an address
    pub fn get_symbol_name(&self, addr: CpuAddr) -> Option<String> {
        if let Some(ref elf_info) = self.elf_info {
            if let Some(name) = elf_info.get_symbol_name(addr) {
                return Some(name.to_string());
            }
        }
        None
    }
    
    // New helper method to detect jump targets based on common patterns
    fn detect_jump_targets_by_pattern(&self, addr: CpuAddr) -> Vec<CpuAddr> {
        let mut targets = Vec::new();
        let offset = (addr as usize) * 2;
        
        // Look for 8 bytes before the current instruction for table setup patterns
        if offset >= 8 {
            // Look for typical Z-register setup (r30/r31)
            // LDI r30, lo8(table); LDI r31, hi8(table)
            let instr1 = ((self.prog[offset-8] as u16) << 8) | (self.prog[offset-7] as u16);
            let instr2 = ((self.prog[offset-6] as u16) << 8) | (self.prog[offset-5] as u16);
            
            if (instr1 & 0xF0F0) == 0xE0E0 && (instr2 & 0xF0F0) == 0xE0F0 {
                // Extract immediate values
                let zl = ((instr1 & 0x0F00) >> 4) | (instr1 & 0x000F);
                let zh = ((instr2 & 0x0F00) >> 4) | (instr2 & 0x000F);
                let table_addr = ((zh as u32) << 8) | (zl as u32);
                
                // Check if this is within program memory and could be a table
                if table_addr * 2 < self.prog_size {
                    // Look at potential table data (up to 8 entries)
                    for i in 0..8 {
                        if (table_addr as usize + i*2 + 1) * 2 < self.prog.len() {
                            let entry_offset = (table_addr as usize + i*2) * 2;
                            let entry = ((self.prog[entry_offset+1] as u32) << 8) | 
                                        (self.prog[entry_offset] as u32) |
                                        ((self.prog[entry_offset+3] as u32) << 24) |
                                        ((self.prog[entry_offset+2] as u32) << 16);
                            
                            // Table entries are typically word addresses
                            let target = entry / 2;
                            
                            // Verify this looks like a valid code address
                            if target * 2 < self.prog_size && target > 0 {
                                targets.push(target);
                            }
                        }
                    }
                }
            }
        }
        
        targets
    }
}
