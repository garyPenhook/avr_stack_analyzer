// CPU simulation for AVR architecture

use std::collections::{HashMap, HashSet};
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

pub const CPU_FF_FLOW: u32 = CPU_F_RET | CPU_F_CALL | CPU_F_IJMP | CPU_F_COND_JUMP | CPU_F_UNCOND_JUMP;
pub const CPU_MIN_INSTR_SIZE: u32 = 2;

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
    
    pub icall_list: Vec<CpuICallListEntry>,
    pub visited: HashSet<CpuAddr>,
    pub stack_map: HashMap<CpuAddr, u32>,      // Map function address to stack usage
    pub call_graph: HashMap<CpuAddr, Vec<CpuAddr>>, // Call graph for functions
    
    pub last_opcode: u16,
    
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
            
            icall_list: Vec::new(),
            visited: HashSet::new(),
            stack_map: HashMap::new(),
            call_graph: HashMap::new(),
            
            last_opcode: 0,
            
            // Initialize the new field
            elf_info: None,
        }
    }
    
    fn init_instruction_set() -> Vec<AvrInstruction> {
        let mut instructions = Vec::new();
        
        // PUSH - Push register on stack
        instructions.push(AvrInstruction {
            opcode: 0x920F,
            mask: 0xFE0F,
            mnemonic: "PUSH".to_string(),
            flags: CPU_F_STACK | CPU_F_INSTR,
            stack_change: -1,
        });
        
        // POP - Pop register from stack
        instructions.push(AvrInstruction {
            opcode: 0x900F,
            mask: 0xFE0F,
            mnemonic: "POP".to_string(),
            flags: CPU_F_STACK | CPU_F_INSTR,
            stack_change: 1,
        });
        
        // CALL - Call subroutine
        instructions.push(AvrInstruction {
            opcode: 0x940E,
            mask: 0xFE0E,
            mnemonic: "CALL".to_string(),
            flags: CPU_F_CALL | CPU_F_INSTR,
            stack_change: -2,
        });
        
        // RCALL - Relative call to subroutine
        instructions.push(AvrInstruction {
            opcode: 0xD000,
            mask: 0xF000,
            mnemonic: "RCALL".to_string(),
            flags: CPU_F_CALL | CPU_F_INSTR,
            stack_change: -2,
        });
        
        // RET - Return from subroutine
        instructions.push(AvrInstruction {
            opcode: 0x9508,
            mask: 0xFFFF,
            mnemonic: "RET".to_string(),
            flags: CPU_F_RET | CPU_F_INSTR,
            stack_change: 2,
        });
        
        // RETI - Return from interrupt
        instructions.push(AvrInstruction {
            opcode: 0x9518,
            mask: 0xFFFF,
            mnemonic: "RETI".to_string(),
            flags: CPU_F_RETI | CPU_F_INSTR,
            stack_change: 2,
        });
        
        // IJMP - Indirect jump
        instructions.push(AvrInstruction {
            opcode: 0x9409,
            mask: 0xFFFF,
            mnemonic: "IJMP".to_string(),
            flags: CPU_F_IJMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // ICALL - Indirect call to subroutine
        instructions.push(AvrInstruction {
            opcode: 0x9509,
            mask: 0xFFFF,
            mnemonic: "ICALL".to_string(),
            flags: CPU_F_CALL | CPU_F_IJMP | CPU_F_INSTR,
            stack_change: -2,
        });
        
        // JMP - Jump
        instructions.push(AvrInstruction {
            opcode: 0x940C,
            mask: 0xFE0E,
            mnemonic: "JMP".to_string(),
            flags: CPU_F_UNCOND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // RJMP - Relative jump
        instructions.push(AvrInstruction {
            opcode: 0xC000,
            mask: 0xF000,
            mnemonic: "RJMP".to_string(),
            flags: CPU_F_UNCOND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // BREQ - Branch if equal
        instructions.push(AvrInstruction {
            opcode: 0xF001,
            mask: 0xFC07,
            mnemonic: "BREQ".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // BRNE - Branch if not equal
        instructions.push(AvrInstruction {
            opcode: 0xF401,
            mask: 0xFC07,
            mnemonic: "BRNE".to_string(),
            flags: CPU_F_COND_JUMP | CPU_F_INSTR,
            stack_change: 0,
        });
        
        // ... Add more AVR instructions as needed
        
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
        
        // Find the instruction without borrowing self
        let instruction = self.find_instruction(opcode).cloned();
        
        if let Some(instr) = instruction {
            self.stack_change += instr.stack_change;
            
            // Process based on instruction flags
            if (instr.flags & CPU_F_CALL) != 0 {
                // Call instruction - extract target address
                let target = self.get_call_target(addr, opcode, &instr);
                
                // Add to call graph
                if let Some(target_addr) = target {
                    if self.call_graph.contains_key(&addr) {
                        self.call_graph.get_mut(&addr).unwrap().push(target_addr);
                    } else {
                        self.call_graph.insert(addr, vec![target_addr]);
                    }
                }
            }
            
            Ok(())
        } else {
            // Unknown instruction, but not necessarily an error in AVR analysis
            Ok(())
        }
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
                // Indirect call - we may not know the target at analysis time
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
        
        // Simulate execution to track stack changes
        self.simulate_execution(start_addr)?;
        
        // Store the maximum stack usage for this function
        let stack_usage = self.max_stack_usage;
        self.stack_map.insert(start_addr, stack_usage);
        
        Ok(stack_usage)
    }
    
    fn simulate_execution(&mut self, start_addr: CpuAddr) -> Result<()> {
        self.pc = start_addr;
        let mut stack_depth = 0;
        let mut max_stack = 0;
        let mut visited = HashSet::new();
        
        while self.pc * CPU_MIN_INSTR_SIZE < self.prog_size {
            if visited.contains(&self.pc) {
                // We've been here before, avoid infinite loops
                break;
            }
            
            visited.insert(self.pc);
            
            let opcode = self.read_opcode(self.pc);
            if let Some(instr) = self.find_instruction(opcode) {
                if (instr.flags & CPU_F_RET) != 0 {
                    // End of function
                    break;
                }
                
                stack_depth -= instr.stack_change;
                if stack_depth > max_stack {
                    max_stack = stack_depth;
                }
                
                if stack_depth < 0 {
                    // Stack underflow
                    return Err(AvrStackError::new(
                        ErrorCode::NegativeStackChange,
                        file!(),
                        line!(),
                        &format!("Negative stack change at address 0x{:x}", self.pc * CPU_MIN_INSTR_SIZE)
                    ));
                }
                
                // Process based on instruction flags
                if (instr.flags & CPU_F_CALL) != 0 {
                    // Call instruction - we'd recurse here in a full analysis
                    // For simplicity, just assume some stack usage
                    stack_depth += 4; // Estimated stack for function call
                    if stack_depth > max_stack {
                        max_stack = stack_depth;
                    }
                }
                
                if (instr.flags & (CPU_F_UNCOND_JUMP | CPU_F_COND_JUMP)) != 0 {
                    // Jump instructions can create branches
                    // In a full analysis we'd follow all branches
                    // For simplicity, just continue with the next instruction
                }
                
                // Move to next instruction
                self.pc += if instr.mnemonic == "CALL" || instr.mnemonic == "JMP" { 2 } else { 1 };
            } else {
                // Unknown instruction, just move to next
                self.pc += 1;
            }
        }
        
        self.max_stack_usage = max_stack as u32;
        
        Ok(())
    }
    
    // Add a method to get symbol name from the optional ElfInfo
    pub fn get_symbol_name(&self, addr: CpuAddr) -> Option<String> {
        if let Some(ref elf_info) = self.elf_info {
            elf_info.get_symbol_name(addr).map(String::from)
        } else {
            None
        }
    }
}

// Create an alias for compatibility with the analysis module
pub type AVRProcessor = Cpu;

// Helper functions for address sign extension
pub fn addr_sign_extend_7(x: u32) -> u32 {
    if (x & 0x40) != 0 {
        x | 0xffffff80
    } else {
        x
    }
}

pub fn addr_sign_extend_12(x: u32) -> u32 {
    if (x & 0x800) != 0 {
        x | 0xfffff000
    } else {
        x
    }
}

// Pattern matcher for AVR function prologues and epilogues
pub struct PatternMatcher {
    pub prologue_patterns: Vec<(Vec<u8>, &'static str, u32)>, // (pattern, name, stack_size)
    pub epilogue_patterns: Vec<(Vec<u8>, &'static str)>,      // (pattern, name)
}

impl PatternMatcher {
    pub fn new() -> Self {
        let mut matcher = PatternMatcher {
            prologue_patterns: Vec::new(),
            epilogue_patterns: Vec::new(),
        };
        
        // Standard function prologue for newer GCC/AVR-GCC
        matcher.prologue_patterns.push((
            vec![
                0x2f, 0x92, // push r2
                0x3f, 0x92, // push r3
                0x4f, 0x92, // push r4
                0x5f, 0x92, // push r5
                0x6f, 0x92, // push r6
                0x7f, 0x92, // push r7
                0x8f, 0x92, // push r8
                0x9f, 0x92, // push r9
                0xaf, 0x92, // push r10
                0xbf, 0x92, // push r11
                0xcf, 0x92, // push r12
                0xdf, 0x92, // push r13
                0xef, 0x92, // push r14
                0xff, 0x92, // push r15
                0x0f, 0x93, // push r16
                0x1f, 0x93, // push r17
                0xcf, 0x93, // push r28
                0xdf, 0x93, // push r29
            ],
            "modern_avr_prologue",
            18,
        ));
        
        // Shorter prologue for leaf functions
        matcher.prologue_patterns.push((
            vec![
                0xcf, 0x93, // push r28
                0xdf, 0x93, // push r29
            ],
            "leaf_function_prologue",
            2,
        ));
        
        // Standard function epilogue
        matcher.epilogue_patterns.push((
            vec![
                0xdf, 0x91, // pop r29
                0xcf, 0x91, // pop r28
                0x1f, 0x91, // pop r17
                0x0f, 0x91, // pop r16
                0xff, 0x90, // pop r15
                0xef, 0x90, // pop r14
                0xdf, 0x90, // pop r13
                0xcf, 0x90, // pop r12
                0xbf, 0x90, // pop r11
                0xaf, 0x90, // pop r10
                0x9f, 0x90, // pop r9
                0x8f, 0x90, // pop r8
                0x7f, 0x90, // pop r7
                0x6f, 0x90, // pop r6
                0x5f, 0x90, // pop r5
                0x4f, 0x90, // pop r4
                0x3f, 0x90, // pop r3
                0x2f, 0x90, // pop r2
                0x08, 0x95, // ret
            ],
            "standard_epilogue",
        ));
        
        matcher
    }
    
    pub fn find_prologue(&self, data: &[u8], start_offset: usize) -> Option<(&'static str, usize, u32)> {
        for (pattern, name, stack_size) in &self.prologue_patterns {
            if data.len() >= start_offset + pattern.len() {
                let mut matched = true;
                for (i, &byte) in pattern.iter().enumerate() {
                    if data[start_offset + i] != byte {
                        matched = false;
                        break;
                    }
                }
                
                if matched {
                    return Some((name, pattern.len(), *stack_size));
                }
            }
        }
        
        None
    }
    
    pub fn find_epilogue(&self, data: &[u8], start_offset: usize) -> Option<(&'static str, usize)> {
        for (pattern, name) in &self.epilogue_patterns {
            if data.len() >= start_offset + pattern.len() {
                let mut matched = true;
                for (i, &byte) in pattern.iter().enumerate() {
                    if data[start_offset + i] != byte {
                        matched = false;
                        break;
                    }
                }
                
                if matched {
                    return Some((name, pattern.len()));
                }
            }
        }
        
        None
    }
}
