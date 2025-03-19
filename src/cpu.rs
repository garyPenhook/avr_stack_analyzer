// CPU simulation for AVR architecture

use std::collections::HashMap;
use std::rc::Rc;
use crate::avr_stack::Result;

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

#[derive(Debug, Clone)]
pub struct CpuInstruction {
    pub parse_func: fn(&mut Cpu),
    pub exec_func: fn(&mut Cpu),
    pub mnemonic: String,
    pub op32: bool,
}

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

#[derive(Debug)]
pub struct Cpu {
    pub instr_array: Vec<CpuInstruction>,
    pub instr: HashMap<u16, Rc<CpuInstruction>>,
    pub flags: u32,
    
    pub pc: CpuAddr,
    pub pc_prev: CpuAddr,
    pub pc_at_first_stack_out: CpuAddr,
    pub jump_to: Vec<CpuAddr>,
    
    pub prog_size: u32,
    pub iprog_size: u32,
    pub iprog_size_m2: u32,  // Lowest multiple of 2 >= iprog_size
    pub ram_start: u32,
    pub opcode: u32,
    pub opcode2: u32,  // If Instr->op32
    
    pub big_a: u32,
    pub big_k: u32,
    pub bbb: u32,
    pub k: u32,
    pub rd: u32,
    pub rr: u32,
    pub q: u32,
    pub sss: u32,
    
    pub prog: Vec<u8>,
    pub stack_change: i32,
    
    pub wrap_0: bool,
    
    pub icall_list: Vec<CpuICallListEntry>,
    pub parse_history: [CpuAddr; 6],
    
    pub ijmp: IjmpInfo,
}

impl Cpu {
    pub fn new() -> Self {
        Cpu {
            instr_array: Vec::with_capacity(100),
            instr: HashMap::new(),
            flags: 0,
            
            pc: 0,
            pc_prev: 0,
            pc_at_first_stack_out: 0,
            jump_to: vec![0; 256],
            
            prog_size: 0,
            iprog_size: 0,
            iprog_size_m2: 0,
            ram_start: 0,
            opcode: 0,
            opcode2: 0,
            
            big_a: 0,
            big_k: 0,
            bbb: 0,
            k: 0,
            rd: 0,
            rr: 0,
            q: 0,
            sss: 0,
            
            prog: Vec::new(),
            stack_change: 0,
            
            wrap_0: false,
            
            icall_list: Vec::new(),
            parse_history: [0; 6],
            
            ijmp: IjmpInfo {
                table_size: 0,
                data_size: 0,
                addr: 0,
            },
        }
    }
    
    pub fn init(&mut self, prog: Vec<u8>, prog_size: u32, ram_start: u32) -> Result<()> {
        self.prog = prog;
        self.prog_size = prog_size;
        self.ram_start = ram_start;
        
        // Convert prog_size to instruction units
        self.iprog_size = self.prog_size / CPU_MIN_INSTR_SIZE;
        
        // Find lowest multiple of 2 >= iprog_size
        let mut m2 = 1;
        while m2 < self.iprog_size {
            m2 *= 2;
        }
        self.iprog_size_m2 = m2;
        
        Ok(())
    }
    
    // CPU instruction parsing and execution methods would follow
    // ...
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

// Pattern matcher for CPU instruction recognition
pub struct PatternMatcher {
    patterns: Vec<(Vec<u8>, &'static str)>,
}

impl PatternMatcher {
    pub fn new() -> Self {
        let mut matcher = PatternMatcher {
            patterns: Vec::new(),
        };
        
        // Add the newer compiler prologue pattern
        matcher.patterns.push((
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
        ));
        
        // Add more patterns...
        
        matcher
    }
    
    pub fn find_pattern(&self, data: &[u8], start_offset: usize) -> Option<(&'static str, usize)> {
        for (pattern, name) in &self.patterns {
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
