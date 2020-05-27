use std::mem;

use crate::groundtruth;
use capstone::prelude::*;
use fancy_regex::Regex;
use lazy_static::lazy_static;

#[allow(dead_code)]
pub enum DISASSEMBLER {
    CAPSTONE,
    ZYDIS,
}

#[allow(dead_code)]
mod cs_group_type {
    pub type Type = u8;

    pub const CS_GRP_INVALID: Type = 0;
    pub const CS_GRP_JUMP: Type = 1;
    pub const CS_GRP_CALL: Type = 2;
    pub const CS_GRP_RET: Type = 3;
    pub const CS_GRP_INT: Type = 4;
    pub const CS_GRP_IRET: Type = 5;
}

pub fn disassemble(
    buffer: Vec<u8>,
    architecture: &groundtruth::ARCHITECTURE,
    disassembler: DISASSEMBLER,
) -> Result<Vec<groundtruth::Instruction>, &'static str> {
    match disassembler {
        DISASSEMBLER::CAPSTONE => {
            return disassemble_capstone(buffer, architecture);
        }
        DISASSEMBLER::ZYDIS => {
            return disassemble_zydis(buffer, architecture);
        }
    }
}

pub fn disassemble_capstone(
    buffer: Vec<u8>,
    architecture: &groundtruth::ARCHITECTURE,
) -> Result<Vec<groundtruth::Instruction>, &'static str> {
    let mut instructions = Vec::new();

    let mode = match architecture {
        groundtruth::ARCHITECTURE::X86 => arch::x86::ArchMode::Mode32,
        groundtruth::ARCHITECTURE::X64 => arch::x86::ArchMode::Mode64,
        _ => arch::x86::ArchMode::Mode64,
    };

    let mut cs = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .unwrap();

    let disassembled_instructions = match cs.disasm_all(&buffer, 0x0) {
        Ok(instructions) => instructions,
        Err(_e) => {
            return Err("Could not disassemble given bytes!");
        }
    };

    // debug!("Found {} instructions", disassembled_instructions.len());

    for i in disassembled_instructions.iter() {
        // Create new instructions
        let mut instruction = groundtruth::Instruction {
            mnemonic: i.mnemonic().unwrap().to_string(),
            operand: i.op_str().unwrap().to_string(),
            bytes: i.bytes().to_vec(),
            offset: i.address(),
            length: i.bytes().len() as u64,
            flags: Vec::new(),
        };

        // Get details for groups
        let detail: InsnDetail = cs.insn_detail(&i).unwrap();

        // Set specific instruction flags depending on group type
        for group in detail.groups() {
            let group_id = unsafe { mem::transmute::<InsnGroupId, u8>(group) };
            match group_id {
                cs_group_type::CS_GRP_CALL => {
                    instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_CALL]);
                }
                cs_group_type::CS_GRP_INT => {
                    instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_INT]);
                }
                cs_group_type::CS_GRP_IRET => {
                    instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_IRET]);
                }
                cs_group_type::CS_GRP_JUMP => {
                    instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_JUMP]);
                }
                cs_group_type::CS_GRP_RET => {
                    instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_RET]);
                }
                _ => {}
            }
        }

        // Check if instruction is a nop (single/multi byte) and set align flag if true
        if i.mnemonic().unwrap() == "nop" {
            instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
        }

        lazy_static! {
            static ref RE: Regex =
                Regex::new("^(r|e)([a-z]{2}), dword ptr \\[(r|e)\\2\\]$").unwrap();
        }

        // Check if instruction is a MSVC specific "NOP"
        // Note: these are not real NOPs since they introduce data dependency
        // TODO: Add mov

        if i.mnemonic().unwrap() == "lea" {
            if RE.is_match(i.op_str().unwrap()).unwrap() {
                instruction.set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
            }
        }

        instructions.push(instruction);
    }

    Ok(instructions)
}

pub fn disassemble_zydis(
    _buffer: Vec<u8>,
    _architecture: &groundtruth::ARCHITECTURE,
) -> Result<Vec<groundtruth::Instruction>, &'static str> {
    let instructions = Vec::new();
    Ok(instructions)
}
