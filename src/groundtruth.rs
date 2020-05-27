use serde_derive::{Deserialize, Serialize};

/// Flags for Instructions, Functions and Bytes.
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialOrd, PartialEq, Serialize)]
pub enum FLAG {
    CODE,
    DATA,
    EXECUTABLE,
    WRITEABLE,
    READABLE,
    INSTRUCTION_START,
    INSTRUCTION_END,
    FUNCTION_START,
    FUNCTION_END,
    BLOCK_START,
    INSTRUCTION_ALIGNMENT,
    INSTRUCTION_JUMP,
    INSTRUCTION_CALL,
    INSTRUCTION_RET,
    INSTRUCTION_INT,
    INSTRUCTION_IRET,
}

/// Describes different architectures.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, Serialize)]
pub enum ARCHITECTURE {
    X64,
    X86,
    UNKNOWN,
}

/// Describes different architectures.
#[derive(Debug, Clone, Serialize)]
pub struct Byte {
    pub offset: u64,
    pub value: u8,
    pub flags: Vec<FLAG>,
}

impl Byte {
    pub fn is_code(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::CODE)
    }

    pub fn is_data(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::DATA)
    }

    pub fn is_alignment(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_ALIGNMENT)
    }

    pub fn is_instruction_jump(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_JUMP)
    }

    pub fn is_instruction_return(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_RET)
    }

    pub fn is_instruction_start(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_START)
    }

    pub fn is_instruction_interrupt(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_INT)
    }

    pub fn is_function_start(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::FUNCTION_START)
    }

    pub fn get_flags(&self) -> Vec<FLAG> {
        self.flags.clone()
    }

    pub fn set_flags(&mut self, flags: Vec<FLAG>) {
        //self.flags.append(flags);s
        for flag in flags {
            self.flags.push(flag);
        }
        self.flags.dedup();
    }
}

/// Describes different architectures.
#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    pub mnemonic: String,
    pub operand: String,
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub length: u64,
    pub flags: Vec<FLAG>,
}

impl Instruction {
    pub fn get_flags(&self) -> Vec<FLAG> {
        self.flags.clone()
    }

    pub fn is_alignment(&self) -> bool {
        self.flags.iter().any(|x| x == &FLAG::INSTRUCTION_ALIGNMENT)
    }
    pub fn set_flags(&mut self, flags: Vec<FLAG>) {
        //self.flags.append(flags);
        for flag in flags {
            self.flags.push(flag);
        }
        self.flags.dedup();
    }
}

#[derive(Debug, Clone)]
pub struct Type {}

/// Represents a PE section and its meta data.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub raw_data_offset: u64,
    pub raw_data_size: u64,
}

/// Represents a hole (meaning contiguous unidentified bytes) within a byte vector.
#[derive(Debug)]
pub struct Hole {
    pub start: u64,
    pub end: u64,
    pub size: u64,
}

/// Represents a symbol with the S_THUNK32 tag.
#[derive(Debug, PartialEq, Serialize)]
pub struct Thunk {
    pub offset: u64,
    pub segment: u8,
    pub size: u64,
}

/// Represents a symbol with an S_LDATA32 or S_GDATA32 tag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Data {
    pub name: String,
    pub offset: u64,
    pub segment: u8,
    pub size: u64,
}

/// Represents a symbol with the S_LABEL32 tag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Label {
    pub name: String,
    pub offset: u64,
    pub segment: u8,
}

/// Represents a symbol with an S_GPROC32, S_LPROC32 or S_PUB32 tag.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Function {
    pub name: String,
    pub offset: u64,
    pub segment: u8,
    pub size: u64,
    pub labels: Vec<Label>,
    pub data: Vec<Data>,
}

/// Represents all accumulated information about a PDB file.
#[derive(Debug)]
pub struct PDB {
    pub image_base: u64,
    pub architecture: ARCHITECTURE,
    pub functions: Vec<Function>,
    pub data: Vec<Data>,
    pub thunks: Vec<Thunk>,
    pub labels: Vec<Label>,
}

/// Represents all accumulated information about a ELF file.
#[derive(Debug)]
pub struct DWARF {
    pub image_base: u64,
    pub architecture: ARCHITECTURE,
    pub functions: Vec<Function>,
}
