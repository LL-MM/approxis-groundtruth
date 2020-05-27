use crate::groundtruth;
use serde_derive::{Deserialize, Serialize};

/// Represents a dump containing all the information about a PDB obtained.
#[derive(Serialize)]
struct Dump {
    version: String,
    timestamp: u64,
    architecture: groundtruth::ARCHITECTURE,
    total_bytes: u64,
    bytes_identified: u64,
    accuracy: f64,
    bytes: Vec<groundtruth::Byte>,
    functions: Vec<groundtruth::Function>,
    instructions: Vec<groundtruth::Instruction>,
}

pub mod plain {
    use std::fs;

    use crate::b2g;
    use crate::groundtruth;

    pub fn dump(
        file_name: String,
        image_base: u64,
        sections: Vec<groundtruth::Section>,
        bytes: Vec<groundtruth::Byte>,
    ) {
        let mut string = String::new();

        for section in sections {
            string += &format!("******* section {} *******\n", section.name);
            string += &format!(
                "<{} va: 0x{:08X}, size:0x{:08X}, flags: []>\n",
                section.name, section.va, section.raw_data_size
            );

            if section.name == ".text" {
                let mut i = 0;

                while i < bytes.len() {
                    let mut byte = &bytes[i];

                    string += &format!("@0x{:012X}: ", byte.offset + image_base);

                    let mut flags = "[".to_string();

                    if byte.is_code() {
                        // Check and set code related flags
                        if byte.is_function_start() {
                            flags += "F";
                        }

                        // This will be bytes used for alignment which are not reachable at all
                        if byte.is_alignment() {
                            flags += "N";
                        }

                        if byte.is_instruction_jump() {
                            flags += "J";
                        }

                        if byte.is_instruction_interrupt() {
                            flags += "3";
                        }

                        if byte.is_instruction_return() {
                            flags += "R";
                        }

                        if byte.is_instruction_start() {
                            flags += "I";
                        }

                        if byte.is_code() {
                            flags += "C";
                        }

                        flags += "]";

                        i += 1;
                        for j in i..bytes.len() {
                            byte = &bytes[j];

                            if byte.is_code()
                                && !byte.is_instruction_start()
                                && !byte.is_data()
                                && !byte.is_alignment()
                            {
                                flags += "C";
                                i += 1;
                            } else {
                                break;
                            }
                        }
                    } else if byte.is_data() {
                        flags += "D]";

                        i += 1;
                        for j in i..bytes.len() {
                            byte = &bytes[j];

                            if byte.is_data()
                                && !byte.is_instruction_start()
                                && !byte.is_code()
                                && !byte.is_alignment()
                            {
                                flags += "D";
                                i += 1;
                            } else {
                                break;
                            }
                        }
                    } else if byte.is_alignment() {
                        flags += "N]";

                        i += 1;
                        for j in i..bytes.len() {
                            byte = &bytes[j];

                            if byte.is_alignment()
                                && !byte.is_instruction_start()
                                && !byte.is_code()
                                && !byte.is_data()
                            {
                                flags += "N";
                                i += 1;
                            } else {
                                break;
                            }
                        }
                    } else {
                        flags += "U]";

                        i += 1;
                        for j in i..bytes.len() {
                            byte = &bytes[j];

                            if !byte.is_alignment()
                                && !byte.is_instruction_start()
                                && !byte.is_code()
                                && !byte.is_data()
                            {
                                flags += "U";
                                i += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    string += &flags;
                    string += "\n";
                }
            }
        }

        // Save dump
        fs::write(format!("{}.txt", file_name), string).expect("Unable to write file");
    }

    pub fn dump_pe(pe: &b2g::pe::PE) {
        dump(
            pe.file_name.clone(),
            pe.pdb.image_base,
            pe.sections.clone(),
            pe.bytes.clone(),
        );
    }

    pub fn dump_elf(elf: &b2g::elf::ELF) {
        dump(
            elf.file_name.clone(),
            elf.dwarf.image_base,
            elf.sections.clone(),
            elf.bytes.clone(),
        );
    }
}

pub mod yaml {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_yaml;

    use crate::b2g;
    use crate::dumper;
    use crate::groundtruth;

    pub fn dump(
        file_name: String,
        architecture: groundtruth::ARCHITECTURE,
        bytes: Vec<groundtruth::Byte>,
        functions: Vec<groundtruth::Function>,
        instructions: Vec<groundtruth::Instruction>,
    ) {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("System time went backwards");

        let total_bytes = bytes.len();
        let bytes_identified = bytes.iter().filter(|b| b.get_flags().len() > 0).count();

        let dump = dumper::Dump {
            version: "v0.1".to_string(),
            timestamp: since_the_epoch.as_secs(),
            architecture,
            total_bytes: total_bytes as u64,
            bytes_identified: bytes_identified as u64,
            accuracy: 100.0 * (bytes_identified as f64 / total_bytes as f64),
            bytes: bytes.clone(),
            functions: functions.clone(),
            instructions: instructions.clone(),
        };

        // Serialize
        let s = serde_yaml::to_string(&dump).unwrap();

        // Save dump
        fs::write(format!("{}.yaml", file_name), s).expect("Unable to write file");
    }

    pub fn dump_pe(pe: &b2g::pe::PE) {
        dump(
            pe.file_name.clone(),
            pe.architecture,
            pe.bytes.clone(),
            pe.pdb.functions.clone(),
            pe.instructions.clone(),
        );
    }

    pub fn dump_elf(elf: &b2g::elf::ELF) {
        dump(
            elf.file_name.clone(),
            elf.architecture,
            elf.bytes.clone(),
            elf.dwarf.functions.clone(),
            elf.instructions.clone(),
        );
    }
}
