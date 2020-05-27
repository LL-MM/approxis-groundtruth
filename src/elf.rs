use std::fs::File;
use std::io::Read;

use goblin::elf;
use goblin::elf::header;

use crate::groundtruth;

pub fn get_architecture(path: &str) -> Result<groundtruth::ARCHITECTURE, &'static str> {
    let mut buffer = Vec::new();

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_e) => {
            return Err("[-] Could not find file!");
        }
    };

    match f.read_to_end(&mut buffer) {
        Ok(_f) => {}
        Err(_e) => {
            return Err("[-] Could not read file!");
        }
    };

    let elf = match elf::Elf::parse(&buffer) {
        Ok(pe) => pe,
        Err(_e) => {
            return Err("[-] Could not parse ELF!");
        }
    };

    let architecture = match elf.is_64 {
        false => groundtruth::ARCHITECTURE::X86,
        true => groundtruth::ARCHITECTURE::X64,
        _ => groundtruth::ARCHITECTURE::UNKNOWN,
    };

    Ok(architecture)
}

/// Add.
pub fn read_elf(path: &str) -> Result<Vec<groundtruth::Byte>, &'static str> {
    let mut buffer = Vec::new();
    let mut bytes = Vec::new();

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_e) => {
            return Err("[-] Could not find file!");
        }
    };

    match f.read_to_end(&mut buffer) {
        Ok(_f) => {}
        Err(_e) => {
            return Err("[-] Could not read file!");
        }
    };

    for (offset, byte) in buffer.iter().enumerate() {
        bytes.push(groundtruth::Byte {
            offset: offset as u64,
            value: *byte,
            flags: Vec::new(),
        })
    }

    Ok(bytes)
}

/// Add.
pub fn parse_sections(path: &str) -> Result<Vec<groundtruth::Section>, &'static str> {
    let mut buffer = Vec::new();

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_e) => {
            return Err("[-] Could not find file!");
        }
    };

    match f.read_to_end(&mut buffer) {
        Ok(_f) => {}
        Err(_e) => {
            return Err("[-] Could not read file!");
        }
    };

    let elf = match elf::Elf::parse(&buffer) {
        Ok(pe) => pe,
        Err(_e) => {
            return Err("[-] Could not parse pe");
        }
    };

    let mut sections: Vec<groundtruth::Section> = Vec::new();

    for section in elf.section_headers {
        let name = match elf.shdr_strtab.get(section.sh_name) {
            Some(name) => name.unwrap().to_string(),
            None => "Placeholder".to_string(),
        };

        sections.push(groundtruth::Section {
            name,
            va: section.sh_addr as u64,
            raw_data_offset: section.sh_offset as u64,
            raw_data_size: section.sh_size as u64,
        });
    }

    Ok(sections)
}
