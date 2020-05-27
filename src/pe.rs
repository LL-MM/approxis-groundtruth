use std::fs::File;
use std::io::Read;

use goblin::pe;
use goblin::pe::header::{COFF_MACHINE_X86, COFF_MACHINE_X86_64};

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

    let pe = match pe::PE::parse(&buffer) {
        Ok(pe) => pe,
        Err(_e) => {
            return Err("[-] Could not parse pe");
        }
    };

    let architecture = match pe.header.coff_header.machine {
        COFF_MACHINE_X86 => groundtruth::ARCHITECTURE::X86,
        COFF_MACHINE_X86_64 => groundtruth::ARCHITECTURE::X64,
        _ => groundtruth::ARCHITECTURE::UNKNOWN,
    };

    Ok(architecture)
}

pub fn read_pe(path: &str) -> Result<Vec<groundtruth::Byte>, &'static str> {
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

    let pe = match pe::PE::parse(&buffer) {
        Ok(pe) => pe,
        Err(_e) => {
            return Err("[-] Could not parse pe");
        }
    };

    let mut sections: Vec<groundtruth::Section> = Vec::new();

    for section in pe.sections {
        let name = match String::from_utf8(section.name.to_vec()) {
            Ok(name) => name.trim_matches(char::from(0)).to_string(),
            Err(_e) => "PLACEHOLDER".to_string(),
        };

        sections.push(groundtruth::Section {
            name,
            va: section.virtual_address as u64,
            raw_data_offset: section.pointer_to_raw_data as u64,
            raw_data_size: section.size_of_raw_data as u64,
        });
    }

    Ok(sections)
}
