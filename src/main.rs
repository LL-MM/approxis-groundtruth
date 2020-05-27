pub mod b2g;
pub mod disassembler;
pub mod dumper;
pub mod elf;
pub mod groundtruth;
pub mod parser;
pub mod pe;

use clap::{App, Arg};
use goblin::{error, Object};
use log::{error, info, warn};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn main() {
    let matches = App::new("Binary2Groundtruth")
        .version("0.1")
        .author("xitan <git@xitan.me>")
        .about("Creates groundtruth mappings from PDBs/ELFs.")
        .arg(
            Arg::with_name("DUMP")
                .help("Sets the input PDB/ELF YAML dump to use.")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("BINARY")
                .help("Sets the input PE/ELF to use.")
                .required(true)
                .index(2),
        )
        .get_matches();

    //pdb2groundtruth::run(matches.value_of("PDB").unwrap(), matches.value_of("PE").unwrap());

    simple_logger::init().unwrap();

    info!("[+] Binary2Groundtruth Parser started.");

    let mut fd =
        File::open(matches.value_of("BINARY").unwrap()).expect("[-] Could not find binary.");
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)
        .expect("[-] Could not read binary.");
    match Object::parse(&buffer).expect("") {
        Object::Elf(_) => {
            let mut p2g = b2g::elf::ELF::new(
                matches.value_of("DUMP").unwrap(),
                matches.value_of("BINARY").unwrap(),
            );
            p2g.process();
        }
        Object::PE(_) => {
            let mut p2g = b2g::pe::PE::new(
                matches.value_of("DUMP").unwrap(),
                matches.value_of("BINARY").unwrap(),
            );
            p2g.process();
        }
        _ => {
            error!("[-] Binary not supported. Only PE and ELF binaries are supported.");
        }
    }
}
