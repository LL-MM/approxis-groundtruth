pub mod yaml {
    pub mod pdb {

        use log::{debug, error, info, warn};
        use std::fs::File;
        use std::io::prelude::*;

        use crate::groundtruth;
        use yaml_rust::{Yaml, YamlLoader};

        pub fn load_pdb(path: &str) -> Result<groundtruth::PDB, &'static str> {
            let mut f = match File::open(path) {
                Ok(f) => f,
                Err(_e) => {
                    return Err("[-] Could not find file!");
                }
            };

            let mut contents = String::new();

            match f.read_to_string(&mut contents) {
                Ok(_f) => {}
                Err(_e) => {
                    return Err("[-] Could not read file!");
                }
            };

            let docs = YamlLoader::load_from_str(contents.as_str()).unwrap();

            let doc = &docs[0];

            // Guard: Check if TpiStream exists
            if doc["TpiStream"].is_badvalue() {
                return Err("Could not parse TpiStream");
            }

            // Guard: Check if DbiStream exists
            if doc["DbiStream"].is_badvalue() {
                return Err("Could not parse DbiStream");
            }

            let dbi_stream = &doc["DbiStream"];
            let tpi_stream = &doc["TpiStream"];

            // Collections
            let mut functions: Vec<groundtruth::Function> = Vec::new();
            let mut labels: Vec<groundtruth::Label> = Vec::new();
            let mut data: Vec<groundtruth::Data> = Vec::new();
            let mut thunks: Vec<groundtruth::Thunk> = Vec::new();
            let mut _types: Vec<groundtruth::Type> = Vec::new();

            // Collect all types

            for record in tpi_stream["Records"].as_vec().unwrap() {
                match record["Kind"].as_str().unwrap() {
                    "LF_STRUCTURE" => {}
                    _ => {}
                }
            }

            // Iterate all modules
            for module in dbi_stream["Modules"].as_vec().unwrap() {
                // Guard: Check if module has "Modi"
                if module["Modi"].is_badvalue() {
                    continue;
                }

                for record in module["Modi"]["Records"].as_vec().unwrap() {
                    match record["Kind"].as_str().unwrap() {
                        "S_GPROC32" => {
                            functions.push(parse_function(&record));
                        }
                        "S_LPROC32" => {
                            functions.push(parse_function(&record));
                        }
                        "S_PUB32" => {
                            functions.push(parse_function(&record));
                        }
                        "S_THUNK32" => {
                            let thunk = parse_thunk(&record);

                            functions.push(groundtruth::Function {
                                name: "<Thunk>".to_string(),
                                offset: thunk.offset,
                                segment: thunk.segment,
                                size: thunk.size,
                                labels: Vec::new(),
                                data: Vec::new(),
                            });

                            thunks.push(thunk);
                        }
                        "S_LABEL32" => {
                            labels.push(parse_label(&record));
                        }
                        "S_LDATA32" => {
                            data.push(parse_data(&record));
                        }
                        "S_GDATA32" => {
                            data.push(parse_data(&record));
                        }
                        _ => {}
                    }
                }
            }

            debug!("##### PARSER ######");
            debug!("Functions: {}", functions.len());
            debug!("Labels: {}", labels.len());
            debug!("Data: {}", data.len());
            debug!("Thunks: {}", thunks.len());

            // Sort symbols by address
            functions.sort_by(|a, b| a.offset.cmp(&b.offset));
            data.sort_by(|a, b| a.offset.cmp(&b.offset));
            labels.sort_by(|a, b| a.offset.cmp(&b.offset));
            thunks.sort_by(|a, b| a.offset.cmp(&b.offset));

            // Remove duplicates
            functions.dedup();
            data.dedup();
            labels.dedup();
            thunks.dedup();

            // Collect meta information
            let architecture = match dbi_stream["MachineType"].as_str().unwrap() {
                "x86" => groundtruth::ARCHITECTURE::X86,
                "x64" => groundtruth::ARCHITECTURE::X64,
                _ => groundtruth::ARCHITECTURE::UNKNOWN,
            };

            let image_base = match dbi_stream["MachineType"].as_str().unwrap() {
                "x86" => 0x400000,
                "x64" => 0x140000000,
                _ => 0x140000000,
            };

            Ok(groundtruth::PDB {
                architecture,
                image_base,
                functions,
                thunks,
                data,
                labels,
            })
        }

        /// Add.
        fn parse_function(record: &Yaml) -> groundtruth::Function {
            groundtruth::Function {
                name: record["ProcSym"]["DisplayName"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                offset: record["ProcSym"]["Offset"].as_i64().unwrap() as u64,
                segment: record["ProcSym"]["Segment"].as_i64().unwrap() as u8,
                size: record["ProcSym"]["CodeSize"].as_i64().unwrap() as u64,
                labels: Vec::new(),
                data: Vec::new(),
            }
        }

        /// Add.
        fn parse_thunk(record: &Yaml) -> groundtruth::Thunk {
            groundtruth::Thunk {
                offset: record["Thunk32Sym"]["Off"].as_i64().unwrap() as u64,
                segment: record["Thunk32Sym"]["Seg"].as_i64().unwrap() as u8,
                size: record["Thunk32Sym"]["Len"].as_i64().unwrap() as u64,
            }
        }

        /// Add.
        fn parse_label(record: &Yaml) -> groundtruth::Label {
            groundtruth::Label {
                name: record["LabelSym"]["DisplayName"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                offset: record["LabelSym"]["Offset"].as_i64().unwrap() as u64,
                segment: record["LabelSym"]["Segment"].as_i64().unwrap() as u8,
            }
        }

        /// Add.
        fn parse_data(record: &Yaml) -> groundtruth::Data {
            let name = match record["DataSym"]["DisplayName"].as_str() {
                Some(name) => name,
                None => "PLACEHOLDER",
            };

            groundtruth::Data {
                name: name.to_string(),
                offset: record["DataSym"]["Offset"].as_i64().unwrap() as u64,
                segment: record["DataSym"]["Segment"].as_i64().unwrap() as u8,
                size: 0,
            }
        }
    }

    pub mod elf {
        use log::{debug, error, info, warn};
        use std::collections::HashMap;
        use std::fs::File;
        use std::io::prelude::*;

        use crate::groundtruth;
        use yaml_rust::{Yaml, YamlLoader};

        /// Some documentation.
        #[allow(dead_code)]
        pub fn load_elf(path: &str) -> Result<groundtruth::DWARF, &'static str> {
            let mut f = match File::open(path) {
                Ok(f) => f,
                Err(_e) => {
                    return Err("[-] Could not find file!");
                }
            };

            let mut contents = String::new();

            match f.read_to_string(&mut contents) {
                Ok(_f) => {}
                Err(_e) => {
                    return Err("[-] Could not read file!");
                }
            };

            let docs = YamlLoader::load_from_str(contents.as_str()).unwrap();

            let doc = &docs[0];

            // Guard: Check if TpiStream exists
            if doc["Symbols"].is_badvalue() {
                return Err("Could not parse Symbols");
            }

            let symbols = &doc["Symbols"];
            let file_header = &doc["FileHeader"];
            let sections = &doc["Sections"];

            let mut ssections = HashMap::new();

            for (index, section) in sections.as_vec().unwrap().iter().enumerate() {
                ssections.insert(section["Name"].as_str().unwrap(), index);
                debug!("{}: {}", index, section["Name"].as_str().unwrap());
            }

            // Collections
            let mut functions: Vec<groundtruth::Function> = Vec::new();

            // Iterate all symbols (local, global, weak)
            let mut all_symbols = Vec::new();

            // TODO: This was the old format of obj2yaml.
            // all_symbols.extend(symbols["Local"].as_vec().unwrap());
            // all_symbols.extend(symbols["Global"].as_vec().unwrap());
            // all_symbols.extend(symbols["Weak"].as_vec().unwrap());
            all_symbols.extend_from_slice(symbols.as_vec().unwrap());

            for symbol in all_symbols {
                // Guard: Check if module has "Modi"
                if symbol["Type"].is_badvalue() {
                    continue;
                }
                match symbol["Type"].as_str().unwrap() {
                    "STT_FUNC" => {
                        if let Some(function) = parse_function(&symbol, &ssections) {
                            functions.push(function);
                        }
                    }
                    _ => {}
                }
            }

            debug!("##### PARSER ######");
            debug!("Functions: {}", functions.len());

            // Sort symbols by address
            functions.sort_by(|a, b| a.offset.cmp(&b.offset));

            // Remove duplicates
            functions.dedup();

            // Collect meta information
            let architecture = match file_header["Class"].as_str().unwrap() {
                "ELFCLASS32" => groundtruth::ARCHITECTURE::X86,
                "ELFCLASS64" => groundtruth::ARCHITECTURE::X64,
                _ => groundtruth::ARCHITECTURE::UNKNOWN,
            };

            let image_base = match file_header["Class"].as_str().unwrap() {
                "ELFCLASS32" => 0x400000,
                "ELFCLASS64" => 0x140000000,
                _ => 0x140000000,
            };

            Ok(groundtruth::DWARF {
                architecture,
                image_base,
                functions,
            })
        }

        /// Add.
        fn parse_function(
            record: &Yaml,
            sections: &HashMap<&str, usize>,
        ) -> Option<groundtruth::Function> {
            let name = record["Name"].as_str().unwrap();

            let section = match record["Section"].as_str() {
                Some(section) => section,
                None => {
                    debug!("Function {} has no section", name);
                    return None;
                }
            };

            let size = match record["Size"].as_i64() {
                Some(size) => size,
                None => {
                    debug!("Function {} has no size", name);
                    return None;
                }
            };

            let offset = match record["Value"].as_i64() {
                Some(offset) => offset,
                None => {
                    debug!("Function {} has no offset", name);
                    return None;
                }
            };

            Some(groundtruth::Function {
                name: name.to_string(),
                offset: offset as u64,
                segment: *sections.get(section).unwrap() as u8,
                size: size as u64,
                labels: Vec::new(),
                data: Vec::new(),
            })
        }
    }
}
