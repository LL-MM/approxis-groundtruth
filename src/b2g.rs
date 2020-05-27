pub mod pe {
    use log::{debug, error, info, warn};
    use std::path;
    use std::process;

    use crate::disassembler;
    use crate::dumper;
    use crate::groundtruth;
    use crate::parser;
    use crate::pe;

    pub struct PE {
        pub architecture: groundtruth::ARCHITECTURE,
        pub file_name: String,
        pub pdb: groundtruth::PDB,
        pub sections: Vec<groundtruth::Section>,
        pub bytes: Vec<groundtruth::Byte>,
        pub instructions: Vec<groundtruth::Instruction>,
    }

    impl PE {
        pub fn new(path_to_yaml: &str, path_to_pe: &str) -> Self {
            // Grab filename from path
            let file_name = path::Path::new(path_to_pe)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            // Retrieve architecture from PE header
            let architecture = match pe::get_architecture(path_to_pe) {
                Ok(architecture) => architecture,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Collect symbols from PDB
            let pdb = match parser::yaml::pdb::load_pdb(path_to_yaml) {
                Ok(pdb) => pdb,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Collect sections from PE header
            // Note: PE header sections start at 0 while PDB segments start at 1
            let sections = match pe::parse_sections(path_to_pe) {
                Ok(sections) => sections,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Create raw byte vector from binary
            let bytes = match pe::read_pe(path_to_pe) {
                Ok(byte_vector) => byte_vector,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            PE {
                file_name,
                architecture,
                pdb,
                sections,
                bytes,
                instructions: Vec::new(),
            }
        }

        pub fn process(&mut self) {
            // Grab text section
            let text_section = match self.sections.iter().find(|s| s.name == ".text") {
                Some(text_section) => text_section.clone(),
                None => {
                    error!("[-] Binary does not have a text section!");
                    process::exit(1);
                }
            };

            // Trim byte vector (we only need the data of text section) that means cut before raw
            // data start and after raw data end
            self.trim_byte_vector(
                text_section.raw_data_offset,
                text_section.raw_data_offset + text_section.raw_data_size,
            );

            self.rebase_byte_vector(0x1000);

            // Pre-process functions
            self.preprocess_functions();

            // Connect found symbols  (e.g. add data or labels within a function to its parent function)
            self.create_relationships();

            // Cut in-line data which is at the end of a function (jump tables)
            self.cut_in_line_data_end();

            // Cut in-line data which is in the middle of a function (jump tables)
            self.cut_in_line_data_mid();

            // Set byte flags (code/data is already known)
            self.set_byte_flags();

            // Disassemble code bytes (functions)
            self.disassemble();

            // Detect alignment/filler bytes
            self.detect_alignment_bytes();

            // Detect end of section
            self.detect_end_of_section();

            // Create debug print
            self.print();

            // Create final mapping
            dumper::plain::dump_pe(&self);
            dumper::yaml::dump_pe(&self);
        }

        fn disassemble(&mut self) {
            for function in &mut self.pdb.functions {
                let mut function_buffer = Vec::new();

                for offset in 0..function.size {
                    // Guard: Byte already flagged as data
                    if self.bytes[(function.offset + offset) as usize].is_data() {
                        continue;
                    }

                    // Set specific flags
                    self.bytes[(function.offset + offset) as usize].set_flags(vec![
                        groundtruth::FLAG::CODE,
                        groundtruth::FLAG::READABLE,
                        groundtruth::FLAG::EXECUTABLE,
                    ]);

                    // Add byte to function buffer
                    function_buffer.push(self.bytes[(function.offset + offset) as usize].value);
                }

                // Set function start and end
                self.bytes[function.offset as usize]
                    .set_flags(vec![groundtruth::FLAG::FUNCTION_START]);
                self.bytes[(function.offset + function.size - 1) as usize]
                    .set_flags(vec![groundtruth::FLAG::FUNCTION_END]);

                // Disassemble function bytes
                let instructions = match disassembler::disassemble(
                    function_buffer,
                    &self.pdb.architecture,
                    disassembler::DISASSEMBLER::CAPSTONE,
                ) {
                    Ok(instructions) => instructions,
                    Err(e) => {
                        error!("{}", e);
                        process::exit(1);
                    }
                };
                // Set instruction start and end, copy instruction flags
                for instruction in instructions {
                    // Since we (may have) cut our function buffer in the middle our instruction offset will become "wrong"
                    // the moment we come to the first instruction after the "hole" we created by erasing some bytes in the middle
                    // since they were data bytes. Therefore we need to account for the additional offset created by the size of the
                    // removed bytes.
                    // TODO: Handle multiple holes in the middle.
                    let mut additional_offset = 0;

                    for data in &function.data {
                        // Check current instruction has a offset which would in theory place in the inline data hole
                        if (instruction.offset + function.offset + additional_offset) >= data.offset
                        {
                            additional_offset += data.size;
                        }
                    }

                    self.bytes[(additional_offset + function.offset + instruction.offset) as usize]
                        .set_flags(vec![groundtruth::FLAG::INSTRUCTION_START]);

                    // Instruction End Example: Start 0x0, Size 0x8 => Instruction: 0x0-0x8 therefore the 8th byte (the last byte) is 0x7
                    self.bytes[(additional_offset
                        + function.offset
                        + instruction.offset
                        + instruction.length
                        - 1) as usize]
                        .set_flags(vec![groundtruth::FLAG::INSTRUCTION_END]);

                    // TODO: Set instruction flags for not only the first byte of instruction
                    self.bytes[(additional_offset + function.offset + instruction.offset) as usize]
                        .set_flags(instruction.get_flags());

                    // debug!("{:x?}", instruction);

                    // Append to instructions vector
                    self.instructions.push(instruction);
                }
            }
        }

        fn preprocess_functions(&mut self) {
            self.pdb.functions.retain(|ref f| f.size > 0)
        }

        fn set_byte_flags(&mut self) {
            for function in &self.pdb.functions {
                // Set data flags
                // Attention: we have to use the child data of a function and not from the normal
                // data collection because ONLY the child data has a up-to-date size value.
                for data in &function.data {
                    for i in 0..data.size {
                        self.bytes[(data.offset + i) as usize]
                            .set_flags(vec![groundtruth::FLAG::DATA]);
                    }
                }

                // Set data and code flags
                for i in 0..function.size {
                    // Guard: Check if byte is already data (because there is data within the function)
                    if self.bytes[(function.offset + i) as usize].is_data() {
                        continue;
                    }

                    self.bytes[(function.offset + i) as usize]
                        .set_flags(vec![groundtruth::FLAG::CODE]);
                }
            }
        }

        fn trim_byte_vector(&mut self, start: u64, end: u64) {
            // Cut current start to new start and new end to current end
            self.bytes.drain(..start as usize);
            self.bytes.drain((end - start) as usize..);
        }

        fn rebase_byte_vector(&mut self, base: u64) {
            // Reset offsets
            for (offset, byte) in self.bytes.iter_mut().enumerate() {
                byte.offset = offset as u64 + base;
            }
        }

        fn cut_in_line_data_end(&mut self) {
            // Check for every function if there is in-line data at its end
            for function in &mut self.pdb.functions {
                for data in &mut function.data {
                    // Guard: Data which is in the middle of function has always an empty name
                    if data.name != "" {
                        continue;
                    }

                    // Check if data is in bounds of function (maybe function has multiple in-line data
                    // and has already been cut before the current data symbol
                    if data.offset > function.offset
                        && data.offset < (function.offset + function.size)
                    {
                        // Set size of data
                        data.size = (function.size + function.offset) - data.offset;

                        // Cut function: set end of function to start of data
                        function.size = data.offset - function.offset;
                    }
                }
            }
        }

        fn cut_in_line_data_mid(&mut self) {
            // Check for every function if there is in-line data at its end
            for function in &mut self.pdb.functions {
                for data in &mut function.data {
                    // Guard: Data which is in the middle of function never has an empty name
                    if data.name == "" {
                        continue;
                    }

                    // Count labels within function which contain the base name of the data
                    // Example: Name of jump table: "MsetTab" and name of its labels: "msetTabX" (x is a number between 0-<amount of switch cases>)
                    let mut label_counter = 0;

                    // Make base name lower case for comparison with label name
                    let mut base_name = data.name.to_lowercase();

                    // Remove suffix "vec" if existend
                    base_name = base_name.replace("vec", "");

                    for label in &function.labels {
                        if label.name.to_lowercase().contains(base_name.as_str()) {
                            label_counter += 1;
                        }
                    }

                    // Set calculated size for data
                    data.size = label_counter * 0x4;
                }
            }
        }

        fn create_relationships(&mut self) {
            // Add relationships between labels/data and its parent functions
            for function in &mut self.pdb.functions {
                // Check all labels available
                for label in &self.pdb.labels {
                    // Guard: Check if same segment
                    if label.segment != function.segment {
                        continue;
                    }

                    // Check if label is within function boundary

                    if label.offset > function.offset
                        && label.offset < (function.offset + function.size)
                    {
                        function.labels.push(label.clone());
                    }
                }

                // Check all data available
                for data in &self.pdb.data {
                    // Guard: Check if same segment
                    if data.segment != function.segment {
                        continue;
                    }

                    if data.offset > function.offset
                        && data.offset < (function.offset + function.size)
                    {
                        function.data.push(data.clone());
                    }
                }
            }
        }

        fn print(&self) {
            debug!("######## META ###########");
            debug!("{:?}", self.pdb.architecture);

            debug!("######## SECTIONS #########");
            for section in &self.sections {
                debug!("{:x?}", section);
            }

            debug!("######## FUNCTIONS #########");
            for function in &self.pdb.functions {
                debug!("{:x?}", function);
            }

            debug!("######## THUNKS ###########");
            for thunks in &self.pdb.thunks {
                debug!("{:x?}", thunks);
            }

            debug!("####### DATA ##########");
            for data in &self.pdb.data {
                debug!("{:x?}", data);
            }

            debug!("######## LABELS #########");
            for label in &self.pdb.labels {
                debug!("{:x?}", label);
            }

            debug!("### DATA IN FUNCTION ###");
            for function in self.pdb.functions.iter().filter(|f| f.data.len() > 0) {
                debug!(
                    "{:?} {:x?} {:x?}",
                    function.name, function.offset, function.size
                );
                for data in &function.data {
                    debug!("\t{:x?}", data);
                }
            }

            let holes = self.detect_holes();
            debug!("######## HOLES #########");
            let mut unknown_bytes = 0;
            for hole in holes {
                debug!("{:x?}", hole);
                unknown_bytes += hole.size;
            }

            debug!("####### COUNT ########");
            debug!("Functions: {}", self.pdb.functions.len());
            debug!("Thunks: {}", self.pdb.thunks.len());
            debug!("Data: {}", self.pdb.data.len());
            debug!("Labels: {}", self.pdb.labels.len());

            debug!("##### STATISTICS ######");
            debug!(
                "Identified bytes {:.2}/{:.2} ({:.2}%)",
                (self.bytes.len() as u64 - unknown_bytes),
                self.bytes.len(),
                100.0 * (self.bytes.len() as u64 - unknown_bytes) as f64 / self.bytes.len() as f64
            );
            debug!("Tail: 0x{:x}", self.bytes.len())
        }

        fn detect_end_of_section(&mut self) {
            // Get current section (vector) size
            let mut section_size = self.bytes.len();

            // Check whole byte vector but start from the end
            for byte in self.bytes.iter().rev() {
                // Guard: Only if this byte currently does not have any purpose
                if byte.is_code() || byte.is_data() {
                    break;
                }

                // Check if byte is 0x0 and reduce vector size
                if byte.value == 0x0 {
                    section_size -= 1;
                }
            }

            // Remove the empty tail
            self.bytes.truncate(section_size);
        }

        fn detect_alignment_bytes(&mut self) {
            // Check whole byte vector for known alignment bytes
            for byte in &mut self.bytes {
                // Guard: Only if this byte currently does not have any purpose
                if byte.is_code() || byte.is_data() {
                    continue;
                }

                // Check if byte is 0xCC (int3)
                if byte.value == 0xCC {
                    byte.set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
                }
            }

            // Find holes and check of the holes are multi-byte nops
            let holes = self.detect_holes();

            for hole in holes {
                // Get buffer of hole and disassemble it
                let hole_buffer = self.bytes[hole.start as usize..hole.end as usize]
                    .iter()
                    .map(|b| b.value)
                    .collect();
                let instructions = match disassembler::disassemble(
                    hole_buffer,
                    &self.pdb.architecture,
                    disassembler::DISASSEMBLER::CAPSTONE,
                ) {
                    Ok(instructions) => instructions,
                    Err(e) => {
                        error!("{}", e);
                        process::exit(1);
                    }
                };

                for instruction in instructions {
                    if instruction.is_alignment() {
                        for offset in 0..instruction.length {
                            self.bytes[(hole.start + instruction.offset + offset) as usize]
                                .set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
                        }
                    }
                }
            }
        }

        fn detect_holes(&self) -> Vec<groundtruth::Hole> {
            let mut holes = Vec::new();
            let mut hole_size = 0;

            for (offset, byte) in self.bytes.iter().enumerate() {
                // Check if this byte has currently no flags at all
                if byte.get_flags().len() == 0 {
                    hole_size += 1;
                } else {
                    if hole_size > 0 {
                        holes.push(groundtruth::Hole {
                            start: (offset - hole_size) as u64,
                            end: (offset - 1) as u64,
                            size: hole_size as u64,
                        });
                    }
                    hole_size = 0;
                }
            }

            // If the loop exited while detecting a new hole, that means a hole which shared its end with the buffer itself it will be lost. Recover it manually.
            if hole_size > 0 {
                holes.push(groundtruth::Hole {
                    start: (self.bytes.len() - 1 - hole_size) as u64,
                    end: (self.bytes.len() - 1) as u64,
                    size: hole_size as u64,
                });
            }

            holes
        }
    }
}

pub mod elf {
    use log::{debug, error, info, warn};
    use std::path;
    use std::process;

    use crate::disassembler;
    use crate::dumper;
    use crate::elf;
    use crate::groundtruth;
    use crate::parser;

    pub struct ELF {
        pub architecture: groundtruth::ARCHITECTURE,
        pub file_name: String,
        pub dwarf: groundtruth::DWARF,
        pub sections: Vec<groundtruth::Section>,
        pub bytes: Vec<groundtruth::Byte>,
        pub instructions: Vec<groundtruth::Instruction>,
    }

    impl ELF {
        pub fn new(path_to_yaml: &str, path_to_elf: &str) -> Self {
            // Grab filename from path
            let file_name = path::Path::new(path_to_elf)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();

            // Collect symbols from DWARF debugging information.
            let elf = match parser::yaml::elf::load_elf(path_to_yaml) {
                Ok(elf) => elf,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Retrieve architecture.
            let architecture = match elf::get_architecture(path_to_elf) {
                Ok(architecture) => architecture,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Collect sections.
            let sections = match elf::parse_sections(path_to_elf) {
                Ok(sections) => sections,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            // Create raw byte vector from binary.
            let bytes = match elf::read_elf(path_to_elf) {
                Ok(byte_vector) => byte_vector,
                Err(e) => {
                    error!("{}", e);
                    process::exit(1);
                }
            };

            ELF {
                file_name,
                architecture,
                dwarf: elf,
                sections,
                bytes,
                instructions: Vec::new(),
            }
        }

        pub fn process(&mut self) {
            // Grab text section
            let text_section = match self.sections.iter().find(|s| s.name == ".text") {
                Some(text_section) => text_section.clone(),
                None => {
                    error!("[-] Binary does not have a text section.");
                    process::exit(1);
                }
            };

            debug!(
                "[+] .text section identified (start: {:x}, size: {:x}, va: {:x}).",
                text_section.raw_data_offset, text_section.raw_data_size, text_section.va
            );

            // Pre-process functions
            self.preprocess_functions();

            // Set byte flags (code/data is already known)
            self.set_byte_flags();

            // Disassemble code bytes (functions)
            self.disassemble();

            // Trim byte vector (we only need the data of text section) that means cut before raw
            // data start and after raw data end
            self.trim_byte_vector(
                text_section.raw_data_offset,
                text_section.raw_data_offset + text_section.raw_data_size,
            );

            self.rebase_byte_vector(text_section.va);

            // Detect alignment/filler bytes
            self.detect_alignment_bytes();

            // Detect end of section
            self.detect_end_of_section();

            // Create debug print
            self.print();

            // Create final mapping
            dumper::plain::dump_elf(&self);
            dumper::yaml::dump_elf(&self);
        }

        fn disassemble(&mut self) {
            for function in &mut self.dwarf.functions {
                let mut function_buffer = Vec::new();

                for offset in 0..function.size {
                    // Guard: TODO
                    if (function.offset + offset) as usize >= self.bytes.len() {
                        warn!(
                            "[-] Function {} (allegedly) ends outside of the text section.",
                            function.name
                        );
                        return;
                    }

                    // Guard: Byte already flagged as data
                    if self.bytes[(function.offset + offset) as usize].is_data() {
                        continue;
                    }

                    // Set specific flags
                    self.bytes[(function.offset + offset) as usize].set_flags(vec![
                        groundtruth::FLAG::CODE,
                        groundtruth::FLAG::READABLE,
                        groundtruth::FLAG::EXECUTABLE,
                    ]);

                    // Add byte to function buffer
                    function_buffer.push(self.bytes[(function.offset + offset) as usize].value);
                }

                // Set function start and end
                self.bytes[function.offset as usize]
                    .set_flags(vec![groundtruth::FLAG::FUNCTION_START]);
                self.bytes[(function.offset + function.size - 1) as usize]
                    .set_flags(vec![groundtruth::FLAG::FUNCTION_END]);

                // Disassemble function bytes
                let instructions = match disassembler::disassemble(
                    function_buffer,
                    &self.dwarf.architecture,
                    disassembler::DISASSEMBLER::CAPSTONE,
                ) {
                    Ok(instructions) => instructions,
                    Err(e) => {
                        error!("{}", e);
                        process::exit(1);
                    }
                };
                // Set instruction start and end, copy instruction flags
                for instruction in instructions {
                    self.bytes[(function.offset + instruction.offset) as usize]
                        .set_flags(vec![groundtruth::FLAG::INSTRUCTION_START]);

                    // Instruction End Example: Start 0x0, Size 0x8 => Instruction: 0x0-0x8 therefore the 8th byte (the last byte) is 0x7
                    self.bytes
                        [(function.offset + instruction.offset + instruction.length - 1) as usize]
                        .set_flags(vec![groundtruth::FLAG::INSTRUCTION_END]);

                    // TODO: Set instruction flags for not only the first byte of instruction
                    self.bytes[(function.offset + instruction.offset) as usize]
                        .set_flags(instruction.get_flags());

                    // Append to instructions vector
                    self.instructions.push(instruction);
                }
            }
        }

        fn preprocess_functions(&mut self) {
            self.dwarf.functions.retain(|ref f| f.size > 0)
        }

        fn set_byte_flags(&mut self) {
            for function in &self.dwarf.functions {
                // Set data flags
                // Attention: we have to use the child data of a function and not from the normal
                // data collection because ONLY the child data has a up-to-date size value.
                for data in &function.data {
                    for i in 0..data.size {
                        self.bytes[(data.offset + i) as usize]
                            .set_flags(vec![groundtruth::FLAG::DATA]);
                    }
                }

                // Set data and code flags
                for i in 0..function.size {
                    // Guard: Check if function size is greater than section size.
                    if (function.offset + i) as usize >= self.bytes.len() {
                        warn!(
                            "[-] Function {} (allegedly) ends outside of the text section.",
                            function.name
                        );
                        break;
                    }

                    // Guard: Check if byte is already data (because there is data within the function)
                    if self.bytes[(function.offset + i) as usize].is_data() {
                        continue;
                    }

                    self.bytes[(function.offset + i) as usize]
                        .set_flags(vec![groundtruth::FLAG::CODE]);
                }
            }
        }

        fn trim_byte_vector(&mut self, start: u64, end: u64) {
            // Cut current start to new start and new end to current end
            self.bytes.drain(..start as usize);
            self.bytes.drain((end - start) as usize..);
        }

        fn rebase_byte_vector(&mut self, base: u64) {
            // Reset offsets
            for (offset, byte) in self.bytes.iter_mut().enumerate() {
                byte.offset = offset as u64 + base;
            }
        }

        fn print(&self) {
            debug!("######## META ###########");
            debug!("{:?}", self.dwarf.architecture);

            debug!("######## SECTIONS #########");
            for section in &self.sections {
                debug!("{:x?}", section);
            }

            debug!("######## FUNCTIONS #########");
            for function in &self.dwarf.functions {
                debug!("{:x?}", function);
            }

            debug!("### DATA IN FUNCTION ###");
            for function in self.dwarf.functions.iter().filter(|f| f.data.len() > 0) {
                debug!(
                    "{:?} {:x?} {:x?}",
                    function.name, function.offset, function.size
                );
                for data in &function.data {
                    debug!("\t{:x?}", data);
                }
            }

            let holes = self.detect_holes();
            debug!("######## HOLES #########");
            let mut unknown_bytes = 0;
            for hole in holes {
                debug!("{:x?}", hole);
                unknown_bytes += hole.size;
            }

            debug!("####### COUNT ########");
            debug!("Functions: {}", self.dwarf.functions.len());

            debug!("##### STATISTICS ######");
            debug!(
                "Identified bytes {:.2}/{:.2} ({:.2}%)",
                (self.bytes.len() as u64 - unknown_bytes),
                self.bytes.len(),
                100.0 * (self.bytes.len() as u64 - unknown_bytes) as f64 / self.bytes.len() as f64
            );
            debug!("Tail: 0x{:x}", self.bytes.len())
        }

        fn detect_end_of_section(&mut self) {
            // Get current section (vector) size
            let mut section_size = self.bytes.len();

            // Check whole byte vector but start from the end
            for byte in self.bytes.iter().rev() {
                // Guard: Only if this byte currently does not have any purpose
                if byte.is_code() || byte.is_data() {
                    break;
                }

                // Check if byte is 0x0 and reduce vector size
                if byte.value == 0x0 {
                    section_size -= 1;
                }
            }

            // Remove the empty tail
            self.bytes.truncate(section_size);
        }

        fn detect_alignment_bytes(&mut self) {
            // Check whole byte vector for known alignment bytes
            for byte in &mut self.bytes {
                // Guard: Only if this byte currently does not have any purpose
                if byte.is_code() || byte.is_data() {
                    continue;
                }

                // Check if byte is 0xCC (int3)
                if byte.value == 0xCC {
                    byte.set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
                }
            }

            // Find holes and check of the holes are multi-byte nops
            let holes = self.detect_holes();

            for hole in holes {
                // Get buffer of hole and disassemble it
                let hole_buffer = self.bytes[hole.start as usize..hole.end as usize]
                    .iter()
                    .map(|b| b.value)
                    .collect();
                let instructions = match disassembler::disassemble(
                    hole_buffer,
                    &self.dwarf.architecture,
                    disassembler::DISASSEMBLER::CAPSTONE,
                ) {
                    Ok(instructions) => instructions,
                    Err(e) => {
                        error!("{}", e);
                        process::exit(1);
                    }
                };

                for instruction in instructions {
                    if instruction.is_alignment() {
                        for offset in 0..instruction.length {
                            self.bytes[(hole.start + instruction.offset + offset) as usize]
                                .set_flags(vec![groundtruth::FLAG::INSTRUCTION_ALIGNMENT]);
                        }
                    }
                }
            }
        }

        fn detect_holes(&self) -> Vec<groundtruth::Hole> {
            let mut holes = Vec::new();
            let mut hole_size = 0;

            for (offset, byte) in self.bytes.iter().enumerate() {
                // Check if this byte has currently no flags at all
                if byte.get_flags().len() == 0 {
                    hole_size += 1;
                } else {
                    if hole_size > 0 {
                        holes.push(groundtruth::Hole {
                            start: (offset - hole_size) as u64,
                            end: (offset - 1) as u64,
                            size: hole_size as u64,
                        });
                    }
                    hole_size = 0;
                }
            }

            // If the loop exited while detecting a new hole, that means a hole which shared its end with the buffer itself it will be lost. Recover it manually.
            if hole_size > 0 {
                holes.push(groundtruth::Hole {
                    start: (self.bytes.len() - 1 - hole_size) as u64,
                    end: (self.bytes.len() - 1) as u64,
                    size: hole_size as u64,
                });
            }

            holes
        }
    }
}
