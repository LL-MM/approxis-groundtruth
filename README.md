## Binary2Groundtruth

Generates a ground truth map of a binary with the help of debug symbols.

### Features

- Cross-platform
- Supports PE and ELF binaries.
- Generates detailed ground truth mappings.

### Goal

Provide a cross-platform utility to generate ground truth mappings from binaries for further analysis and evaluation. Motivated by of Dennis Andriesse et al. on "An In-Depth Analysis of Disassembly on Full-Scale x86/x64 Binaries"(https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/andriesse).

### Usage

#### Pre-process binaries

Currently the PDB/ELF files do **not** get automatically parsed with the help of llvm-pdb2yaml/llvm-obj2yaml.

##### Convert PDB to YAML dump

> $ llvm-pdbutil-<version> pdb2yaml -all <path_to_pdb>  > dump

##### Convert ELF to YAML dump
> $ obj2yaml-<version> <path_to_elf>  > dump

#### Create ground truth map from dump

> $ git clone https://github.com/LL-MM/approxis-groundtruth && cd approxis-groundtruth  
> $ cargo build --release  
> $ cargo run --release <path_to_yaml_dump> <path_to_binary>

Creates a debug report with statistics and two dumps named <binary_name>.yaml and <binary_name>.txt.

### Outputs

#### YAML

If specified the tool dumps the generated mappings (as well as all functions, data, labels) in a human-friendly YAML file.

#### RAW

If specified the tool creates a mapping of every single byte within the binary and its corresponding
flags.

- C: Code
  - I: Instruction Start
  - F: Function Start
  - R: Return
  - 3: Interrupt
- N: Alignment (mostly NOPs)
- D: Data
- U: Unknown

### Dependencies

- [llvm-pdbutil](https://github.com/llvm-mirror/llvm/tree/master/tools/llvm-pdbutil): LLVMs PDB dumper
- [Capstone](https://github.com/aquynh/capstone): Capstone disassembly/disassembler framework.

### Acknowledgments

- [Microsoft: PDB Repository](https://github.com/Microsoft/microsoft-pdb)
- [The PDB File Format - LLVM 8 Documentation](https://llvm.org/docs/PDB/index.html)

### Authors

- Marcel Meuter ([@x1tan](https://twitter.com/x1tan))
- Lorenz Liebler ([@kn000x](https://twitter.com/kn000x))

### License

Binary2Groundtruth is licensed under the MIT license.
