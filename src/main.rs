use color_eyre::Result;
use goblin::elf::Elf;
use goblin::elf64::section_header::SHF_EXECINSTR;
use goblin::{error, Object};
use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, Instruction, InstructionInfoFactory, OpKind,
    RflagsBits, FlowControl, IntelFormatter, Formatter,
};
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::fs;
use std::iter::{Flatten, Map};
use std::ops::Range;
use std::path::Path;
use yaxpeax_arch::LengthedInstruction;
use yaxpeax_x86::amd64::{InstDecoder, Opcode, Operand};

/// A call into the GOT
#[derive(Debug, Clone)]
struct Terminal {
    faddr: usize,
    vaddr: usize,
    target: usize,
}

#[derive(Debug, Clone)]
struct Gadget {
    faddr: usize,
    vaddr: usize,
    terminal: Terminal,
}

impl Gadget {
    fn decode(&self, file: &[u8]) -> String {
        let mut output = format!("{:X}: ", self.vaddr);
        let mut decoder = Decoder::new(64, file, DecoderOptions::NONE);
        let mut instr = Instruction::new();
        let mut formatter = IntelFormatter::new();
        decoder.set_ip(self.vaddr as u64);
        decoder.set_position(self.faddr);
        while decoder.can_decode() && decoder.position() <= self.terminal.faddr {
            decoder.decode_out(&mut instr);
            formatter.format(&instr, &mut output);
            output += "; "
        }
        output
        
    }
}


impl Display for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:X}: call {:X}", self.vaddr, self.target)
    }
}

fn extract_section(elf: &Elf, section: &str) -> (usize, usize, usize) {
    elf.section_headers
        .iter()
        .map(|section| {
            (
                elf.shdr_strtab.get_at(section.sh_name).unwrap_or(""),
                section.sh_addr,
                section.sh_offset,
                section.sh_size,
            )
        })
        .filter(|(name, _, _, _)| *name == section)
        .map(|(_, a, b, c)| (a as usize, b as usize, c as usize))
        .next()
        .expect("couldnt find section by name")

    // println!("{:?} {:X?} {:X?}", name, offset, size);
    // (offset..(offset + size)).filter(|x| x % 8 == 0).collect()
}

fn extract_executable_sections(elf: &Elf) -> Vec<(usize, usize, usize)> {
    elf.section_headers
        .iter()
        .filter(|section| section.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR)
        .map(|section| {
            (
                section.sh_addr as usize,
                section.sh_offset as usize,
                section.sh_size as usize,
            )
        })
        .collect::<Vec<_>>()
}

fn add(u: usize, i: i32) -> usize {
    if i.is_negative() {
        u.wrapping_sub(i.wrapping_abs() as u32 as usize)
    } else {
        u.wrapping_add(i as usize)
    }
}

// fn fmt_instruction(instr: &Instruction, vaddr: usize) -> String {
//     match (instr.opcode(), instr.operand(0)) {
//         (Opcode::CALL, Operand::ImmediateI32(rel)) => {
//             // rebase
//             format!("{:x}: call 0x{:x}", vaddr, add(vaddr, rel + 5))
//         }
//         _ => {
//             format!("{:x}: {}", vaddr, instr)
//         }
//     }
//     // if instr.opcode() == Opcode::CALL && instr.operand(0) == Operand::Imm {

//     // }
//     // if slice.len() > 8 {
//     // format!("{:x}: {} {:X?}", vaddr, instr, instr)
//     // }
// }

fn extract_got_functions(buffer: &[u8], elf: &Elf) -> HashMap<usize, String> {
    elf.syms
        .iter()
        .filter(|sym| sym.is_function())
        // .filter(|sym| sym.st_value == 0x000a9c90)
        .map(|sym| {
            (
                sym.st_value as usize,
                elf.strtab.get_at(sym.st_name).unwrap_or("").to_string(),
            )
        })
        .collect()
    // println!("{:?}", lol);

    // HashMap::new()
}


struct GadgetTerminalIterator<'a, 'b>
{
    buffer: &'a [u8],
    elf: &'b Elf<'a>,
    faddr: usize,
    vaddr: usize,
    decoder: Decoder<'a>,
    sections: Box<dyn Iterator<Item=(usize,usize)>>,
    // TODO optimize: this prob doesn't need to heap allocate
    target_ranges: [Range<usize>; 1],
}

impl<'a, 'b> GadgetTerminalIterator<'a, 'b>
{
    pub fn new(buffer: &'a [u8], elf: &'b Elf<'a>) -> Self {
        let plt_sec = extract_section(&elf, ".plt.sec");
        let mut decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
        let mut sections_iter = Box::new(extract_executable_sections(&elf).into_iter().map(|(vaddr, faddr, size)| {
            (vaddr..vaddr+size).zip(faddr..faddr+size)
        }).flatten());
        // let (first_faddr, first_vaddr) = sections_iter.next().expect("executable addresses iter did not yield at least 1 address");
        Self {
            buffer: buffer,
            elf: elf,
            faddr: 0,
            vaddr: 0,
            decoder: decoder,
            sections: sections_iter,
            target_ranges: [
                plt_sec.0..(plt_sec.0+plt_sec.2)
            ]

        }
    }
}

impl<'a, 'b> Iterator for GadgetTerminalIterator<'a, 'b>
{
    type Item = Terminal;

    fn next(&mut self) -> Option<Self::Item> {
        let mut instr = Instruction::new();
        loop {
            (self.vaddr, self.faddr) = self.sections.next()?;
            self.decoder.set_ip(self.vaddr as u64);
            self.decoder.set_position(self.faddr).expect("tried to decode address outside of file");
            self.decoder.decode_out(&mut instr);
            if !instr.is_invalid() && instr.op0_kind() == OpKind::NearBranch64 {
                let target = instr.near_branch64() as usize;
                if self.target_ranges.iter().any(|range| range.contains(&target)) {
                    return Some(Terminal {
                        vaddr: self.vaddr,
                        faddr: self.faddr,
                        target
                    })
                }
            }
        }
    }
}

fn find_gadgets(buffer: &[u8], elf: &Elf, terminal: Terminal, gadgets: &mut Vec<Gadget>) {
    // let mut gadgets = Vec::new();
    let mut decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
    let mut instr = Instruction::new();
    'outer: for prefix in 1..256 {
        let mut position = terminal.faddr - prefix as usize;
        decoder.set_ip(terminal.vaddr as u64 - prefix);
        let _ = decoder.set_position(position);
        while position < terminal.faddr {
            
            
            decoder.decode_out(&mut instr);
            position += instr.len();

            if instr.flow_control() != FlowControl::Next || instr.is_invalid(){
                continue 'outer;
            }
        }
        if position == terminal.faddr {
            gadgets.push(Gadget {
                faddr: terminal.faddr - prefix as usize,
                vaddr: terminal.vaddr - prefix as usize,
                terminal: terminal.clone()
            })
        }
    }
}

fn main() -> Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let buffer = fs::read(path)?;
            match Object::parse(&buffer)? {
                Object::Elf(elf) => {
                    println!("elf: {:X?}", extract_section(&elf, ".got.plt"));
                    println!("elf: {:X?}", extract_section(&elf, ".plt.sec"));
                    let mut gadgets = Vec::new();
                    for terminal in GadgetTerminalIterator::new(&buffer, &elf) {
                        find_gadgets(&buffer, &elf, terminal, &mut gadgets);
                        // println!("{}", terminal);
                    }
                    for gadget in gadgets {
                        println!("{}", gadget.decode(&buffer));
                    }
                }
                // Object::PE(pe) => {
                //     println!("pe: {:#?}", &pe);
                // },
                // Object::COFF(coff) => {
                //     println!("coff: {:#?}", &coff);
                // },
                // Object::Mach(mach) => {
                //     println!("mach: {:#?}", &mach);
                // },
                // Object::Archive(archive) => {
                //     println!("archive: {:#?}", &archive);
                // },
                // Object::Unknown(magic) => { println!("unknown magic: {:#x}", magic) },
                _ => {}
            }
        }
    }
    Ok(())
}
