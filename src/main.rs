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

// fn extract_plt_functions(buffer: &[u8], elf: &Elf) -> HashMap<usize, String> {
//     let got_map = extract_got_functions(buffer, elf);
//     for (a,b) in got_map.iter() {
//         println!("{:X}: {}", a,b);
//     }
//     // println!("got map {:X?}", got_map);
//     let decoder = InstDecoder::minimal();
//     let (section_vaddr, start, size) = extract_section(elf, ".plt.sec");
//     println!("start {:x} vaddr {:x}", start, section_vaddr);
//     let section_buf = &buffer[start..start + size];
//     let section_buf_iter = (0..size)
//         .into_iter()
//         .map(|i| (section_vaddr + i, &section_buf[i..]));
//     let mut plt_map = HashMap::new();
//     for (vaddr, slice) in section_buf_iter {
//         if let Ok(instr) = decoder.decode_slice(slice) {
//             if instr.opcode() == Opcode::ENDBR64 {
//                 println!("instr: {}", instr);
//                 let target = decoder
//                     .decode_slice(&slice[(instr.len().to_const() as usize)..])
//                     .unwrap();
//                 println!("{:?}", target);
//                 match target.operand(0) {
//                     Operand::RegDisp(_, disp) => {
//                         let phys_addr = add(start + vaddr - section_vaddr, instr.len().to_const() as i32 + disp + target.len().to_const() as i32);
//                         let value = u64::from_be_bytes(buffer[phys_addr..phys_addr+8].try_into().unwrap());
//                         println!("{:X?}", &buffer[phys_addr..phys_addr+64]);
//                         println!("deref {:x} to {:x}", add(vaddr, instr.len().to_const() as i32 + disp + target.len().to_const() as i32), value);

//                         plt_map.insert(
//                             vaddr,
//                             got_map.get(&add(vaddr, instr.len().to_const() as i32 + disp + target.len().to_const() as i32)).unwrap().to_string()
//                         );
//                     }
//                     _ => {}
//                 }
//                 // println!("instr: {}", );
//             }
//         }
//     }
//     plt_map
// }

fn find_terminals(buffer: &[u8], elf: &Elf) -> Vec<Terminal> {
    // TODO prob need to expand this to multiple PLT sections but its .plt.sec on test libc
    let (plt_vaddr, _, plt_size) = extract_section(&elf, ".plt.sec");
    let mut terminals = Vec::new();
    for (vaddr, faddr, size) in extract_executable_sections(&elf) {
        println!("start: {:X} end {:X}", vaddr, vaddr+size);
        let section_buf = &buffer[faddr..faddr + size];
        let mut decoder = Decoder::new(64, section_buf, DecoderOptions::NONE);

        for (vaddr, offset) in (0..size).map(|i| (vaddr + i, i)) {
            let mut instr = Instruction::new();
            decoder.set_ip(vaddr as u64);
            decoder.set_position(offset);
            decoder.decode_out(&mut instr);
            // println!("{:X}: {} {:X}", instr.ip(), instr, instr.near_branch64());
            if !instr.is_invalid() {
                if instr.op0_kind() == OpKind::NearBranch64 {
                    let target = instr.near_branch64() as usize;
                    if target >= plt_vaddr && target <= plt_vaddr + plt_size {
                        terminals.push(Terminal {
                            faddr: faddr + offset,
                            vaddr,
                            target,
                        });
                    }
                }
            }
        }
    }
    terminals
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
                    for terminal in find_terminals(&buffer, &elf) {
                        find_gadgets(&buffer, &elf, terminal, &mut gadgets);
                        // println!("{}", terminal);
                    }
                    for gadget in gadgets {
                        println!("{}", gadget.decode(&buffer));
                    }
                    // extract_plt_functions(&buffer, &elf);
                    // let decoder = InstDecoder::minimal();
                    // for (vaddr, start, size) in extract_executable_sections(&elf) {
                    //     let section_buf = &buffer[start..start+size];
                    //     let section_buf_iter = (0..size).into_iter().map(|i| (vaddr+i, &section_buf[i..]));
                    //     for (vaddr, slice) in section_buf_iter {
                    //         if let Ok(instr) = decoder.decode_slice(slice) {

                    //     }
                    // }
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
