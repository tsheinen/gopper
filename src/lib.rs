use color_eyre::eyre::bail;
use color_eyre::Result;
use goblin::elf::Elf;
use goblin::elf64::section_header::SHF_EXECINSTR;
use goblin::Object;
use iced_x86::{
    Decoder, DecoderOptions, Instruction, OpKind, FlowControl, IntelFormatter, Formatter,
};
use std::fmt::Display;
use std::ops::Range;

/// A call into the GOT
#[derive(Debug, Clone)]
pub struct Terminal {
    pub faddr: usize,
    pub vaddr: usize,
    pub target: usize,
}

#[derive(Debug, Clone)]
pub struct Gadget {
    pub faddr: usize,
    pub vaddr: usize,
    pub terminal: Terminal,
}

impl Gadget {
    pub fn decode(&self, file: &[u8]) -> String {
        let mut output = format!("{:X}: ", self.vaddr);
        let mut decoder = Decoder::new(64, file, DecoderOptions::NONE);
        let mut instr = Instruction::new();
        let mut formatter = IntelFormatter::new();
        decoder.set_ip(self.vaddr as u64);
        decoder.set_position(self.faddr).expect("tried to decode address outside of file");
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

struct GadgetTerminalIterator<'a>
{
    faddr: usize,
    vaddr: usize,
    decoder: Decoder<'a>,
    sections: Box<dyn Iterator<Item=(usize,usize)>>,
    // TODO optimize: this prob doesn't need to heap allocate
    target_ranges: [Range<usize>; 1],
}

impl<'a> GadgetTerminalIterator<'a>
{
    pub fn new(buffer: &'a [u8], elf: &Elf<'a>) -> Self {
        let plt_sec = extract_section(&elf, ".plt.sec");
        let decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
        let sections_iter = Box::new(extract_executable_sections(&elf).into_iter().map(|(vaddr, faddr, size)| {
            (vaddr..vaddr+size).zip(faddr..faddr+size)
        }).flatten());
        // let (first_faddr, first_vaddr) = sections_iter.next().expect("executable addresses iter did not yield at least 1 address");
        Self {
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

impl<'a> Iterator for GadgetTerminalIterator<'a>
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


pub fn get_all_gadgets(buffer: &[u8]) -> Result<Vec<Gadget>> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            println!("elf: {:X?}", extract_section(&elf, ".got.plt"));
            println!("elf: {:X?}", extract_section(&elf, ".plt.sec"));
            let mut gadgets = Vec::new();
            for terminal in GadgetTerminalIterator::new(&buffer, &elf) {
                find_gadgets(&buffer, &elf, terminal, &mut gadgets);
            }
            return Ok(gadgets);
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
        _ => bail!("does not support non ELF objects")
    }
}


