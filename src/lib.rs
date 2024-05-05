use color_eyre::eyre::bail;
use color_eyre::Result;
use goblin::elf::reloc::R_X86_64_GOTOFF64;
use goblin::elf::sym::{STT_FUNC, STT_GNU_IFUNC};
use goblin::elf::Elf;
use goblin::elf64::section_header::SHF_EXECINSTR;
use goblin::Object;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, FormatterOutput, FormatterTextKind,
    Instruction, IntelFormatter, Mnemonic, OpKind, SymbolResolver, SymbolResult,
};
use owo_colors::{AnsiColors, OwoColorize, Stream::Stdout};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{IsTerminal, Write};
use std::ops::Range;

/// A call into the GOT
#[derive(Debug, Clone)]
pub struct Terminal {
    pub faddr: usize,
    pub vaddr: usize,
    pub target: usize,
}

// Custom formatter output that stores the output in a vector.
struct HighlightedFormatter {
    buf: String,
    colorize: bool,
}

impl HighlightedFormatter {
    pub fn new(colorize: bool) -> Self {
        Self {
            buf: String::new(),
            colorize,
        }
    }
}

impl Display for HighlightedFormatter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.buf)?;
        Ok(())
    }
}

impl FormatterOutput for HighlightedFormatter {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        use std::fmt::Write;
        if self.colorize {
            write!(
                &mut self.buf,
                "{}",
                text.color(match kind {
                    FormatterTextKind::Number => AnsiColors::Green,
                    FormatterTextKind::Function
                    | FormatterTextKind::FunctionAddress
                    | FormatterTextKind::LabelAddress
                    | FormatterTextKind::Label => AnsiColors::BrightBlue,
                    // FormatterTextKind::Directive | FormatterTextKind::Keyword => AnsiColors::BrightYellow,
                    FormatterTextKind::Prefix
                    | FormatterTextKind::Mnemonic
                    | FormatterTextKind::Directive
                    | FormatterTextKind::Keyword => AnsiColors::BrightYellow,
                    FormatterTextKind::Register => AnsiColors::BrightRed,
                    _ => AnsiColors::White,
                })
            )
            .expect("write to string should never fail")
        } else {
            write!(&mut self.buf, "{}", text).expect("write to string should never fail")
        }
    }
}

struct GotSymbolResolve {
    symbols: HashMap<usize, String>,
    colorize: bool,
}

impl GotSymbolResolve {
    pub fn new(symbols: HashMap<usize, String>, colorize: bool) -> Self {
        Self { symbols, colorize }
    }
}

impl SymbolResolver for GotSymbolResolve {
    fn symbol(
        &mut self,
        instruction: &Instruction,
        operand: u32,
        instruction_operand: Option<u32>,
        address: u64,
        address_size: u32,
    ) -> Option<iced_x86::SymbolResult<'_>> {
        if let Some(symbol_string) = self.symbols.get(&(address as usize)) {
            Some(SymbolResult::with_string(
                address,
                format!(
                    "{} ({})",
                    symbol_string,
                    if self.colorize {
                        format!("{:X}", address).bright_green().to_string()
                    } else {
                        format!("{:X}", address)
                    }
                ),
            ))
        } else {
            None
        }
    }
}

pub struct GadgetFormatter<'a> {
    buffer: &'a [u8],
    colorize: bool,
    symbols: Option<HashMap<usize, String>>,
}

impl<'a> GadgetFormatter<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            colorize: false,
            symbols: None,
        }
    }

    pub fn symbols(&mut self, symbols: HashMap<usize, String>) -> &mut Self {
        self.symbols = Some(symbols);
        self
    }

    pub fn colorize(&mut self, colorize: bool) -> &mut Self {
        self.colorize = colorize;
        self
    }

    pub fn format_str(&self, gadget: &Gadget) -> String {
        let mut out = Vec::new();
        self.format(gadget, &mut out);
        String::from_utf8(out).expect("generated invalid utf 8 :(")
    }
    pub fn format<WRITE: Write>(&self, gadget: &Gadget, output: &mut WRITE) {
        let mut decoder = Decoder::new(64, &self.buffer, DecoderOptions::NONE);
        let mut instr = Instruction::new();
        let symbol_resolver = self
            .symbols
            .clone()
            .map(|s| Box::new(GotSymbolResolve::new(s, self.colorize)) as Box<dyn SymbolResolver>);
        let mut formatter = IntelFormatter::with_options(symbol_resolver, None);
        decoder.set_ip(gadget.vaddr as u64);
        decoder
            .set_position(gadget.faddr)
            .expect("tried to decode address outside of file");
        let mut highlighted_formatter = HighlightedFormatter::new(self.colorize);
        highlighted_formatter.write(&format!("{:X}: ", gadget.vaddr), FormatterTextKind::Number);
        while decoder.can_decode() && decoder.position() <= gadget.terminal.faddr {
            decoder.decode_out(&mut instr);
            formatter.format(&instr, &mut highlighted_formatter);
            highlighted_formatter.write("; ", FormatterTextKind::Text);
        }
        write!(output, "{}", highlighted_formatter);
    }
}

#[derive(Debug, Clone)]
pub struct Gadget {
    pub faddr: usize,
    pub vaddr: usize,
    pub terminal: Terminal,
}

impl Gadget {
    pub fn is_valid(&self, buffer: &[u8]) -> bool {
        // walk forward from start and see if there is a blocker before the terminal instruction
        // TODO: decoder doesn't need to be constructed every time
        let mut decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
        let mut instr = Instruction::new();
        let mut position = 0;
        decoder.set_ip(self.vaddr as u64 + position as u64);
        decoder
            .set_position(self.faddr + position)
            .expect("tried to decode address outside of file");
        while decoder.position() < self.terminal.faddr {
            decoder.decode_out(&mut instr);
            position += instr.len();
            if instr.flow_control() != FlowControl::Next || instr.is_invalid() {
                return false;
            }
        }
        return decoder.position() == self.terminal.faddr;
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

struct GadgetTerminalIterator<'a> {
    faddr: usize,
    vaddr: usize,
    decoder: Decoder<'a>,
    sections: Box<dyn Iterator<Item = (usize, usize)>>,
    // TODO optimize: this prob doesn't need to heap allocate
    target_ranges: [Range<usize>; 1],
}

impl<'a> GadgetTerminalIterator<'a> {
    pub fn new(buffer: &'a [u8], elf: &Elf<'a>) -> Self {
        let plt_sec = extract_section(&elf, ".plt.sec");
        let decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
        let sections_iter = Box::new(
            extract_executable_sections(&elf)
                .into_iter()
                .map(|(vaddr, faddr, size)| (vaddr..vaddr + size).zip(faddr..faddr + size))
                .flatten(),
        );
        Self {
            faddr: 0,
            vaddr: 0,
            decoder: decoder,
            sections: sections_iter,
            target_ranges: [plt_sec.0..(plt_sec.0 + plt_sec.2)],
        }
    }
}

impl<'a> Iterator for GadgetTerminalIterator<'a> {
    type Item = Terminal;

    fn next(&mut self) -> Option<Self::Item> {
        let mut instr = Instruction::new();
        loop {
            (self.vaddr, self.faddr) = self.sections.next()?;
            self.decoder.set_ip(self.vaddr as u64);
            self.decoder
                .set_position(self.faddr)
                .expect("tried to decode address outside of file");
            self.decoder.decode_out(&mut instr);
            if !instr.is_invalid() && instr.op0_kind() == OpKind::NearBranch64 {
                let target = instr.near_branch64() as usize;
                if self
                    .target_ranges
                    .iter()
                    .any(|range| range.contains(&target))
                {
                    return Some(Terminal {
                        vaddr: self.vaddr,
                        faddr: self.faddr,
                        target,
                    });
                }
            }
        }
    }
}

pub struct GadgetsIterator<'a> {
    iter: Box<dyn Iterator<Item = Gadget> + 'a>,
}

impl<'a> GadgetsIterator<'a> {
    pub fn new(buffer: &'a [u8], elf: &Elf<'a>) -> Self {
        // how far back should we search for valid gadgets
        const MAX_GADGET_PREFIX: usize = 256;
        Self {
            iter: Box::new(
                GadgetTerminalIterator::<'a>::new(buffer, elf)
                    .flat_map(|term| {
                        // TODO: this should short circuit?
                        // the main complexity is short circuiting properly in the case where a subset of an instruction is invalid but the full instruction is not
                        // perhaps short circuit on n (15 being the max x86 instruction length) invalid instruction
                        (1..MAX_GADGET_PREFIX).map(move |sub| Gadget {
                            faddr: term.faddr - sub,
                            vaddr: term.vaddr - sub,
                            terminal: term.clone(),
                        })
                    })
                    .filter(|g| g.is_valid(buffer)),
            ),
        }
    }
}

impl<'a> Iterator for GadgetsIterator<'a> {
    type Item = Gadget;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub fn got_to_symbol(buffer: &[u8]) -> HashMap<usize, String> {
    // println!("{:X?}", elf.pltrelocs);
    let elf = match Object::parse(&buffer).expect("not a valid object") {
        Object::Elf(elf) => elf,
        _ => panic!("can't pull symbols from non-elf..."),
    };
    let plt_relocs = elf
        .pltrelocs
        .iter()
        .filter(|reloc| reloc.r_type == 0x25)
        .map(|reloc| (reloc.r_offset, reloc.r_addend.expect("r_addend must exist")))
        .collect::<HashMap<_, _>>();
    // extract plt stubs
    // cross ref dynsyms with .rela.plt
    // connect plt stub to symbol?
    let sym_map: HashMap<usize, String> = elf
        .dynsyms
        .iter()
        .filter(|sym| sym.st_type() == STT_FUNC || sym.st_type() == STT_GNU_IFUNC)
        .map(|sym| {
            (
                sym.st_value as usize,
                elf.dynstrtab.get_at(sym.st_name).unwrap_or("").to_string(),
            )
        })
        .collect();

    let (section_vaddr, start, size) = extract_section(&elf, ".plt.sec");
    let mut decoder = Decoder::new(64, buffer, DecoderOptions::NONE);
    let mut position = 0;

    let mut plt_map = HashMap::new();
    let mut instr = Instruction::new();
    while decoder.position() + 0x10 < start + size {
        decoder.set_ip((section_vaddr + position) as u64);
        decoder.set_position(start + position);
        decoder.decode_out(&mut instr);
        // println!("{:?} {:X}", instr, instr.ip());
        assert_eq!(instr.mnemonic(), Mnemonic::Endbr64);
        let plt_func_start = instr.ip();
        decoder.decode_out(&mut instr);
        assert_eq!(instr.op0_kind(), OpKind::Memory);
        // println!("{:X?}", (plt_func_start, instr.memory_displacement64()));
        plt_map.insert(plt_func_start, instr.memory_displacement64());
        position += 0x10;
    }

    let mut fin_map = HashMap::new();
    for (plt_stub, got_entry) in plt_map.iter() {
        if let Some(func) = plt_relocs.get(&got_entry) {
            // println!("FUNC: {:X}", func);
            if let Some(name) = sym_map.get(&(*func as usize)) {
                fin_map.insert(*plt_stub as usize, name.to_string());
            }
        }
    }

    // println!("SYM MAP: {:?}", sym_map.get(&0xC54F0));
    // println!("MAP {:X?}\n\n", &plt_map);
    // println!("RELOCS {:X?}\n\n", &plt_relocs);
    // println!("{:X?}\n\n", &sym_map);
    // println!("{:X?}", &fin_map);
    fin_map
    //     let (section_vaddr, start, size) = extract_section(elf, ".plt.sec");
}

pub fn gadgets<'a>(buffer: &'a [u8]) -> Result<GadgetsIterator<'a>> {
    match Object::parse(&buffer)? {
        Object::Elf(elf) => {
            // got_to_symbol(buffer, &elf);
            // panic!("");
            return Ok(GadgetsIterator::new(buffer, &elf));
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
        _ => bail!("does not support non ELF objects"),
    }
}
