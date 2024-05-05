use std::{
    env,
    fs::{self, File},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use color_eyre::Result;

use gopper::{gadgets, got_to_symbol, GadgetFormatter};

// use gopper::get_all_gadgets;
use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    /// ELF to read gadgets from
    #[arg(short, long)]
    file: PathBuf,
    /// Output file for discovered gadgets
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long, env)]
    /// Do not show colors even if supported by output
    no_color: bool,
    #[arg(long, env)]
    /// Show colors even if not supported by output
    force_color: bool,
}
pub trait Output: std::io::Write + IsTerminal {}
impl<Stream: std::io::Write + IsTerminal> Output for Stream {}
fn main() -> Result<()> {
    let args = Args::parse();
    let file_buffer = fs::read(&args.file)?;
    let mut output = match args.output {
        Some(path) => Box::new(File::create(path)?) as Box<dyn Output>,
        None => Box::new(io::stdout()) as Box<dyn Output>,
    };
    let colorize = match (args.no_color, args.force_color) {
        (true, true) => false,
        (true, false) => false,
        (false, true) => true,
        (false, false) => output.is_terminal(),
    };
    let mut formatter = GadgetFormatter::new(&file_buffer);
    formatter.colorize(colorize);
    formatter.symbols(got_to_symbol(&file_buffer));
    for gadget in gadgets(&file_buffer)? {
        formatter.format(&gadget, &mut output);
        write!(&mut output, "\n")?;
    }
    Ok(())
}
