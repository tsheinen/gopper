

use std::{env, fs, path::Path};

use color_eyre::Result;

use gopper::{get_all_gadgets};

// use gopper::get_all_gadgets;




fn main() -> Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let buffer = fs::read(path)?;
            for gadget in get_all_gadgets(&buffer)? {
                println!("{}", gadget.decode(&buffer));
            }
        }
    }
    Ok(())
}