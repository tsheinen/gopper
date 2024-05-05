use std::collections::HashMap;

use color_eyre::{eyre::eyre, Result};
use gopper::{gadgets, got_to_symbol, GadgetFormatter};

const BYTES: &[u8; 6616616] = include_bytes!("./bins/libc6_2.35-0ubuntu3.1_amd64.so");

#[test]
fn find_known_good_gadgets_on_libc_2_35() -> Result<()> {
    let gadgets = gadgets(BYTES)?
        .into_iter()
        .map(|g| (g.vaddr, g))
        .collect::<HashMap<_, _>>();
    let mut formatter = GadgetFormatter::new(BYTES);
    assert_eq!(
        formatter.format_str(gadgets.get(&0x13076C).ok_or(eyre!(
            "couldn't find pop rbx; pop rbp; pop r12; pop r13; pop r14; gadget"
        ))?),
        "13076C: pop rbx; pop rbp; pop r12; pop r13; pop r14; jmp 0000000000028580h; "
    );
    Ok(())
}

#[test]
fn find_known_good_gadgets_on_libc_2_35_with_symbols() -> Result<()> {
    let gadgets = gadgets(BYTES)?
        .into_iter()
        .map(|g| (g.vaddr, g))
        .collect::<HashMap<_, _>>();
    let mut formatter = GadgetFormatter::new(BYTES);
    formatter.symbols(got_to_symbol(BYTES));
    assert_eq!(
        formatter.format_str(gadgets.get(&0x13076C).ok_or(eyre!(
            "couldn't find pop rbx; pop rbp; pop r12; pop r13; pop r14; gadget"
        ))?),
        "13076C: pop rbx; pop rbp; pop r12; pop r13; pop r14; jmp strcasecmp (28580); "
    );
    Ok(())
}
