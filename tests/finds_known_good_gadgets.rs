use std::collections::HashMap;

use color_eyre::{eyre::eyre, Result};
use gopper::gadgets;

#[test]
fn find_known_good_gadgets_on_libc_2_35() -> Result<()> {
    let BYTES = include_bytes!("./bins/libc6_2.35-0ubuntu3.1_amd64.so");
    let gadgets = gadgets(BYTES)?
        .into_iter()
        .map(|g| (g.vaddr, g))
        .collect::<HashMap<_, _>>();

    assert_eq!(
        gadgets
            .get(&0x13076C)
            .ok_or(eyre!(
                "couldn't find pop rbx; pop rbp; pop r12; pop r13; pop r14; gadget"
            ))?
            .decode(BYTES),
        "13076C: pop rbx; pop rbp; pop r12; pop r13; pop r14; jmp 0000000000028580h; "
    );
    Ok(())
}
