//! Gdb debugging helper
#![allow(unused_imports, dead_code, unreachable_code)]
use nupe::Pe;

static RUSTUP_IMAGE: &[u8] = include_bytes!("../../tests/data/rustup-init.exe");

fn main() {
    let pe = Pe::from_bytes(RUSTUP_IMAGE).unwrap();
    dbg!(pe);
}
