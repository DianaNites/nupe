//! Builder type for PE files

#[derive(Debug)]
pub struct Builder {
    //
}

#[cfg(test)]
mod fuzz {
    use super::*;
    use crate::{
        internal::test_util::{kani, RUSTUP_IMAGE},
        Pe,
    };

    /// Test, fuzz, and model [`Pe`] section modification
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn pe_section() {
        bolero::check!()
            .with_type::<(u32, u32)>()
            .for_each(|(a, b)| {
                let pe = Pe::from_bytes(RUSTUP_IMAGE).unwrap().clone();
                dbg!(&pe);
                // let mut b = PeBuilder::from_pe(pe, pe_bytes);

                panic!();
            });
    }
}

/// Test, fuzz, and model [`Pe`] section modification
#[cfg(no)]
#[test]
#[cfg_attr(kani, kani::proof)]
fn pe_section() {
    bolero::check!()
        .with_type::<(u32, u32)>()
        .for_each(|(a, b)| {
            let pe = Pe::from_bytes(RUSTUP_IMAGE).unwrap().clone();
            dbg!(&pe);
            let imp = pe.data_dir(DataDirIdent::Import).unwrap();
            // dbg!(&imp);
            let a = imp.address() as usize;
            let s = imp.size() as usize;
            let imp = &RUSTUP_IMAGE[a..][..s];
            // dbg!(&imp);
            // kani::assume(pe);

            panic!();
        });
}
