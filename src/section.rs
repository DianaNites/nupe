//! Section builders and stuff

use core::marker::PhantomData;

use crate::{
    error::{Error, Result},
    raw::RawSectionHeader,
    OwnedOrRef,
    Section,
    SectionFlags,
};

/// Build a section for a [`crate::PeHeader`] file.
#[derive(Debug, Clone)]
pub struct SectionBuilder<'data> {
    name: [u8; 8],
    data: Option<&'data [u8]>,
    attr: Option<SectionFlags>,
}

impl<'data> SectionBuilder<'data> {
    /// Create a new [`SectionBuilder`]
    pub fn new() -> Self {
        Self {
            name: [b'\0'; 8],
            data: None,
            attr: None,
        }
    }

    /// Name of the section
    ///
    /// If `name` is more than 8 bytes, it is truncated.
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name[..name.len().min(8)].copy_from_slice(name.as_bytes());
        self
    }

    /// Name of the section
    ///
    /// # Errors
    ///
    /// - If `name` is more than 8 bytes.
    pub fn try_name(&mut self, name: &str) -> Result<&mut Self> {
        if name.len() > 8 {
            return Err(Error::InvalidData);
        }
        self.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(self)
    }

    /// Data in the section.
    pub fn data(&mut self, data: &'data [u8]) -> &mut Self {
        self.data = Some(data);
        self
    }

    /// Attributes for the section
    pub fn attributes(&mut self, attr: SectionFlags) -> &mut Self {
        self.attr = Some(attr);
        self
    }

    pub fn build(&mut self) -> Result<Section<'static>> {
        let len = self.data.unwrap().len().try_into().unwrap();
        let mut header = RawSectionHeader {
            name: self.name,
            virtual_size: len,
            virtual_address: todo!(),
            raw_size: len,
            raw_ptr: todo!(),
            reloc_ptr: todo!(),
            line_ptr: todo!(),
            num_reloc: todo!(),
            num_lines: todo!(),
            characteristics: self.attr.unwrap(),
        };
        Ok(Section {
            header: OwnedOrRef::Owned(header),
            base: None,
        })
    }
}
