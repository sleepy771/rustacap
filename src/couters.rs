use std::net::IpAddr;
use std::hash::Hash;

pub type IpfixId = (IpAddr, u16, IpAddr, u16, u8);


pub trait Extractor {
    fn get_value(&self, octets: &[u8], additional_offset: u16) -> Vec<u16>;

    fn offset(&self) -> (u16, u8);

    fn size(&self) -> usize;

    fn reminding(&self) -> usize;
}


struct GenericExtractor {
    offset: u16,  // in bits
    field_length: u16,  // in bits
}


impl Extractor for GenericExtractor {
    
    fn offset(&self) -> (u16, u8) {
        let mask_bits = (self.offset % 8) as u8;
        let octets_offset = self.offset / 8;
        (octets_offset, mask_bits)
    }

    fn size(&self) -> usize {
        match self.reminding() {
            0 => (self.field_length / 16) as usize,
            _ => (self.field_length / 16 + 1) as usize
        }
    }

    fn reminding(&self) -> usize {
        (self.field_length % 16) as usize
    }

    fn get_value(&self, octets: &[u8], additional_offset: u16) -> Vec<u16> {
        let size = self.size();
        let (offset_octets, offset_bits) = self.offset();
        let mut buffer: Vec<u16> = Vec::with_capacity(size);
        let k: u16 = (((self.field_length + self.offset) as f32) / 8f32).ceil() as u16;
        let padding: u8 = (self.field_length + self.offset - (8 * k)) as u8;

        buffer
    }
}


trait DataManipulator<T: Sized + 'static> {
    fn apply(&self, d: &mut Box<T>, packet: &[u8]);

    fn is_applicable(&self, packet: &[u8]) -> bool;
}


trait IDObtainer<T: Sized + Hash + PartialEq + Eq> {
    fn get_id(packet: &[u8]) -> T;
}


struct Column<T: 'static> {
    data_manipulator: &'static DataManipulator<Data<T>>,
    data: Box<Data<T>>,
    bit_size: &'static u8
}

impl<T: Sized + 'static> Column<T> {
    fn apply(&mut self, packet: &[u8]) {
        if self.data_manipulator.is_applicable(packet) {
            self.data_manipulator.apply(&mut self.data, packet);
        }
    }

    fn get_value(&self) -> T {
    }
}

trait Data<T: Sized + Copy + Clone> {
    fn get_as_array(&self) -> Vec<u16>;

    fn get_value(&self) -> T;

    fn set_value(&mut self, value: T);
}


struct U64Data {
    value: u64,
}

struct U32Data {
    value: u32,
}

struct U16Data {
    value: u16,
}

struct U8Data {
    value: u8
}

impl Data<u64> for U64Data {
    fn get_as_array(&self) -> Vec<u16> {
        vec![
            (self.value >> 48) as u16,
            ((self.value >> 32) & 0xFFFF) as u16,
            ((self.value >> 16) & 0xFFFF) as u16,
            (self.value & 0xFFFF) as u16
        ]
    }

    fn get_value(&self) -> u64 {
        self.value
    }

    fn set_value(&mut self, value: u64) {
        self.value = value;
    }
}

impl Data<u32> for U32Data {
    fn get_as_array(&self) -> Vec<u16> {
        vec![
            (self.value >> 16) as u16,
            (self.value & 0xFFFF) as u16
        ]
    }

    fn get_value(&self) -> u32 {
        self.value
    }

    fn set_value(&mut self, value: u32) {
        self.value = value;
    }
}

impl Data<u16> for U16Data {
    fn get_as_array(&self) -> Vec<u16> {
        vec![self.value]
    }

    fn get_value(&self) -> u16 {
        self.value
    }

    fn set_value(&mut self, value: u16) {
        self.value = value;
    }
}

impl Data<u8> for U8Data {
    fn get_as_array(&self) -> Vec<u16> {
        vec![(self.value << 8) as u16]
    }

    fn get_value(&self) -> u8 {
        self.value
    }

    fn set_value(&mut self, value: u8) {
        self.value = value;
    }
}