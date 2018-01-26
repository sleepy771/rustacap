struct Ipfix {
    version_number: u16,
    length: u16,
    export_time: u32,
    sequence_number: u32,
    observation_domain_id: u32,
}

struct TemplateSet {
    set_id: u16,
    length: u16,
    records: Vec<TemplateRecord>
}


struct TemplateRecord {
    template_id: u16,
    field_count: u16,
    specifiers: Vec<FieldSpecifier>
}


struct FieldSpecifier {
    enterprise_infromation_element_id: u16,
    field_length: u16,
    enterprise_number: Option<u32>
}


pub impl FieldSpecifier {
    pub new(information_element_id: u16, field_length: u16, enterprise_number: Option<u32>) -> FieldSpecifier {
        FieldSpecifier {
            enterprise_infromation_element_id: create_info_element_id(information_element_id, !enterprise_number.is_none()),
            field_length: field_length,
            enterprise_number: enterprise_number,
        }
    }

    pub is_enterprise(&self) -> bool {
        enterprise_infromation_element_id & (1 << 16) == (1 << 16)
    }
}


fn create_info_element_id(info_element_id: u16, is_enterprise: bool) -> u16 {
    if is_enterprise {
        info_element_id | (1u16 << 15)
    } else {
        info_element_id
    }
}

struct OptionsTemplate {
    set_id: u16,
    length: u16,
    records: Vec<OptionsTemplateRecord>
}

struct OptionsTemplateRecord {
    template_id: u16,
    field_count: u16,
    scope_field_count: u16,  // MUST NOT BE 0, @see https://tools.ietf.org/html/rfc7011#section-3
    scope_fields: Vec<u16>,
    specifiers: Vec<u16>
}


struct ScopeFieldSpecifier {
    enterprise_info_elm_id: u16,
    field_length: u16,
    enterprise_number: Option<u16>
}

struct OptionsTemplateFieldSpecifier {
    enterprise_info_elm_id: u16,
    field_length: u16,
    enterprise_number: Option<u16>
}


struct DataSet {
    set_id: u16,
    length: u16,
    records: Vec<DataSetRecord>
}

pub impl DataSet {
    pub fn new(set_id: u16) -> DataSet {
        DataSet {
            set_id: set_id,
            length: 0u16,
            records: records,
        }
    }

    pub fn add_optimistic(&mut self, record: DataSetRecord) {
        self.records.push(record);
    }
}


struct DataSetRecord {
    record_fields: Vec<u16>, // TODO change this back to [u8; 4]
}

pub impl DataSetRecord {
    pub fn new(length: usize) -> DataSetRecord {
        DataSetRecord {
            record_fields: Vec::with_capacity(length)
        }
    }

    pub fn store_u64(&mut self, value: u64) {
        self.record_fields[0] = (value >> 48 as u16);
        self.record_fields[1] = ((value >> 32) & 0xffff) as u16;
        self.record_fields[2] = ((value >> 16) & 0xffff) as u16;
        self.record_fields[3] = (value & 0xffff) as u16;
    }

    pub fn store_u32(&mut self, value: u32) {
        self.record_fields[0] = (value >> 16) as u16;
        self. record_fields[1] = (value & 0xffff) as u16;
    }

    pub fn store_u16(&mut self, value: u16) {
        self.record_fields[0] = value;
    }

    pub fn store_u8(&mut self, value: u8) {
        self.record_fields[0] = (value as u16) << 8;
    }

    pub fn load_u64(&self) -> u64 {
        self.record_fields[0] as u64 << 48 | self.record_fields[1] as u64 << 32 | self.record_fields[2] as u64 << 16 | self.record_fields[3] as u64
    }

    pub fn load_u32(&self) -> u32 {
        self.record_fields[0] as u32 << 16 | self.record_fields[1] as u32
    }

    pub fn load_u16(&self) -> u16 {
        self.record_fields[0]
    }

    pub fn load_u8(&self) -> u8 {
        (self.record_fields[0] >> 8) as u8
    }

    pub fn setTcpControlBits(&mut self, control_bits: u16) {
        let current_control_bits = self.load_u16();
        self.store_u16(current_control_bits | control_bits);
    }

    pub fn increaseCounter(&mut self) {
        let counter = ds.load_u64();
        self.store_u64(counter + 1);
    }

    pub fn setProtocolIdentifier(&mut self, protocol_id: u8) {
        self.store_u8(protocol_id);
    }

    pub fn setIpClassOfService(*mut self, class_of_service: u8) {
        self.store_u8(class_of_service);
    }
}


fn to_u32(octets: &[u8], offset: usize, padding: u8) -> u32 {
    match padding {
        0 => octets[offset] << 24 | octets[offset + 1] << 16 | octets[offset + 2] << 8 | octets[offset + 3],
        1 => octets[offset] << 24 | octets[offset + 1] << 16 | octets[offset + 2] << 8,
        2 => octets[offset] << 24 | octets[offset + 1] << 16
        3 => octets[offset] << 24
        _ => 0u32
}


fn to_u16(octets: &[u8], offset: usize, padding: u8) -> u16 {
    match padding {
        0 => ((octets[offset] as u16 << 8) | octets[offset + 1] as u16),
        1 => octets[offset] as u16 << 8,
        _ => 0u16
    }
}
