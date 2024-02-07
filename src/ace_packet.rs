use std::ops::Range;

pub trait DPacket {
    fn new(data: &[u8]) -> Box<Self>;

    fn getChannelData(&self, channel: &u8) -> Box<[u8]>;
    fn getPCMChannelData(&self, channel: &u8) -> u32;
    fn getRangePCMChannelData(&self, channel: Range<u8>) -> Vec<u32>;
}

pub struct ACEPacket {
    vlan: bool,
    payload: Box<[u8]>,
}

impl DPacket for ACEPacket {
    fn new(data: &[u8]) -> Box<ACEPacket> {
        Box::new(
            ACEPacket {
                payload: Box::from(data),
                vlan: data.len().eq(&235),
            }
        )
    }

    fn getChannelData(&self, channel: &u8) -> Box<[u8]> {
        let offset = if self.vlan { 18 } else { 14 };
        let data = &self.payload[usize::from(offset + channel * 3)-1..usize::from(offset + channel * 3 + 3)];

        return Box::from(data);
    }

    fn getPCMChannelData(&self, channel: &u8) -> u32 {
        let ch = channel % 9 * 8 + (channel / 9);
        let mut data = interpret24bitAsInt32(&self.getChannelData(&ch));

        data = (data & 0xff0000) >> 16 | (data & 0x00ff00) | (data & 0x0000ff) << 16;
        data = (data & 0xf0f0f0) >> 4 | (data & 0x0f0f0f) << 4;

        return data;
    }
    fn getRangePCMChannelData(&self, channels: Range<u8>) -> Vec<u32> {
        let mut data = vec!(0u32, channels.len() as u32);
        let mut i = 0;
        for ch in channels {
            let chData = self.getPCMChannelData(&ch);
            data[i] = chData;
            i += 1;
        }
        return data;
    }
}

fn interpret24bitAsInt32(data: &[u8]) -> u32 {
    let num: u32 =
        (data[0] as u32) << 16 |
            (data[1] as u32) << 8 |
            data[2] as u32;

    return num;
}