use pcap::{Active, Capture, Device, Error, Packet};

pub trait Adapter {
    fn new() -> Self;
    fn open(&mut self);
    fn nextPacket(&mut self) -> Result<Packet, Error>;
}

pub struct ACEAdapter {
    device: Device,
    pub capture: Option<Capture<Active>>
}

impl Adapter for ACEAdapter {
    fn new() -> Self {
        let deviceList = Device::list().unwrap();

        deviceList.iter().enumerate().for_each(|(i, x)| {
            println!("{} ({}) -> {}", x.name, x.desc.as_ref().unwrap(), i)
        });

        eprint!("Select adapter: ");
        let deviceNum: usize;
        text_io::scan!("{}", deviceNum);

        let device = &deviceList[deviceNum];


        ACEAdapter { device: device.clone(), capture: None }
    }

    fn open(&mut self) {
        self.capture = Some(Capture::from_device(self.device.clone())
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap());
    }

    fn nextPacket(&mut self) -> Result<Packet, Error> {
        return self.capture.as_mut().unwrap().next_packet();
    }
}