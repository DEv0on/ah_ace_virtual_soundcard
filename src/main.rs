mod network_adapter;
mod main_client;
mod ace_packet;

use std::collections::VecDeque;
use pcap::Packet;
use crate::ace_packet::{ACEPacket, DPacket};
use crate::main_client::{Client, MainClient};
use crate::network_adapter::Adapter;
use wasapi::*;

fn main() {
    let client: MainClient = Client::new();
    let mut adapter = client.adapter.lock().unwrap();
    adapter.open();

    initialize_mta().unwrap();

    let device = get_default_device(&Direction::Render).unwrap();
    let mut audio_client = device.get_iaudioclient().unwrap();
    let desired_format = WaveFormat::new(24, 24, &SampleType::Int, 48000, 2, None);

    let blockalign = desired_format.get_blockalign();
    let (def_time, min_time) = audio_client.get_periods().unwrap();
    let needs_convert = needsConvert(&audio_client, &desired_format);


    audio_client
        .initialize_client(
            &desired_format,
            def_time,
            &Direction::Render,
            &ShareMode::Shared,
            needs_convert,
        )
        .unwrap();

    let h_event = audio_client.set_get_eventhandle().unwrap();

    let render_client = audio_client.get_audiorenderclient().unwrap();
    audio_client.start_stream().unwrap();
    loop {
        let mut buffer_frame_count = audio_client.get_available_space_in_frames().unwrap();
        let mut buffer = vec![0u8; buffer_frame_count as usize * blockalign as usize];
        let mut offset = 0;
        while offset < buffer_frame_count as usize {
            let wrappedPacket = adapter.capture.as_mut().unwrap().next_packet();
            if wrappedPacket.is_err() {
                continue;
            }

            let packet: Packet = wrappedPacket.unwrap();
            if !(235..239).contains(&packet.data.len()) {
                continue;
            }

            let acePacket: ACEPacket = *DPacket::new(packet.data);

            let channelsData = acePacket.getRangePCMChannelData(0..desired_format.get_nchannels() as u8);

            channelsData.iter().enumerate().for_each(|(i, x)| {
                let mut bytes = VecDeque::from(x.to_be_bytes());
                bytes.pop_front();
                bytes.iter().enumerate().for_each(|(j, x)| {
                    buffer[(offset * blockalign as usize) + i * 3 + j] = *x;
                })
            });
            offset += 1;
        }
        render_client.write_to_device(
            buffer.len() / blockalign as usize,
            blockalign as usize,
            &buffer,
            None,
        )
            .unwrap();
        if h_event.wait_for_event(500).is_err() {
            println!("error, stopping playback");
            audio_client.stop_stream().unwrap();
            break;
        }
    }
}

fn needsConvert(audio_client: &AudioClient, desired_format: &WaveFormat) -> bool {
    return match audio_client.is_supported(&desired_format, &ShareMode::Shared) {
        Ok(None) => {
            false
        }
        Ok(Some(modified)) => {
            true
        }
        Err(err) => {
            let desired_formatex = desired_format.to_waveformatex().unwrap();
            match audio_client.is_supported(&desired_formatex, &ShareMode::Shared) {
                Ok(None) => {
                    false
                }
                Ok(Some(modified)) => {
                    true
                }
                Err(err) => {
                    true
                }
            }
        }
    };
}