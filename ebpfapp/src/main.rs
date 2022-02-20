mod parser;
use anyhow::Context;
use aya::maps::perf::{AsyncPerfEventArray, Events};
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use ebpfapp_common::{PacketLog, PacketType, XdpAction};
use log::info;
use parser::Packet;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use std::convert::{TryFrom, TryInto};
use std::net::{self, Ipv4Addr};
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio::{signal, task};

use crate::parser::{parse_buf, ParserToString};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

#[derive(Debug)]
pub enum Command {
    Block { ip: Ipv4Addr },
    Allow { ip: Ipv4Addr },
}

fn process_bpf_events(bpf: &Bpf) -> Result<(), anyhow::Error> {
    // Load buffers from each cpu as AsyncPerfEventArray is a per cpu ring buffer.
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let mut action_list: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("ACTION_LIST")?)?;

    let (tx, mut rx) = mpsc::channel::<Command>(32);

    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            let _ = match cmd {
                Command::Block { ip } => {
                    action_list.insert(u32::from(ip), XdpAction::DROP as u32, 0)
                }
                Command::Allow { ip } => {
                    action_list.insert(u32::from(ip), XdpAction::PASS as u32, 0)
                }
            };
        }
    });

    for cpu_id in online_cpus()? {
        let tx = tx.clone();
        let mut buf = perf_array.open(cpu_id, None)?;
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            // Process events
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let packet = parse_and_log_packet(buf);
                    // block icmp packets
                    if packet.packet_type == PacketType::ICMP {
                        let _ = tx.send(Command::Block { ip: packet.source }).await;
                    } else {
                        let _ = tx.send(Command::Allow { ip: packet.source }).await;
                    }
                }
            }
        });
    }
    Ok(())
}

fn parse_and_log_packet(buf: &mut BytesMut) -> Packet {
    let packet = parse_buf(buf);
    println!("{} - {}", packet.source, packet.destination);
    println!(
        "LOG: SRC {}, DST{} , packet_type {} - {}, ACTION {}",
        packet.source,
        packet.destination,
        packet.packet_type.to_str(),
        packet.packet_type as u8,
        packet.action.to_str(),
    );
    packet
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpfapp"
    ))?;
    let program: &mut Xdp = bpf.program_mut("ebpfapp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    process_bpf_events(&bpf)?;

    info!("Listening on {}", &opt.iface);
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
