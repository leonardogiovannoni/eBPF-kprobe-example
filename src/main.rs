mod common;
use crate::common::data::Data;
use std::ffi::CStr;

use anyhow::anyhow;
use aya::{
    include_bytes_aligned, maps::AsyncPerfEventArray, programs::{FEntry, KProbe}, util::online_cpus, Bpf, Btf,
};
// use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    //#[clap(short, long, default_value = "eth0")]
    //iface: String,
}
//const BPF_FILE: &'static str = "../out.o";
//const BPF_FILE: &'static str = env!("CONFIG_DAT_PATH");
macro_rules! BPF_FILE {
    () => {
        env!("CONFIG_DAT_PATH")
        //"../out.o"
    };
}
const BPF_BYTES: &'static [u8] = include_bytes_aligned!(BPF_FILE!());
/* 
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Data {
    file_name: [u8; 128],
}
*/


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    //let opt = Opt::parse();

    // env_logger::init();

    let mut bpf = Bpf::load(BPF_BYTES)?;

    // if let Err(e) = EbpfLogger::init(&mut bpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }
    
    
    let program: &mut FEntry = bpf.program_mut("get_file_name").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
     
    program.load("vfs_read", &btf)?;
    program.attach()?;
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let tmp = bpf.take_map("EVENTS").ok_or(anyhow!("NOPE"))?;
    let mut events = AsyncPerfEventArray::try_from(tmp)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        tokio::task::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(10240); num_cpus];
            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Data;
                    let data = unsafe { *ptr };
                    let file_name = CStr::from_bytes_until_nul(&data.filename).unwrap();
                    let file_name = file_name.to_str().unwrap();
                    println!("file_name: {:?}", file_name);
                }
            }
        });
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
