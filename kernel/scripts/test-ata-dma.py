#!/usr/bin/env python3
"""Run the actual ATA driver with port/PCI stubs; no privileged I/O executes."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'src/ata.rs').read_text()
start = source.index('unsafe fn outl(')
end = source.index('\nfn dma_transfer', start)
# The only driver substitution replaces privileged OUTL with its inert port stub.
source = source[:start] + 'unsafe fn outl(port:u16,value:u32) { crate::io_outl(port,value); }\n' + source[end:]
source += r'''
#[cfg(test)] mod lifecycle {
    use super::*;
    #[test] fn actual_dma_lifecycle() {
        for scenario in 0..5 {
            crate::MOCK.with(|state| *state.borrow_mut() = crate::Mock { scenario, ..Default::default() });
            unsafe {
                core::ptr::write(core::ptr::addr_of_mut!(DEVICE), Some(Device {
                    sectors: 32, dma: Some(Dma {function: crate::pci::Function {bus:0,device:1,function:1},base:0xc000}), failed:false
                }));
                (*core::ptr::addr_of_mut!(BOUNCE)).0.fill(0x5a);
            }
            let mut output = [0xa5;512];
            let result = read_sectors(0, &mut output);
            if scenario == 0 {
                assert!(result.is_ok());
                assert_eq!(output, [0x5a;512]);
                assert!(!device().unwrap().failed);
                assert_eq!(crate::MOCK.with(|s| s.borrow().disabled), 0);
            } else {
                if scenario == 3 { assert!(matches!(result, Err(BlockError::Timeout))); }
                else { assert!(matches!(result, Err(BlockError::Device))); }
                assert_eq!(output, [0xa5;512], "partial bounce must not publish");
                assert!(device().unwrap().failed);
                assert_eq!(crate::MOCK.with(|s| s.borrow().disabled), 1);
                let starts = crate::MOCK.with(|s| s.borrow().starts);
                assert!(read_sectors(0, &mut output).is_err());
                assert!(write_sectors(0, &[1;512]).is_err());
                assert!(flush().is_err());
                assert_eq!(crate::MOCK.with(|s| s.borrow().starts), starts, "poison forbids subsequent DMA");
            }
            assert!(crate::MOCK.with(|s| s.borrow().stops) > 0);
        }
    }
}
'''
harness = r'''
#![allow(dead_code)]
extern crate self as absd_kernel;
#[path="RULES"] pub mod ata_dma;
pub mod syscall { pub const BLOCK_SECTOR_BYTES:usize=512; }
#[derive(Default)] struct Mock {scenario:u8, starts:usize, stops:usize, disabled:usize, running:bool}
thread_local! {static MOCK: std::cell::RefCell<Mock> = Default::default();}
fn io_outl(_:u16,_:u32) {}
mod kernel_lock {#[derive(Clone,Copy)] pub enum WaitSite {Ata} pub fn assert_bsp_device_access(){} pub fn current_stop_requested()->bool{false}}
mod block {
 #[derive(Debug)] pub enum BlockError {Absent,Timeout,Device,OutOfRange,ReadOnly}
 pub const WRITES_BUILT:bool=true;
 pub fn wait_for_interrupt(_:crate::kernel_lock::WaitSite){}
 pub fn transfer_sectors(bytes:usize)->Result<usize,BlockError>{if bytes==0||bytes>4096||bytes%512!=0{Err(BlockError::OutOfRange)}else{Ok(bytes/512)}}
}
mod serial {
 pub fn write(_: &str){} pub fn hex(_:u64){}
 pub unsafe fn outb(port:u16,value:u8){if port==0xc000{crate::MOCK.with(|s|{let mut s=s.borrow_mut();s.running=value&1!=0;if s.running{s.starts+=1}else{s.stops+=1}})}}
 pub unsafe fn inb(port:u16)->u8{crate::MOCK.with(|s|{let s=s.borrow();match port {
  0x1f7=>if s.scenario==2 {1}else{0x40},
  0xc002=>match s.scenario{0=>4,1=>2,2=>0,3=>0,4=>if s.running{4}else{1},_=>unreachable!()},
  _=>0,
 }})}
}
mod pci {
 #[derive(Clone,Copy,Debug,Eq,PartialEq)] pub struct Function{pub bus:u8,pub device:u8,pub function:u8}
 pub fn find_id(_:u16,_:u16)->Option<Function>{None} pub fn read32(_:Function,_:u8)->u32{0}
 pub fn claim(_:Function,_: &'static str)->Result<(),()>{Ok(())}
 pub fn command(_:Function)->u16{5} pub fn disable_dma(_:Function){crate::MOCK.with(|s|s.borrow_mut().disabled+=1)}
}
pub mod dma_policy {pub struct Declaration; pub const ATA_BMIDE:Declaration=Declaration;}
mod dma {pub fn arm_ide(_:crate::pci::Function,_: &'static crate::dma_policy::Declaration)->Result<(),()>{Ok(())}}
mod smp_fixture {pub fn device_first_poll(_:crate::kernel_lock::WaitSite){}}
mod smp_startup {pub fn first_poll(_:crate::kernel_lock::WaitSite){}}
#[path="DRIVER"] mod ata;
'''
with tempfile.TemporaryDirectory(prefix='ata-dma-host-') as tmp:
    tmp = pathlib.Path(tmp)
    (tmp/'ata.rs').write_text(source)
    (tmp/'test.rs').write_text(harness.replace('RULES', str(root/'src/ata_dma.rs')).replace('DRIVER', str(tmp/'ata.rs')))
    subprocess.run(['rustc','--edition=2024','--test','-C','relocation-model=static','-C','link-arg=-no-pie',str(tmp/'test.rs'),'-o',str(tmp/'test')],check=True)
    subprocess.run([str(tmp/'test')],check=True)
