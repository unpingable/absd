#![allow(dead_code,unused_imports)]
use std::{cell::RefCell,collections::VecDeque,fs::{File,OpenOptions},io::{self,Read,Write},path::PathBuf,rc::Rc,sync::{Arc,Mutex,OnceLock,atomic::{AtomicBool,AtomicU8,AtomicUsize,Ordering}},time::{Duration,Instant}};
#[path="@SOURCE@/sh/src/lib.rs"]mod shell;
#[path="@SOURCE@/src/sh_input.rs"]mod sh_input;
#[path="@SOURCE@/ssh/src/tty.rs"]mod tty;
#[path="@SOURCE@/ssh/src/plain_input.rs"]mod plain_input;
#[path="@SOURCE@/ssh/src/control.rs"]mod control;
#[path="@SOURCE@/ssh/src/local_console.rs"]mod local_console;
mod oplog{pub fn line(_:String){}}
mod conn{use std::{io,time::Instant};use crate::tty::Terminal;@CONN_TRAITS@}
mod posix{
 use super::*;
 #[repr(C)]struct Poll{fd:i32,events:i16,revents:i16}
 unsafe extern "C"{fn pipe2(p:*mut i32,flags:i32)->i32;fn read(fd:i32,p:*mut u8,n:usize)->isize;fn write(fd:i32,p:*const u8,n:usize)->isize;fn close(fd:i32)->i32;fn poll(p:*mut Poll,n:usize,ms:i32)->i32;fn ioctl(fd:i32,request:usize,...)->i32;fn fcntl(fd:i32,cmd:i32,...)->i32;}
 pub fn pipe()->(u64,u64){let mut f=[0;2];assert_eq!(unsafe{pipe2(f.as_mut_ptr(),0x80000|0x800)},0);(f[0]as u64,f[1]as u64)}
 pub fn capacity(fd:u64,n:i32)->i32{unsafe{fcntl(fd as i32,1031,n)}}
 pub fn ready(fd:u64,writing:bool,ms:u64)->bool{let mut p=Poll{fd:fd as i32,events:if writing{4}else{1},revents:0};(unsafe{poll(&mut p,1,ms.min(1000)as i32)})>0}
 pub fn read_fd(fd:u64,b:&mut[u8],ms:u64)->Result<usize,i64>{if !ready(fd,false,ms){return Err(-110)}let n=unsafe{read(fd as i32,b.as_mut_ptr(),b.len())};if n<0{Err(-110)}else{Ok(n as usize)}}
 pub fn write_fd(fd:u64,b:&[u8],ms:u64)->Result<usize,i64>{if !ready(fd,true,ms){return Err(-110)}let n=unsafe{write(fd as i32,b.as_ptr(),b.len().min(256))};if n<0{Err(-32)}else{Ok(n as usize)}}
 pub fn all(fd:u64,mut b:&[u8]){while !b.is_empty(){match write_fd(fd,b,10){Ok(n)if n>0=>b=&b[n..],Err(-110)=>{},other=>panic!("IPC write {other:?}")}}}
 pub fn available(fd:u64)->Result<[u64;4],i64>{let mut n=0i32;if unsafe{ioctl(fd as i32,0x541busize,&mut n)}<0{return Err(-1)}let mut p=Poll{fd:fd as i32,events:1,revents:0};unsafe{poll(&mut p,1,0)};Ok([n as u64,8192,1,if p.revents&16!=0{0}else{1}])}
 pub fn close_fd(fd:u64){if fd!=0{unsafe{close(fd as i32)};}}
}
static PHASE:AtomicU8=AtomicU8::new(0);
static STALE:AtomicBool=AtomicBool::new(false);
static INTERRUPTS:AtomicUsize=AtomicUsize::new(0);
static DRAINED:AtomicUsize=AtomicUsize::new(0);
static AUDIT:OnceLock<Mutex<Vec<String>>>=OnceLock::new();
fn audit(s:impl Into<String>){AUDIT.get_or_init(Default::default).lock().unwrap().push(s.into());}
thread_local!{static CONFIG:RefCell<(u64,u64,u64,PathBuf)>=RefCell::new((0,0,0,PathBuf::new()));}
fn root_path(path:&str)->PathBuf{CONFIG.with(|c|c.borrow().3.join(path.trim_start_matches('/')))}
mod absd_runtime{
 use super::*;
 pub fn ticks()->u64{static START:OnceLock<Instant>=OnceLock::new();START.get_or_init(Instant::now).elapsed().as_millis()as u64}
 pub fn close(fd:u64)->Result<(),i64>{posix::close_fd(fd);Ok(())}
 pub fn standard_stream_handles()->(u64,u64){CONFIG.with(|c|(c.borrow().0,0))}
 pub fn read_within(fd:u64,b:&mut[u8],ticks:u64)->Result<usize,i64>{
  let input=standard_stream_handles().0;
  if fd==input{assert_eq!(PHASE.load(Ordering::SeqCst),3,"native read paused stdin before mode0 acknowledgement");}
  let n=posix::read_fd(fd,b,ticks);
  if fd==input{if let Ok(n)=n{DRAINED.fetch_add(n,Ordering::SeqCst);}if matches!(n,Ok(0)|Err(-110)){PHASE.store(4,Ordering::SeqCst);audit("drain-complete");}}
  n
 }
 pub fn write_within(fd:u64,b:&[u8],ticks:u64)->Result<usize,i64>{posix::write_fd(fd,b,ticks)}
 pub mod session{pub fn channel()->Option<(u64,u64)>{super::CONFIG.with(|c|{let c=c.borrow();Some((c.1,c.2))})}}
 pub mod fsd{pub fn pipe_info(fd:u64)->Result<[u64;4],i64>{super::posix::available(fd)}}
 pub mod terminal{pub struct Size{pub columns:u32,pub rows:u32}pub fn size()->Option<Size>{None}}
}
#[unsafe(no_mangle)]unsafe extern "C" fn __absd_std_read(ptr:*mut u8,len:usize)->isize{
 assert!(!matches!(PHASE.load(Ordering::SeqCst),1|2),"shell attempted stdin read during control-only discard wait");
 let fd=CONFIG.with(|c|c.borrow().0);let b=unsafe{std::slice::from_raw_parts_mut(ptr,len)};
 loop{match posix::read_fd(fd,b,1){Ok(n)=>return n as isize,Err(-110)=>{},Err(n)=>return n as isize}}
}
mod native{
 use super::{absd_runtime,root_path};use std::{fs::{File,OpenOptions},io::{self,Read,Write}};
 use crate::control::{self,Decoder,Frame};use crate::shell::{Authority,Exit,Host,Input,Output,Ran,SessionRequest,Stage};
 const KERNEL_TIMEOUT:i64=-110;const ANSWER_TICKS:u64=60000;
 @NATIVE_STRUCTS@
 impl Host for Absd{
  @NATIVE_METHODS@
  type Source=File;type Sink=File;
  fn open_read(&mut self,path:&str)->io::Result<File>{File::open(root_path(path))}
  fn open_write(&mut self,path:&str,append:bool)->io::Result<File>{OpenOptions::new().create(true).write(true).truncate(!append).append(append).open(root_path(path))}
  fn is_dir(&mut self,path:&str)->io::Result<bool>{Ok(root_path(path).is_dir())}
  fn run(&mut self,_:Vec<Stage<File,File>>)->Vec<Ran>{panic!("rejected source started an external program")}
 }
}
#[derive(Default)]struct Board{ack:VecDeque<(u8,u8)>,pending_mode:Option<u8>,disconnect:bool,decoder:Option<control::Decoder>,done:bool}
struct Child{input:u64,events:u64,requests:u64,board:Rc<RefCell<Board>>}
impl Drop for Child{fn drop(&mut self){for f in [self.input,self.events,self.requests]{posix::close_fd(f);}}}
impl Child{
 fn mode_reply(&mut self,status:u8,text:&str){let mode=self.board.borrow_mut().pending_mode.take().unwrap();
  assert_eq!(text,plain_input::CAPABILITY);audit(format!("ack:{mode}:{status}"));
  if mode==4&&status==control::INPUT_PAUSED{PHASE.store(1,Ordering::SeqCst);}
  if mode==0&&status==control::INPUT_PAUSED{assert!(matches!(PHASE.load(Ordering::SeqCst),2|3|4));PHASE.store(3,Ordering::SeqCst);}
  if matches!(mode,1|2)&&status==0&&matches!(PHASE.load(Ordering::SeqCst),1|2|3|4){assert_eq!(PHASE.load(Ordering::SeqCst),4,"rearm before actual pipe drain");PHASE.store(5,Ordering::SeqCst);}
  if mode==4&&STALE.load(Ordering::SeqCst){audit("pre-ack-stale-interrupt");posix::all(self.events,&control::interrupt());}
  posix::all(self.events,&control::reply(status,text));self.board.borrow_mut().ack.push_back((mode,status));
 }
}
impl conn::SessionChild for Child{
 fn read_stdout(&mut self,_:&mut[u8])->io::Result<Option<usize>>{Ok(None)}fn read_stderr(&mut self,_:&mut[u8])->io::Result<Option<usize>>{Ok(None)}
 fn write_stdin(&mut self,b:&[u8])->io::Result<Option<usize>>{assert!(!matches!(PHASE.load(Ordering::SeqCst),1|2|3|4),"producer wrote after pause and before permitted rearm");match posix::write_fd(self.input,b,0){Ok(n)=>Ok(Some(n)),Err(-110)=>Ok(None),Err(_)=>Err(io::ErrorKind::BrokenPipe.into())}}
 fn close_stdin(&mut self){posix::close_fd(self.input);self.input=0;}
 fn try_wait(&mut self)->io::Result<Option<conn::Exit>>{Ok(None)}
 fn terminate(&mut self){if self.events!=0{let _=posix::write_fd(self.events,&control::end(),1);}}
 fn interrupt(&mut self)->bool{if PHASE.load(Ordering::SeqCst)==1{PHASE.store(2,Ordering::SeqCst);INTERRUPTS.fetch_add(1,Ordering::SeqCst);}else{audit("pre-fence-interrupt");}audit("new-interrupt");posix::all(self.events,&control::interrupt());true}
 fn control_request(&mut self,_:Instant)->Result<Option<conn::ControlRequest>,String>{
  let mut b=[0;256];let mut board=self.board.borrow_mut();if board.disconnect&&self.events!=0{posix::close_fd(self.events);self.events=0;}let decoder=board.decoder.get_or_insert_with(||control::Decoder::new(control::REQUESTS));
  match posix::read_fd(self.requests,&mut b,0){Ok(0)=>return Err("closed".into()),Ok(n)=>decoder.push(&b[..n]),Err(-110)=>{},Err(_)=>return Err("read".into())}
  match decoder.next(){Ok(Some(control::Frame::InputMode(mode)))=>{board.pending_mode=Some(mode);audit(format!("request:{mode}"));Ok(Some(conn::ControlRequest::InputMode(mode)))},Ok(None)=>Ok(None),other=>Err(format!("unexpected control {other:?}"))}
 }
 fn control_reply(&mut self,status:u8,text:&str){self.mode_reply(status,text)}
}
struct Spawn(Option<Child>);impl conn::Spawner for Spawn{type Child=Child;fn spawn(&mut self,_:&conn::Command,_:Option<&tty::Terminal>)->io::Result<Child>{Ok(self.0.take().unwrap())}fn machine_request(&mut self,_:conn::MachineRequest)->Result<String,String>{Err("not used".into())}}
trait Producer{fn input(&mut self,b:&[u8]);fn tick(&mut self);fn end(&mut self);fn queued_cancel(&mut self){panic!("only the local ingress pipe supplies queued cancellation")}}
struct Local{manager:local_console::Manager<Child>,spawn:Spawn,reader:u64,writer:u64,requests:u64}
impl Local{fn new(child:Child)->Self{let requests=child.requests;let(reader,writer)=posix::pipe();let mut s=Self{manager:local_console::Manager::new(true),spawn:Spawn(Some(child)),reader,writer,requests};s.manager.input(b"enrolled\r",Instant::now(),|x|x==b"enrolled",&mut s.spawn);s}}
impl Drop for Local{fn drop(&mut self){posix::close_fd(self.reader);posix::close_fd(self.writer);}}
impl Producer for Local{
 fn input(&mut self,mut b:&[u8]){while !b.is_empty(){match posix::write_fd(self.writer,b,0){Ok(n)=>b=&b[n..],Err(-110)=>{},other=>panic!("local ingress {other:?}")}self.tick();}while posix::available(self.reader).unwrap()[0]>0{self.tick();}}
 fn tick(&mut self){let mut bytes=[0;128];if let Ok(n)=posix::read_fd(self.reader,&mut bytes,0){if n>0{self.manager.input(&bytes[..n],Instant::now(),|_|false,&mut self.spawn);}}
  let upstream_empty=posix::available(self.reader).map(|v|v[0]==0).unwrap_or(false);self.manager.poll(Instant::now(),&mut self.spawn,upstream_empty);self.manager.output(|b|b.len());}
 fn end(&mut self){self.manager.end_all(Instant::now());}
 fn queued_cancel(&mut self){assert!(posix::capacity(self.writer,131072)>=131072);let mut bytes=vec![3];bytes.resize(4096,b'\n');let mut line=b"echo bad > /upstream-effect".to_vec();line.resize(255,b' ');line.push(b'\n');for _ in 0..256{bytes.extend_from_slice(&line);}let total=bytes.len();let mut left=bytes.as_slice();while !left.is_empty(){let n=posix::write_fd(self.writer,left,0).expect("local upstream bounded queue");assert!(n>0);left=&left[n..];}assert_eq!(posix::available(self.reader).unwrap()[0],total as u64);audit(format!("upstream-queued-before-cancel:{total}"));self.tick();for _ in 0..2{assert!(posix::ready(self.requests,false,1000),"native local control request absent");self.tick();audit(format!("queued-after-local-control:{}",posix::available(self.reader).unwrap()[0]));}}
}

fn main(){
 let args:Vec<String>=std::env::args().collect();let frontend=&args[1];let scenario=&args[2];STALE.store(scenario=="stale",Ordering::SeqCst);let root=PathBuf::from(&args[3]);std::fs::create_dir(&root).unwrap();
 let(input_r,input_w)=posix::pipe();let(events_r,events_w)=posix::pipe();let(requests_r,requests_w)=posix::pipe();CONFIG.with(|c|*c.borrow_mut()=(input_r,events_r,requests_w,root.clone()));
 let done=Arc::new(AtomicBool::new(false));let server_done=done.clone();assert_eq!(frontend,"local");let scenario_copy=scenario.clone();
 let server=std::thread::spawn(move||{
  let board=Rc::new(RefCell::new(Board::default()));let child=Child{input:input_w,events:events_w,requests:requests_r,board:board.clone()};
  let mut producer:Box<dyn Producer>=Box::new(Local::new(child));
  let mut lines=VecDeque::new();let body=vec![b'x';4000];
  if scenario_copy=="quote"{lines.push_back(b"echo '\n".to_vec());}else{lines.push_back(b"echo forbidden > /earlier; cat <<'END'\n".to_vec());}
  for i in 0..263{let mut line=body.clone();line.push(b'\n');if i==262{line.extend_from_slice(if scenario_copy=="quote"{b"' > /refused\necho fresh > /fresh\n"}else{b"END\necho forbidden > /queued\n"});}lines.push_back(line);}
  let source_bytes:usize=lines.iter().map(Vec::len).sum();if scenario_copy=="quote"{assert_eq!(source_bytes,1_052_303);}audit(format!("source-bytes:{source_bytes}"));let mut rejected=false;let mut fresh=0usize;
  while !server_done.load(Ordering::SeqCst){producer.tick();let ack=board.borrow_mut().ack.pop_front();
   if let Some((mode,status))=ack{
    if mode==4{assert_eq!(status,control::INPUT_PAUSED);rejected=true;
     // Keep newlines, delimiters and effectful tails fenced with no boundary.
     let mut batch=[b'\n';4096];let poison=b"END\necho bad > /discarded\n\n";batch[..poison.len()].copy_from_slice(poison);
     for _ in 0..257{producer.input(&batch);producer.tick();assert_eq!(PHASE.load(Ordering::SeqCst),1);}
     audit("discarded-without-boundary");
     if scenario_copy=="backlog"{producer.queued_cancel();}else if scenario_copy=="disconnect"{board.borrow_mut().disconnect=true;producer.tick();}else if scenario_copy=="end"{producer.end();}else{producer.input(b"old\x03echo bad >/same-batch\n\n");producer.tick();producer.input(b"echo bad >/after-cancel\n\x03");producer.tick();}
    }else if matches!(mode,1|2)&&status==0{
     if PHASE.load(Ordering::SeqCst)==5{let command=if fresh==0{b"echo ok > /ok\n".as_slice()}else{b"exit 0\n"};fresh+=1;producer.input(command);}
     else if let Some(line)=lines.pop_front(){producer.input(&line);}
    }
   }
   std::thread::yield_now();
  }
  assert!(rejected);assert!(lines.is_empty());
 });
 let mut shell=shell::Shell::new(native::Absd::new(),"/".into());let(mut out,mut err)=(Vec::new(),Vec::new());let status=shell::session(&mut shell,shell::Mode::Interactive,&mut sh_input::interactive(),&mut out,&mut err);
 done.store(true,Ordering::SeqCst);drop(shell);posix::close_fd(input_r);server.join().unwrap();
 std::fs::write(root.join("audit.json"),format!("{:?}",AUDIT.get().unwrap().lock().unwrap())).unwrap();
 let notice=String::from_utf8(err).unwrap();assert_eq!(notice.matches("input exceeds 1 MiB").count(),1);
 for name in ["earlier","queued","discarded","same-batch","after-cancel","refused","fresh","upstream-effect"]{assert!(!root.join(name).exists(),"effect escaped: {name}");}
 if scenario=="end"||scenario=="disconnect"{assert_eq!(status,shell::STATUS_INTERRUPTED);assert!(!root.join("ok").exists());}
 else{assert_eq!(status,0);assert_eq!(std::fs::read(root.join("ok")).unwrap(),b"ok\n");assert_eq!(INTERRUPTS.load(Ordering::SeqCst),1);assert!(DRAINED.load(Ordering::SeqCst)>0,"did not exercise a real pending-pipe drain");}
 println!("frontend={frontend} scenario={scenario} status={status} one_refusal=true earlier_effects=false fresh_ok={} drained={} interrupts={}",root.join("ok").exists(),DRAINED.load(Ordering::SeqCst),INTERRUPTS.load(Ordering::SeqCst));
 println!("audit={:?}",AUDIT.get().unwrap().lock().unwrap());
}
