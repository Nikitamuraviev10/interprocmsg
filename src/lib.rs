extern crate libc;
use std::mem;
use std::io::{Result, Error};

#[repr(C)]
union Union {
    sival_int: i32,
    sival_ptr: *mut libc::c_void,
}

extern "C" {
    pub fn sigqueue(
        __pid: libc::pid_t,
        __signal: ::std::os::raw::c_int,
        __value: libc::sigval,
    ) -> ::std::os::raw::c_int;
}

static mut IPM: Option<InterProcMsg> = None;


fn sig_handler(_sig : i32, info: libc::siginfo_t){
    
    let ipm = match get_ipm(){
        Some(s) => s,
        None => return
    };

    let _pid = unsafe{ info.si_pid() };
    
    let msgid : i32 = unsafe{
        let mut x = Union {
            sival_int: 0,
        };
        x.sival_ptr = info.si_value().sival_ptr;
        x.sival_int
    };

    let d = (ipm.handler)();
    
    /// сделать обработку response
    let _res = ipm.response(&d, msgid);
    
    
}

fn get_ipm() -> Option<&'static mut InterProcMsg> {
    unsafe{
        IPM.as_mut()
    }
}

fn sig_init(sig: i32) -> usize {
    /// сделать обработку всех вызовов
    unsafe {
        let mut new_action: libc::sigaction = mem::zeroed();
        let mut old_action: libc::sigaction = mem::zeroed();
        
        new_action.sa_flags = libc::SA_SIGINFO;
        new_action.sa_sigaction = sig_handler as usize;
        libc::sigemptyset(&mut new_action.sa_mask as *mut libc::sigset_t);

        libc::sigaction(
            sig,
            &mut new_action as *mut libc::sigaction,
            &mut old_action as *mut libc::sigaction,
        );
        old_action.sa_sigaction
    }
}

pub struct InterProcMsg{
    pub handler : Box<dyn Fn() -> Vec<u8>>,
}


impl InterProcMsg{

    pub fn response(&self, data : &[u8], msgid : i32) -> Result<()> {
        
        let msg_type : i64 = 1;
        let msg_type = msg_type.to_be_bytes();
        let len = data.len();
        let len_head = mem::size_of::<i64>();
        
        let mut tmp : Vec<u8> = Vec::with_capacity(len_head+len);

        tmp.extend_from_slice(&msg_type);
        tmp.extend_from_slice(data);
        
        let status = unsafe{ libc::msgsnd(msgid, tmp.as_mut_ptr() as *mut libc::c_void, len, 0) };
        
        if status == -1 {
            return Err(Error::last_os_error());
        }
        
        return Ok(());
    }

    
    fn signal_to(pid : i32, code : i32) -> Result<()>{
        let sigval = unsafe{
            let x = Union {
                sival_int: code,
            };
            libc::sigval { sival_ptr: x.sival_ptr }
        };
        
        let status = unsafe{ sigqueue (pid, libc::SIGURG, sigval ) };
        
        if status == 0{
            return Ok(());
        }else{
            return Err(Error::last_os_error());
        }
        
    }
    
    pub fn request(&self, pid : i32) -> Result<Vec<u8>> {
                
        let msgid = unsafe{ libc::msgget(libc::IPC_PRIVATE, 0o666 | libc::IPC_CREAT) };
        
        if msgid == -1 {
            return Err(Error::last_os_error());
        }
        
        Self::signal_to(pid, msgid)?;
        
        let msgtype : i64 = 0;
        let mut data = [0u8; libc::BUFSIZ as usize];
        let len = unsafe{ libc::msgrcv(msgid, data.as_mut_ptr() as *mut libc::c_void, libc::BUFSIZ as usize, msgtype, 0) };
        
        if len == -1 {
            return Err(Error::last_os_error());
        }
        
        let status = unsafe{ libc::msgctl(msgid, libc::IPC_RMID, 0 as *mut libc::msqid_ds) };
        
        if status == -1 {
            return Err(Error::last_os_error());
        }
        
        let from : usize = 8;
        let to : usize = from+(len as usize);
        
        return Ok(data[from..to].to_vec());
        
    }

}

pub fn new<F: Fn() -> Vec<u8> + 'static>(fun: F) -> Option<&'static mut InterProcMsg>{
    
    if get_ipm().is_some() {
        return None;
    }
    
    unsafe{
        IPM = Some( InterProcMsg { 
            handler: Box::new(fun)
        } );
    }
    sig_init(libc::SIGURG);
    
    return get_ipm();
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    
    #[test]
    fn handler() {
        println!("Handler pid: {}", unsafe{ libc::getpid() });
        
        let x = move | | { 
            println!("Cloasure {}", 1); 
            
            let arr = [0u8, 1u8, 2u8];
            
            arr.to_vec()
        };
        
        let _ipm = new(x).unwrap();
        loop{
            thread::sleep( Duration::from_millis(1000) );
        }
    }
    
    #[test]
    fn request(){
        let mut args = std::env::args();
        
        let arg = match args.nth(3){
            Some(s) => s,
            None => {
                return
            }
        };
        
        let pid : i32 = arg.parse().unwrap();
        
        let x = || { Vec::<u8>::new() };
        let ipm = new(x).unwrap();
        
        let req = ipm.request(pid).unwrap();
        println!("Request: {:?}", req );
        
    }
}
