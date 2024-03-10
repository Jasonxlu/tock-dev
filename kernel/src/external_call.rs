use crate::platform::chip::Chip;
use crate::platform::platform::KernelResources;
use crate::process::{self, Process, ProcessId, ShortID, Task};
use crate::syscall::Syscall;

use crate::syscall::{ContextSwitchReason, SyscallReturn};

use crate::debug;

use crate::errorcode::ErrorCode;

use crate::platform::platform::{ProcessFault, SyscallDriverLookup, SyscallFilter};

use crate::syscall::SyscallDriver;

use crate::syscall_driver::CommandReturn;

use crate::hil::uart; // import uart
use crate::utilities::cells::{MapCell, TakeCell};

// import the kernel
use crate::kernel::Kernel;

/// This bool tracks whether there are any external calls pending for service.
static mut JOB_PENDING: bool = false;

pub struct ExternalCall {
    kernel: &'static Kernel,
    processid: ProcessId,

    //TODO:: buffer
    uart: &'static dyn uart::UartData<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    rx_buffer: TakeCell<'static, [u8]>,
}

impl ExternalCall {
    /// Creates a new deferred call with a unique ID.
    pub fn new(
        kernel: &'static Kernel,
        uart: &'static dyn uart::UartData,
        tx_buffer: &'static mut [u8],
        rx_buffer: &'static mut [u8],
    ) -> Self {
        // SAFETY: No accesses to CTR are via an &mut, and the Tock kernel is
        // single-threaded so all accesses will occur from this thread.

        let unique_identifier = kernel.create_process_identifier();

        // Create a dummy processid //TODO: Unsure about what to put for index
        let processid = ProcessId::new(kernel, unique_identifier, 0);

        ExternalCall {
            kernel: kernel,
            processid: processid,
            uart: uart,
            tx_buffer: TakeCell::new(tx_buffer),
            rx_buffer: TakeCell::new(rx_buffer),
        }
    }

    // ExternalCall.start_transmission()
    pub fn start_transmission(&self, buffer: &[u8]) -> Result<(), ErrorCode> {
        debug!("Started transmission");
        self.tx_buffer
            .take()
            .map_or(Err(ErrorCode::BUSY), |tx_buf| {
                for (i, c) in buffer.iter().enumerate() {
                    if i < tx_buf.len() {
                        tx_buf[i] = *c;
                    } else {
                        debug!("buffer too big");
                    }
                }
                // let copy_len = dest.len().max(len);

                // dest[0..copy_len].copy_from_slice(&buffer[0..copy_len]);
                // }
                let len = tx_buf.len();
                let result = self.uart.transmit_buffer(tx_buf, len);
                match result {
                    Ok(()) => Ok(()),
                    Err((code, buffer)) => {
                        // self.tx_buffer.replace(buffer);
                        Err(code)
                    }
                }
            })
    }

    // ExternalCall.receive(&self)
    pub fn receive(&self) -> Result<(), ErrorCode> {
        debug!("Started reception");
        let job = unsafe { JOB_PENDING };

        if (job) {
            debug!("job is occurring right now");
            Ok(())
        } else {
            self.rx_buffer
                .take()
                .map_or(Err(ErrorCode::ALREADY), |rx_buf| {
                    let len = rx_buf.len();
                    let result: Result<(), (ErrorCode, &mut [u8])> =
                        self.uart.receive_buffer(rx_buf, len);
                    match result {
                        Ok(()) => Ok(()),
                        Err((code, buffer)) => {
                            debug!("something went wrong");
                            // self.rx_buffer.replace(buffer);
                            Err(code)
                        }
                    }
                })
        }
    }

    /// Schedule a deferred callback on the client associated with this deferred call
    pub fn set(&self) {
        // SAFETY: No accesses to BITMASK are via an &mut, and the Tock kernel is
        // single-threaded so all accesses will occur from this thread.
        unsafe {
            JOB_PENDING = true;
        }
    }

    pub fn driver_num_is_external(&self, driver_num: usize) -> bool {
        if driver_num >> 31 == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Returns true if any deferred calls are waiting to be serviced,
    /// false otherwise.
    pub fn has_tasks() -> bool {
        // SAFETY: No accesses to BITMASK are via an &mut, and the Tock kernel is
        // single-threaded so all accesses will occur from this thread.
        unsafe { JOB_PENDING }
    }

    // Return an array of u8 that represents the syscall
    pub fn pack_syscall_and_send(&self, syscall: Syscall) {
        if let Syscall::Command {
            driver_number,
            subdriver_number,
            arg0,
            arg1,
        } = syscall
        {
            let mut buffer: [u8; 17] = [0; 17];
            buffer[0] = 1; // Set the first byte to 1 to indicate that it is a syscall
            buffer[1] = (driver_number >> 24) as u8 & 0b01111111;
            buffer[2] = (driver_number >> 16) as u8;
            buffer[3] = (driver_number >> 8) as u8;
            buffer[4] = driver_number as u8;
            buffer[5] = (subdriver_number >> 24) as u8;
            buffer[6] = (subdriver_number >> 16) as u8;
            buffer[7] = (subdriver_number >> 8) as u8;
            buffer[8] = subdriver_number as u8;
            buffer[9] = (arg0 >> 24) as u8;
            buffer[10] = (arg0 >> 16) as u8;
            buffer[11] = (arg0 >> 8) as u8;
            buffer[12] = arg0 as u8;
            buffer[13] = (arg1 >> 24) as u8;
            buffer[14] = (arg1 >> 16) as u8;
            buffer[15] = (arg1 >> 8) as u8;
            buffer[16] = arg1 as u8;

            //TODO: Send the syscall using Uart
            debug!("Sent a syscall");
            self.start_transmission(&buffer);
        }
    }

    pub fn unpack_bytes(&self) -> Result<Syscall, ErrorCode> {
        debug!("started unpacking");
        self.rx_buffer
            .take()
            .map_or(Err(ErrorCode::INVAL), |rx_buf| {
                let mut driver_number: usize = 0;
                for i in 1..5 {
                    driver_number = driver_number << 8;
                    driver_number = driver_number | rx_buf[i] as *const u8 as usize;
                }
                debug!("This is the driver_number {}", driver_number);

                let mut subdriver_number: usize = 0;
                for i in 5..9 {
                    subdriver_number = subdriver_number << 8;
                    subdriver_number = subdriver_number | rx_buf[i] as *const u8 as usize;
                }
                debug!("This is the subdriver number {}", subdriver_number);

                let mut arg0: usize = 0;
                for i in 9..13 {
                    arg0 = arg0 << 8;
                    arg0 = arg0 | rx_buf[i] as *const u8 as usize;
                }

                debug!("This is the arg0 {}", arg0);

                let mut arg1: usize = 0;
                for i in 13..17 {
                    arg1 = arg1 << 8;
                    arg1 = arg1 | rx_buf[i] as *const u8 as usize;
                }
                debug!("This is arg1 {}", arg1);

                Ok(Syscall::Command {
                    driver_number,
                    subdriver_number,
                    arg0,
                    arg1,
                })
            })
    }

    /// Services and clears the next pending `DeferredCall`, returns which index
    /// was serviced
    pub fn service_next_pending<KR: KernelResources<C>, C: Chip>(&self, resources: &KR) {
        // SAFETY: No accesses to BITMASK/DEFCALLS are via an &mut, and the Tock kernel is
        // single-threaded so all accesses will occur from this thread.
        let job = unsafe { JOB_PENDING };
        if job {
            unsafe {
                JOB_PENDING = false;
            }

            let syscall = self.unpack_bytes().unwrap(); // Unwrap the Result twice to get the Syscall value

            self.handle_external_syscall::<_, _>(resources, self.processid, syscall);
        }
    }
    // Function to handle external syscalls and process them
    pub fn handle_external_syscall<KR: KernelResources<C>, C: Chip>(
        &self,
        resources: &KR,
        // process: &dyn process::Process,
        processid: ProcessId,
        syscall: Syscall,
    ) {
        // Hook for process debugging.
        // process.debug_syscall_called(syscall); // TODO:: << Figure out what to do about process here

        // Handles only the `Command` syscall
        if let Syscall::Command {
            driver_number,
            subdriver_number,
            arg0,
            arg1,
        } = syscall
        {
            resources
                .syscall_driver_lookup()
                .with_driver(driver_number, |driver| {
                    let cres = match driver {
                        Some(d) => d.command(subdriver_number, arg0, arg1, processid),
                        None => CommandReturn::failure(ErrorCode::NODEVICE),
                    };

                    let res = SyscallReturn::from_command_return(cres);

                    let mut return_buffer: [u8; 17] = [0; 17];
                    return_buffer[0] = 2;

                    debug!("Sent a response");

                    self.start_transmission(&return_buffer); // TODO: << Figure out what to do about process here
                });
        }
    }
}

impl uart::TransmitClient for ExternalCall {
    fn transmitted_buffer(
        &self,
        buffer: &'static mut [u8],
        tx_len: usize,
        rval: Result<(), ErrorCode>,
    ) {
        debug!("Completed transmission");
        self.tx_buffer.replace(buffer);

        // // for pong: call self.receive()
        debug!("Calling reception from tx callback");
        let result = self.receive();

        // if let Err(code) = result {
        //     debug!("{:?}", code);
        // }
    }
    fn transmitted_word(&self, _rval: Result<(), ErrorCode>) {}
}

impl uart::ReceiveClient for ExternalCall {
    fn received_buffer(
        &self,
        buffer: &'static mut [u8],
        rx_len: usize,
        rcode: Result<(), ErrorCode>,
        error: uart::Error,
    ) {
        // debug!("{}", buffer[0]);

        // // Print out what was received in transmission
        // buffer[0] += 1; // Increment the 0th value of the buffer for pong
        //                 // self.send(buffer);

        // let mut new_buffer: [u8; 17] = [0; 17];

        // for (i, c) in buffer.iter().enumerate() {
        //     new_buffer[i] = *c;
        // }

        // NEW STUFF:
        // - Check to see if the first byte of the rx_buffer is going to be a
        // syscall

        debug!("Completed reception");
        let id = buffer[0];
        debug!("{}", id);

        self.rx_buffer.replace(buffer);

        if id == 2 {
            debug!("{}", id);
        } else if id == 1 {
            self.set();
        }
        // self.rx_buffer.replace(new_buffer);
        // Copy the contents of the original buffer into the new buffer

        let receive_result = self.receive();

        match receive_result {
            Ok(()) => {
                debug!("Reception completed");
            }
            Err(code) => {
                debug!("{:?}", code);
            }
        }

        // let transmission_result: Result<(), ErrorCode> = self.start_transmission(&new_buffer);
        // if let Err(code) = transmission_result {
        //     debug!("{:?}", code);
        // } else {
        //     debug!("transmit complete");
        // }
        // check result/error code
    }

    fn received_word(&self, _word: u32, _rval: Result<(), ErrorCode>, _error: uart::Error) {}
}
