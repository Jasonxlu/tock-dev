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

// import the kernel
use crate::kernel::Kernel;

/// This bool tracks whether there are any external calls pending for service.
static mut JOB_PENDING: bool = false;

pub struct ExternalCall {
    kernel: &'static Kernel,
    processid: ProcessId,
    //TODO:: buffer
}

impl ExternalCall {
    /// Creates a new deferred call with a unique ID.
    pub fn new(kernel: &'static Kernel) -> Self {
        // SAFETY: No accesses to CTR are via an &mut, and the Tock kernel is
        // single-threaded so all accesses will occur from this thread.

        let unique_identifier = kernel.create_process_identifier();

        // Create a dummy processid //TODO: Unsure about what to put for index
        let processid = ProcessId::new(kernel, unique_identifier, 0);

        ExternalCall {
            kernel: kernel,
            processid: processid,
        }
    }

    /// Schedule a deferred callback on the client associated with this deferred call
    pub fn set() {
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
            let mut syscall_bytes = [0; 4];
            syscall_bytes[0] = (driver_number >> 24) as u8;
            syscall_bytes[1] = (subdriver_number >> 16) as u8;
            syscall_bytes[2] = (arg0 >> 8) as u8;
            syscall_bytes[3] = arg1 as u8;

            // TODO: Send the syscall using Uart
        }
    }

    pub fn unpack_syscall(&self, syscall_bytes: [u8; 4]) -> Syscall {
        let driver_number = (syscall_bytes[0] as usize) << 24;
        let subdriver_number = (syscall_bytes[1] as usize) << 16;
        let arg0 = (syscall_bytes[2] as usize) << 8;
        let arg1 = syscall_bytes[3] as usize;

        let syscall = Syscall::Command {
            driver_number,
            subdriver_number,
            arg0,
            arg1,
        };

        return syscall;
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

            // Dummy syscall values
            let driver_number = 2;
            let subdriver_number = 1;
            let arg0 = 1;
            let arg1 = 0;

            // Creating a syscall of type "command"
            let syscall = Syscall::Command {
                driver_number,
                subdriver_number,
                arg0,
                arg1,
            };

            handle_external_syscall::<_, _>(resources, self.processid, syscall);
        }
    }
}

// Function to handle external syscalls and process them
pub fn handle_external_syscall<KR: KernelResources<C>, C: Chip>(
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
                // process.set_syscall_return_value(res); // TODO: << Figure out what to do about process here
            });
    }
}
