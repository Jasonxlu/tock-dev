// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! This module contains the implementation of the `ExternalCall` struct, which
//! is used to handle external syscalls to other boards from the application side.

use crate::errorcode::ErrorCode;
use crate::hil::uart;
use crate::kernel::Kernel;
use crate::platform::chip::Chip;
use crate::platform::platform::KernelResources;
use crate::platform::platform::SyscallDriverLookup;
use crate::process::{Process, ProcessId};
use crate::syscall::Syscall;
use crate::syscall::SyscallReturn;
use crate::syscall_driver::CommandReturn;
use crate::utilities::cells::TakeCell;

/// This bool tracks whether there are any external calls pending for service.
static mut JOB_PENDING: bool = false;
/// This bool tracks whether a response has been received from the other board
/// and if we can send the next syscall
static mut SEND_TRANSMIT: bool = true;

/// ExternalCall struct
pub struct ExternalCall {
    _kernel: &'static Kernel,
    processid: ProcessId,
    uart: &'static dyn uart::UartData<'static>,
    tx_buffer: TakeCell<'static, [u8]>,
    rx_buffer: TakeCell<'static, [u8]>,
    curr_syscall: TakeCell<'static, [u8]>,
}

/// Implement the ExternalCall struct
impl ExternalCall {
    /// Create a new ExternalCall object.
    pub fn new(
        kernel: &'static Kernel,
        uart: &'static dyn uart::UartData,
        tx_buffer: &'static mut [u8],
        rx_buffer: &'static mut [u8],
        curr_syscall: &'static mut [u8],
    ) -> Self {
        // Create a unique identifier for the process
        let unique_identifier = kernel.create_process_identifier();

        // Create a dummy processid
        let processid = ProcessId::new(kernel, unique_identifier, 0);

        ExternalCall {
            _kernel: kernel,
            processid: processid,
            uart: uart,
            tx_buffer: TakeCell::new(tx_buffer),
            rx_buffer: TakeCell::new(rx_buffer),
            curr_syscall: TakeCell::new(curr_syscall),
        }
    }

    /// Start the transmission of the buffer.
    pub fn start_transmission(&self, buffer: &[u8]) -> Result<(), ErrorCode> {
        self.tx_buffer
            .take()
            .map_or(Err(ErrorCode::BUSY), |tx_buf| {
                for (i, c) in buffer.iter().enumerate() {
                    if i < tx_buf.len() {
                        tx_buf[i] = *c;
                    }
                }

                let len = tx_buf.len();
                let result = self.uart.transmit_buffer(tx_buf, len);
                match result {
                    Ok(()) => Ok(()),
                    Err((code, _buffer)) => Err(code),
                }
            })
    }

    /// Start the reception of the buffer.
    pub fn receive(&self) -> Result<(), ErrorCode> {
        self.rx_buffer
            .take()
            .map_or(Err(ErrorCode::ALREADY), |rx_buf| {
                let len = rx_buf.len();
                let result: Result<(), (ErrorCode, &mut [u8])> =
                    self.uart.receive_buffer(rx_buf, len);

                match result {
                    Ok(()) => Ok(()),
                    Err((code, _buffer)) => Err(code),
                }
            })
    }

    /// Set the 'JOB_PENDING' flag to true.
    pub fn set(&self) {
        unsafe {
            JOB_PENDING = true;
        }
    }

    /// Checks if the driver number is external or not.
    pub fn driver_num_is_external(&self, driver_num: usize) -> bool {
        if driver_num >> 31 == 1 {
            return true;
        } else {
            return false;
        }
    }

    /// Returns true if an external call is waiting to be serviced,
    /// false otherwise.
    pub fn has_tasks() -> bool {
        unsafe { JOB_PENDING }
    }

    /// Function to pack the syscall and send it
    /// Only sends the syscall if the SEND_TRANSMIT flag is set to true
    /// (When we receive a response from the other board)
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

            let send_transmit = unsafe { SEND_TRANSMIT };

            if send_transmit {
                let _ = self.start_transmission(&buffer);
            }

            unsafe {
                SEND_TRANSMIT = false;
            }
        }
    }

    /// Function to unpack the bytes received from the other board
    /// into a Syscall
    pub fn unpack_bytes(&self) -> Result<Syscall, ErrorCode> {
        self.curr_syscall.map_or(Err(ErrorCode::INVAL), |rx_buf| {
            let mut driver_number: usize = 0;
            for i in 1..5 {
                driver_number = driver_number << 8;
                driver_number = driver_number | rx_buf[i] as *const u8 as usize;
            }

            let mut subdriver_number: usize = 0;
            for i in 5..9 {
                subdriver_number = subdriver_number << 8;
                subdriver_number = subdriver_number | rx_buf[i] as *const u8 as usize;
            }

            let mut arg0: usize = 0;
            for i in 9..13 {
                arg0 = arg0 << 8;
                arg0 = arg0 | rx_buf[i] as *const u8 as usize;
            }

            let mut arg1: usize = 0;
            for i in 13..17 {
                arg1 = arg1 << 8;
                arg1 = arg1 | rx_buf[i] as *const u8 as usize;
            }

            Ok(Syscall::Command {
                driver_number,
                subdriver_number,
                arg0,
                arg1,
            })
        })
    }

    /// Services and clears the pending External Syscall, if any.
    pub fn service_next_pending<KR: KernelResources<C>, C: Chip>(&self, resources: &KR) {
        let job = unsafe { JOB_PENDING };
        if job {
            unsafe {
                JOB_PENDING = false;
            }

            let syscall = self.unpack_bytes().unwrap();

            self.handle_external_syscall::<_, _>(resources, self.processid, syscall);
        }
    }

    /// Function to handle external syscalls from the other board
    /// and call the appropriate driver
    pub fn handle_external_syscall<KR: KernelResources<C>, C: Chip>(
        &self,
        resources: &KR,
        processid: ProcessId,
        syscall: Syscall,
    ) {
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

                    let _res = SyscallReturn::from_command_return(cres);

                    let mut return_buffer: [u8; 17] = [0; 17];
                    return_buffer[0] = 2;

                    let _ = self.start_transmission(&return_buffer);
                });
        }
    }
}

/// Implement the TransmitClient and ReceiveClient for ExternalCall
impl uart::TransmitClient for ExternalCall {
    fn transmitted_buffer(
        &self,
        buffer: &'static mut [u8],
        _tx_len: usize,
        _rval: Result<(), ErrorCode>,
    ) {
        self.tx_buffer.replace(buffer);
        let _result = self.receive();
    }
    fn transmitted_word(&self, _rval: Result<(), ErrorCode>) {}
}

impl uart::ReceiveClient for ExternalCall {
    fn received_buffer(
        &self,
        buffer: &'static mut [u8],
        _rx_len: usize,
        _rcode: Result<(), ErrorCode>,
        _error: uart::Error,
    ) {
        let id = buffer[0];

        self.curr_syscall.map(|curr_sys| {
            for (i, c) in buffer.iter().enumerate() {
                if i < curr_sys.len() {
                    curr_sys[i] = *c;
                }
            }
        });
    }

    fn received_word(&self, _word: u32, _rval: Result<(), ErrorCode>, _error: uart::Error) {}
}
