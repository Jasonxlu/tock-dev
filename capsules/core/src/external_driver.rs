// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! Provides a basic SyscallDriver implementation to demonstrate a simple operation.
//!
//! The `LifeDriver` serves as a SyscallDriver that provides a few commands related to the meaning
//! of life. This driver does not interact with any specific hardware device; instead, it offers
//! a simple example to illustrate how a SyscallDriver can handle commands and return appropriate
//! responses or errors.
//!
//! Usage
//! -----
//!
//! Since the `LifeDriver` is a test/demo driver, it does not require specific initialization
//! or configuration. You can simply use it as-is to handle commands related to the meaning of life.
//!
//! Syscall Interface
//! -----------------
//!
//! - Stability: 1 - Unstable
//!
//! ### Commands
//!
//! All operations provided by the `LifeDriver` are synchronous and utilize the `command` syscall.
//!
//! #### `command_num`
//!
//! - `0`: Retrieve the meaning of life.
//!   - `data`: Unused.
//!   - Return: The meaning of life (42) as a `u32`.
//! - `1`: Check if the provided data is the meaning of life.
//!   - `data`: The value to check against the meaning of life (42).
//!   - Return: `Ok(())` if the data matches 42; otherwise, returns `INVAL` error code.
//!
//! Example
//! -------
//!
//! ```rust
//! // Instantiate the LifeDriver
//! let life_driver = capsules::life::LifeDriver::new();
//!
//! // Use the driver to get the meaning of life
//! let result = life_driver.command(0, 0, 0, ProcessId::new(0)); // This should return 42 as a u32
//!
//! // Check if a value is the meaning of life
//! let check_result = life_driver.command(1, 42, 0, ProcessId::new(0)); // This should return Ok(())
//! ```

//TODO - Add lifetimes
//TODO - Custom data structure
//TODO - Change doc comments

use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
pub const LIFE: usize = 42;
pub const MAXDRIVERS: usize = 100;

/// Implements a basic SyscallDriver without any specific device management.
pub struct ExternalDriver {
    external_drivers: [(u32, Option<&'static dyn SyscallDriver>); MAXDRIVERS],
    count: usize,
}

impl ExternalDriver {
    pub fn new() -> Self {
        // Initialization logic can be added if needed in the future.
        Self {
            external_drivers: [(0x80000000, None); MAXDRIVERS],
            count: MAXDRIVERS,
        }
    }

    pub fn add_driver(&mut self, driver_num: u32, driver: &'static dyn SyscallDriver) {
        if self.count < 10 {
            self.external_drivers[self.count] = (driver_num, Some(driver));
            self.count += 1;
        }
    }

    pub fn get_driver(&self, driver_num: u32) -> Option<&'static (dyn SyscallDriver + 'static)> {
        for i in 0..self.count {
            if self.external_drivers[i].0 == driver_num {
                return self.external_drivers[i].1;
            }
        }
        None
    }

    pub fn find_driver(&self, driver_num: u32) -> u32 {
        for i in 0..self.count {
            if self.external_drivers[i].0 == driver_num {
                return self.external_drivers[i].0;
            }
        }
        0
    }

    pub fn remove_driver(&mut self, driver_num: u32) {
        for i in 0..self.count {
            if self.external_drivers[i].0 == driver_num {
                self.external_drivers[i] = (0, None);
                self.count -= 1;
                break;
            }
        }
    }
}

impl SyscallDriver for ExternalDriver {
    /// Return the meaning of life
    ///
    /// ### `command_num`
    ///
    /// - `0`: Returns the meaning of life (42) as a u32. This is a simple
    ///        example of a command that returns data.
    /// - `1`: Returns a failure code if the data is not 42. This is a simple
    ///        example of a command that returns a failure code.
    ///
    fn command(&self, command_num: usize, data: usize, _: usize, _: ProcessId) -> CommandReturn {
        match command_num {
            // return the meaning of life
            0 => CommandReturn::success_u32(LIFE as u32),

            // return a failure code if the data is not 42
            1 => {
                if data != LIFE {
                    CommandReturn::failure(ErrorCode::INVAL) /* data is not life */
                } else {
                    CommandReturn::success()
                }
            }

            // default
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, _processid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
