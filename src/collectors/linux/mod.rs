//! Linux collectors. Each one reads files under a `root` (`/` for the live system),
//! so the tests run against fixture trees and a mounted image can be inspected too.
//! They are compiled on every platform so their parsing is unit-tested everywhere,
//! but only wired into `asa collect` on Linux.

pub mod accounts;
pub mod ports;
pub mod systemd;
