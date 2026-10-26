// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
//! CP1 debug log — the blade-observable logging path for Uno firmware.
//!
//! Uno's existing trace backends (semihosting and UART) both require
//! physical or emulator access to the part, so neither is usable on a
//! production blade. This crate fills that gap: it writes structured
//! records into a GSRAM ring that the SP already drains, folds into its
//! own debug log, and flushes to flash for `debuglogread` retrieval.
//!
//! Records are *tokenised* rather than formatted. Each one carries a
//! component-scoped message index plus two `u32` arguments. The SP records
//! raw indices; host-side tooling resolves known indices. This keeps the
//! on-device cost to a handful of stores, which matters for two reasons: it avoids
//! pulling string formatting (and its roughly 43 KB of `.text`) into an
//! image that is already tight, and it is light enough to use on hot
//! paths without perturbing the timing of the very races it is meant to
//! diagnose.
//!
//! The ring layout and base address are a cross-processor contract with
//! the SP; see `rdl/soc/debug_log.rdl` for the full description.
//!
//! # Example
//!
//! ```ignore
//! DebugLogSender::init();
//! DebugLogSender::send(DebugLogEntry::new(
//!     DebugLogSeverity::Info, msg::self_test::PREOP_START, 0, 0,
//! ));
//! ```

mod entry;
mod sender;

pub mod msg;

pub use entry::DebugLogComponent;
pub use entry::DebugLogEntry;
pub use entry::DebugLogSeverity;
pub use sender::DebugLogSender;
