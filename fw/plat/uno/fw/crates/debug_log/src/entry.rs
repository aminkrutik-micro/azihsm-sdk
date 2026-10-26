// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A single debug log record.
//!
//! The layout matches the Cerberus C struct `debug_log_entry_parameters`
//! and the reference CP firmware's `mcr_types::DebugLogEntryParameters`
//! byte for byte. The SP decodes records using that shared definition,
//! so the field order and widths here are a cross-processor contract.

/// Severity of a debug log record.
///
/// Must match the Cerberus `debug_log_severity` C enumeration.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DebugLogSeverity {
    /// Error severity.
    Error = 0,

    /// Warning severity.
    Warning = 1,

    /// Informational severity.
    Info = 2,
}

/// Originating component of a debug log record.
///
/// Must match the Cerberus `debug_log_component` C enumeration. Device
/// specific component IDs start at `0xF0`; only the variants relevant
/// to this firmware are defined here.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DebugLogComponent {
    /// Manticore CP Admin firmware messages.
    ManticoreCp0 = 0xF4,

    /// Manticore CP HSM firmware messages. This is the component the
    /// Uno firmware logs under, since Uno runs on the HSM core.
    ManticoreCp1 = 0xF5,
}

/// A 12-byte debug log record.
///
/// Records carry a message *index* rather than a formatted string. The
/// SP stores the index verbatim and prints it as a raw number, while
/// the host-side reader resolves `(component, msg_index)` against the
/// reference firmware's token table. Uno therefore allocates indices
/// from a range that table does not use; see [`crate::msg`], which is
/// the registry giving each index its meaning.
///
/// Tokenising this way keeps the on-device cost to a few stores and
/// avoids pulling string formatting into the firmware image.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DebugLogEntry {
    /// Record severity.
    pub severity: DebugLogSeverity,

    /// Originating component.
    pub component: DebugLogComponent,

    /// Component-scoped message index.
    pub msg_index: u8,

    /// Reserved; always zero.
    pub reserved: u8,

    /// First message argument.
    pub arg1: u32,

    /// Second message argument.
    pub arg2: u32,
}

impl DebugLogEntry {
    /// Number of 32-bit words in a record.
    pub const DWORDS: usize = 3;

    /// Creates a record for the Uno HSM core (`ManticoreCp1`).
    pub const fn new(severity: DebugLogSeverity, msg_index: u8, arg1: u32, arg2: u32) -> Self {
        Self {
            severity,
            component: DebugLogComponent::ManticoreCp1,
            msg_index,
            reserved: 0,
            arg1,
            arg2,
        }
    }

    /// Packs the record into the three 32-bit words written to GSRAM.
    ///
    /// The header word is assembled explicitly rather than by
    /// transmuting the struct, so the wire layout stays correct
    /// regardless of how the compiler lays out the Rust type.
    pub const fn to_dwords(self) -> [u32; Self::DWORDS] {
        let header = (self.severity as u32)
            | ((self.component as u32) << 8)
            | ((self.msg_index as u32) << 16)
            | ((self.reserved as u32) << 24);

        [header, self.arg1, self.arg2]
    }
}
