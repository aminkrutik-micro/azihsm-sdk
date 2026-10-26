// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Message index registry for the CP1 debug log.
//!
//! # Why indices start at 250 and count *down*
//!
//! Uno emits records under the same component ID as the reference CP
//! firmware (`ManticoreCp1`, `0xF5`). The host-side utility that reads
//! the debug log keys its lookup on `(component, msg_index)`, so it
//! will resolve any index we emit against the reference firmware's
//! token table — `cp/hsm/logging/log-tokens/src/hsm_log_tokens.rs`,
//! which maps a format string to an index.
//!
//! That table currently occupies **0..=179** (180 tokens). An index in
//! that range would therefore render as whatever reference message
//! happens to share the number, silently producing plausible but wrong
//! text. Indices from 180 up are unclaimed in the reference HSM table,
//! and the Admin table currently ends at 143.
//!
//! Allocating downward from 250 keeps the maximum distance from the
//! reference table's growth edge: the reference grows upward from 179,
//! Uno grows downward from 250, and the gap between them is the safety
//! margin. An index the decoder cannot resolve is shown as a raw
//! number, which is the intended outcome for Uno records.
//!
//! The SP itself performs no translation — it stores the record
//! verbatim and prints the raw fields:
//!
//! ```text
//! fmt: <f>, sev: <s>, comp: <c>
//! msg: <msg_index>, arg1: <arg1>, arg2: <arg2>
//! ```
//!
//! so this module is the authoritative decoder ring for Uno.
//!
//! # Rules
//!
//! * Allocate the next index by **decrementing** [`NEXT_FREE`].
//! * Never reuse an index for a new meaning — captures from older
//!   firmware would silently decode wrong.
//! * Document what `arg1` and `arg2` carry; they are the only payload.
//! * Stop before 180. Below that lies the reference token range.

/// Lowest index allocated or reserved so far. Allocate the next message at
/// `NEXT_FREE - 1` and update this constant.
///
/// Must stay above 179, the top of the reference firmware's HSM token
/// table.
// 228..=235 were emitted by earlier negative-validation images. This
// branch does not emit them, but must not reuse their indices.
pub const NEXT_FREE: u8 = 228;

/// Cryptographic algorithm self-test (CAST) events.
pub mod self_test {
    /// The pre-operational self-test suite started. No arguments.
    pub const PREOP_START: u8 = 249;

    /// The whole pre-operational suite passed. No arguments.
    pub const PREOP_PASS: u8 = 248;

    /// A pre-operational test failed and the suite stopped.
    ///
    /// * `arg1` — test id (`TEST_*`) in the low byte, PKA engine index above it.
    /// * `arg2` — `HsmError` code.
    pub const PREOP_FAIL: u8 = 247;

    /// One pre-operational test passed.
    ///
    /// * `arg1` — test id (`TEST_*`).
    /// * `arg2` — PKA engine index, or 0 for non-PKA tests.
    pub const PREOP_TEST_PASS: u8 = 246;

    /// A periodic test is about to run.
    ///
    /// * `arg1` — test id (`TEST_*`).
    /// * `arg2` — PKA engine index, or 0 for non-PKA tests.
    pub const PERIODIC_START: u8 = 245;

    /// The periodic test passed. Arguments as for [`PERIODIC_START`].
    pub const PERIODIC_PASS: u8 = 244;

    /// A periodic test failed; no further periodic tests run.
    ///
    /// * `arg1` — test id in the low byte, PKA engine index above it.
    /// * `arg2` — `HsmError` code.
    pub const PERIODIC_FAIL: u8 = 243;

    /// Every test of the periodic list has run once.
    ///
    /// * `arg1` — completed cycles since boot.
    pub const PERIODIC_CYCLE_DONE: u8 = 242;

    /// Periodic RNG test: Admin accepted the quiesce request, but may not
    /// have finished quiescing yet.
    ///
    /// * `arg1` — IPC status returned by Admin.
    pub const RNG_PREPARE_ACCEPTED: u8 = 241;

    /// Reserved for older builds that skipped the RNG KAT on Admin refusal.
    ///
    /// * `arg1` — last IPC status code from Admin.
    pub const RNG_SKIPPED: u8 = 240;

    /// Periodic RNG test finished and `Done` was sent to Admin.
    ///
    /// * `arg1` — IPC status returned by Admin.
    pub const RNG_ADMIN_DONE: u8 = 239;

    /// Admin has finished quiescing its RNG users.
    ///
    /// * `arg1` — IPC status returned by Admin.
    pub const RNG_ADMIN_READY: u8 = 238;

    /// Admin rejected a handshake request (Prepare, Status or Done).
    ///
    /// * `arg1` — IPC status returned by Admin.
    /// * `arg2` — the rejected request opcode.
    pub const RNG_ADMIN_REJECTED: u8 = 237;

    /// Admin did not answer a handshake request within one second, or the
    /// Status polling window expired.
    ///
    /// * `arg1` — the request opcode.
    /// * `arg2` — 1 when the whole Status window expired, else 0.
    pub const RNG_IPC_TIMEOUT: u8 = 236;

    pub const TEST_AES_CBC: u32 = 1;
    pub const TEST_AES_ECB: u32 = 2;
    pub const TEST_AES_KWP: u32 = 3;
    pub const TEST_HKDF: u32 = 4;
    pub const TEST_KBKDF: u32 = 5;
    pub const TEST_RSA_MOD_EXP: u32 = 6;
    pub const TEST_RSA_MOD_EXP_CRT: u32 = 7;
    pub const TEST_ECDH: u32 = 8;
    pub const TEST_ECDSA: u32 = 9;
    pub const TEST_RNG: u32 = 10;
}
