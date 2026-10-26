// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM ring buffer producer for the CP1 debug log.
//!
//! The HSM writes records into a fixed GSRAM ring; the SP drains it,
//! folds the records into its own debug log, and flushes them to flash.
//! This is the only logging path observable on a production blade — the
//! semihosting and UART trace backends both need physical or emulator
//! access to the part.
//!
//! The protocol mirrors the reference CP firmware's `SimplexPipe`:
//!
//! * The HSM owns the producer index (`TAIL`/PI) and advances it after
//!   writing a record.
//! * The SP owns the consumer index (`HEAD`/CI) and advances it after
//!   reading a record.
//! * The ring is full when `next_pi == ci`, so one slot is always left
//!   unused to keep the empty and full states distinguishable.
//! * A `DMB` between the record write and the PI advance guarantees the
//!   SP observes a complete record before it observes the new index.
//!
//! All state lives in GSRAM at addresses fixed by `debug_log.rdl`, so
//! the sender itself is stateless and needs no allocation.

use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::debug_log::regs::DebugLogRegs;
use azihsm_fw_uno_reg_soc::debug_log::DEBUG_LOG_BASE;
use azihsm_fw_uno_reg_soc::debug_log::QUEUE_COUNT;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::DebugLogEntry;

/// MMIO overlay for the debug log ring in GSRAM.
#[allow(unsafe_code)]
const REGS: StaticRef<DebugLogRegs> =
    // SAFETY: Reinterpreting a fixed GSRAM address as a register block.
    // The address and layout are generated from `debug_log.rdl`, and the
    // region is reserved for this ring alone, so the overlay cannot alias
    // any other object.
    unsafe { StaticRef::new(DEBUG_LOG_BASE as *const DebugLogRegs) };

/// Ring depth in records. Fixed at 170 by the SP collector, which is
/// built with `CP_LOG_COLLECTOR_EXPECTED_RECORDS = 170`.
const RING_DEPTH: u32 = QUEUE_COUNT;

fn next_index(pi: u32, ci: u32) -> Option<u32> {
    let next = if pi + 1 >= RING_DEPTH { 0 } else { pi + 1 };
    (next != ci).then_some(next)
}

fn increment_overflows(count: u32) -> u32 {
    count.wrapping_add(1)
}

/// Producer for the CP1 debug log ring.
///
/// Stateless: every index and counter lives in GSRAM so that the SP can
/// observe them directly, and so the ring survives a CP reset.
#[derive(Clone, Copy, Debug)]
pub struct DebugLogSender;

impl DebugLogSender {
    /// Initialises the ring metadata. Must be called once, before the
    /// first [`DebugLogSender::send`].
    ///
    /// Both indices are reset so the ring starts empty. Resetting the
    /// consumer index is deliberate even though the SP owns it: after a
    /// CP reset the SP keeps running and its index would otherwise
    /// still refer to records from the previous boot, making the ring
    /// look partly full of stale data. Publishing a matching pair of
    /// zeroes gives both sides a clean slate.
    ///
    /// There is a narrow window here where the SP may observe a
    /// mismatched index pair and drain a few stale records. That is
    /// harmless — it can only produce spurious log output at boot — and
    /// it is the same trade-off the reference firmware makes.
    ///
    /// `ring_buffer_size` is published last so the depth is visible
    /// only once the indices are consistent.
    pub fn init() {
        REGS.ring_buffer_head.set(0);
        REGS.ring_buffer_tail.set(0);
        REGS.sender_overflows.set(0);

        cortex_m::asm::dmb();

        REGS.ring_buffer_size.set(RING_DEPTH);
    }

    /// Writes a record to the ring.
    ///
    /// Returns `true` if the record was stored, or `false` if the ring
    /// was full, in which case the record is dropped and the overflow
    /// counter is incremented.
    ///
    /// This never blocks and never panics, so it is safe to call from
    /// an interrupt handler or a fault path.
    pub fn send(entry: DebugLogEntry) -> bool {
        // A corrupt or uninitialised producer index would otherwise
        // index past the end of the ring and scribble over neighbouring
        // GSRAM, so fold anything out of range back to the start.
        let pi = match REGS.ring_buffer_tail.get() {
            pi if pi < RING_DEPTH => pi,
            _ => 0,
        };
        let ci = REGS.ring_buffer_head.get();

        let Some(next_pi) = next_index(pi, ci) else {
            let overflows = REGS.sender_overflows.get();
            REGS.sender_overflows.set(increment_overflows(overflows));

            return false;
        };

        let dwords = entry.to_dwords();
        let slot = &REGS.queue[pi as usize];
        slot.header.set(dwords[0]);
        slot.arg1.set(dwords[1]);
        slot.arg2.set(dwords[2]);

        // Publish the record before the index that makes it visible.
        cortex_m::asm::dmb();

        REGS.ring_buffer_tail.set(next_pi);

        true
    }

    /// Number of records dropped because the ring was full.
    ///
    /// A non-zero value means the SP is not draining fast enough and
    /// log records have been lost.
    pub fn overflows() -> u32 {
        REGS.sender_overflows.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_ring_drops_and_resumes_after_consumer_progress() {
        let mut pi = 0;
        let mut overflows = 0;

        for _ in 0..RING_DEPTH - 1 {
            pi = next_index(pi, 0).expect("ring has a free slot");
        }
        assert_eq!(pi, RING_DEPTH - 1);

        if next_index(pi, 0).is_none() {
            overflows = increment_overflows(overflows);
        }
        assert_eq!(pi, RING_DEPTH - 1);
        assert_eq!(overflows, 1);

        pi = next_index(pi, 1).expect("consumer freed a slot");
        assert_eq!(pi, 0);
        assert!(next_index(pi, 1).is_none());
        assert_eq!(increment_overflows(u32::MAX), 0);
    }
}
