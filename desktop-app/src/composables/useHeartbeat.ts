/**
 * Single composable-agnostic renderer heartbeat (AUDIT F7).
 *
 * The legacy renderer ran THREE independent 2s intervals — the connection
 * status poller, the background settings sync, and the latency reset — each
 * invoking IPC and writing overlapping Vue refs with arbitrary phase offsets.
 * A settings tick could mark `isConnected=false`, fire
 * `triggerConnectionAttempt` (which writes the connection refs to "WAITING
 * FOR COMPANION") a moment before the connection poller read the real status,
 * producing yellow/green flicker and needless IPC volume (3× every 2s).
 *
 * This module owns exactly ONE interval. Every consumer subscribes its tick
 * function here instead of creating its own `setInterval`; the tick fires all
 * subscribers from the SAME macrotask, so the writes are aligned instead of
 * interleaved. The interval is started on first subscribe and stopped when the
 * last subscriber leaves, so an unmounted component never leaks a timer.
 *
 * The tick is kept at the same 2 s cadence the legacy timers used (the audit's
 * "1s" was illustrative — a faster tick would double IPC without fixing the
 * race; the fix is ALIGNMENT, not frequency).
 */
const TICK_MS = 2000;

// DOM/Node `setInterval` handle. Kept internal (not exported as a contract —
// consumers of `useHeartbeat` only ever see the `() => void` unsubscribe
// handle), so it stays portable across lib environments.
type HeartbeatTimer = ReturnType<typeof setInterval>;

type HeartbeatFn = () => void | Promise<void>;

const listeners = new Set<HeartbeatFn>();
let timer: HeartbeatTimer | null = null;

/// Subscribers whose previous tick has NOT completed yet (audit P2-2). The
/// legacy heartbeat fired every subscriber fire-and-forget, so an async tick
/// that took longer than `TICK_MS` (e.g. `useBackgroundSync.syncTick`'s
/// multi-IPC `triggerConnectionAttempt` during a QUIC reconnect) overlapped
/// the next tick — duplicate connection attempts, doubled IPC volume and
/// re-entrant writes to the same Vue refs (the yellow/green flicker the F7
/// alignment was meant to eliminate). A subscriber in flight is skipped on
/// later ticks until its promise settles, giving every subscriber a
/// single-flight guarantee.
const inFlight = new Set<HeartbeatFn>();

function tick() {
  // Snapshot so a subscriber that unsubscribes mid-tick cannot skip others.
  for (const fn of [...listeners]) {
    if (inFlight.has(fn)) {
      // Previous invocation still running — skip this tick (single-flight).
      continue;
    }
    inFlight.add(fn);
    try {
      // Fire-and-forget, like the legacy intervals: one slow IPC invoke must
      // not delay the other subscribers' ticks. The in-flight set clears when
      // the promise settles, so the NEXT tick after completion may fire again.
      Promise.resolve(fn())
        .catch((e) => console.error("Heartbeat tick failed:", e))
        .finally(() => inFlight.delete(fn));
    } catch (e) {
      console.error("Heartbeat tick failed:", e);
      inFlight.delete(fn);
    }
  }
}

function ensureStarted() {
  if (timer === null) {
    timer = setInterval(tick, TICK_MS);
  }
}

function maybeStopped() {
  if (listeners.size === 0 && timer !== null) {
    clearInterval(timer);
    timer = null;
  }
}

/**
 * Subscribe `fn` to the shared heartbeat. Returns an unsubscribe handle; the
 * caller owns the subscription's lifecycle (mirrors the old
 * startPolling/stopPolling pair). No Vue lifecycle hooks are registered here —
 * this is a plain module function so it can be called from onMounted and
 * event handlers, not just setup.
 */
export function useHeartbeat(fn: HeartbeatFn): () => void {
  listeners.add(fn);
  ensureStarted();
  return () => {
    listeners.delete(fn);
    maybeStopped();
  };
}
