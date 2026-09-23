//! Functions that differ between native targets and the browser: the clock and sleeping.

use std::time::Duration;

/// Point in time, used for deadlines and for measuring durations.
///
/// Monotonic on all targets. In a browser it uses `performance.now()`. The wall clock (`Date.now()`) is unsuitable:
/// it can be set backwards, and its resolution of one millisecond is too coarse to time a commit to a nearby server.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub(crate) struct Moment(f64);

impl Moment {
    pub fn now() -> Moment {
        Moment(millis_since_start())
    }

    /// Time since this moment. Zero if the moment is in the future.
    pub fn elapsed(self) -> Duration {
        Moment::now().since(self)
    }

    /// Time from `earlier` to this moment. Zero if `earlier` is later.
    pub fn since(self, earlier: Moment) -> Duration {
        Duration::from_secs_f64(((self.0 - earlier.0) / 1000.0).max(0.0))
    }

    pub fn plus(self, dur: Duration) -> Moment {
        Moment(self.0 + dur.as_secs_f64() * 1000.0)
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Reference point for `Moment`, set on first use. Counting milliseconds from it lets `Moment` be a plain `f64` on
    /// every target.
    fn start() -> Instant {
        use std::sync::OnceLock;
        static START: OnceLock<Instant> = OnceLock::new();
        *START.get_or_init(Instant::now)
    }

    pub(super) fn millis_since_start() -> f64 {
        start().elapsed().as_secs_f64() * 1000.0
    }

    pub(crate) fn epoch_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }

    pub(crate) fn sleep(dur: Duration) {
        std::thread::sleep(dur);
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::time::Duration;

    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen]
    extern "C" {
        /// `performance.now()`, available in workers and on pages. Values are relative to the start of the worker or
        /// page and are only comparable within it. `Moment` values never leave the SQLite worker.
        #[wasm_bindgen(js_namespace = performance, js_name = now)]
        fn performance_now() -> f64;
    }

    pub(super) fn millis_since_start() -> f64 {
        performance_now()
    }

    pub(crate) fn epoch_millis() -> i64 {
        js_sys::Date::now() as i64
    }

    /// Does nothing. SQLite calls this only while waiting for a lock, which cannot happen with one connection per
    /// database. Busy-waiting instead would freeze the worker.
    pub(crate) fn sleep(_dur: Duration) {}
}

use imp::millis_since_start;
pub(crate) use imp::{epoch_millis, sleep};
