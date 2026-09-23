//! Deterministic random number generator (SplitMix64). The same seed gives the same sequence, so runs are repeatable.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns a number in `low..=high`.
    pub fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    /// Returns true with the given probability.
    pub fn chance(&mut self, probability: f64) -> bool {
        (self.next() as f64 / u64::MAX as f64) < probability
    }
}
