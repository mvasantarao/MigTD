// Copyright (c) 2026 Microsoft Corporation
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Explicit random services. Provider selection is not operation/retry authority.

use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    Unavailable,
}

/// A trusted composition-selected source, never a host-proposed seed.
/// Each invocation requests a new independent final 32-byte value.
/// Scripted test sources cannot be selected by deployed consumers.
///
/// ```compile_fail
/// use pal::random::DeterministicRandomSource;
/// ```
pub trait RandomSource {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), RandomError>;
}

pub struct UnavailableRandomSource;

impl RandomSource for UnavailableRandomSource {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), RandomError> {
        output.zeroize();
        log::error!("random service unavailable");
        Err(RandomError::Unavailable)
    }
}

/// Uses ring's operating-system CSPRNG on Linux, including the musl target.
/// Enabling this capability does not select a production SNP composition.
#[cfg(feature = "system-random")]
pub struct SystemRandomSource(ring::rand::SystemRandom);

#[cfg(feature = "system-random")]
impl Default for SystemRandomSource {
    fn default() -> Self {
        Self(ring::rand::SystemRandom::new())
    }
}

#[cfg(feature = "system-random")]
impl RandomSource for SystemRandomSource {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), RandomError> {
        use ring::rand::SecureRandom;
        fill_checked(output, |bytes| {
            self.0.fill(bytes).map_err(|_| RandomError::Unavailable)
        })
    }
}

#[cfg(any(feature = "system-random", test))]
fn fill_checked(
    output: &mut [u8; 32],
    fill: impl FnOnce(&mut [u8; 32]) -> Result<(), RandomError>,
) -> Result<(), RandomError> {
    output.zeroize();
    let mut staged = Secret32::zeroed();
    fill(staged.as_mut()).inspect_err(|error| {
        log::error!("random32 generation failed: {error:?}");
    })?;
    output.copy_from_slice(staged.as_bytes());
    Ok(())
}

/// No Clone/Copy, formatter, persistence or public byte-extraction API.
#[cfg(any(feature = "snp-core", feature = "system-random", test))]
pub(crate) struct Secret32([u8; 32]);

#[cfg(any(feature = "snp-core", feature = "system-random", test))]
impl Secret32 {
    pub(crate) fn zeroed() -> Self {
        Self::from_bytes([0; 32])
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    fn clear(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(any(feature = "snp-core", feature = "system-random", test))]
impl Drop for Secret32 {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Finite scripted values, compiled only into PAL unit tests.
#[cfg(test)]
pub(crate) struct DeterministicRandomSource {
    blocks: std::vec::IntoIter<[u8; 32]>,
    pub(crate) calls: usize,
}

#[cfg(test)]
impl DeterministicRandomSource {
    pub(crate) fn new(blocks: Vec<[u8; 32]>) -> Self {
        Self {
            blocks: blocks.into_iter(),
            calls: 0,
        }
    }
}

#[cfg(test)]
impl RandomSource for DeterministicRandomSource {
    fn fill_random32(&mut self, output: &mut [u8; 32]) -> Result<(), RandomError> {
        self.calls += 1;
        fill_checked(output, |bytes| {
            let block = self.blocks.next().ok_or(RandomError::Unavailable)?;
            bytes.copy_from_slice(&block);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_exact_draws_and_exhaustion() {
        let mut random = DeterministicRandomSource::new(vec![[0x31; 32], [0x72; 32]]);
        let mut output = [0; 32];
        random.fill_random32(&mut output).unwrap();
        assert_eq!(output, [0x31; 32]);
        random.fill_random32(&mut output).unwrap();
        assert_eq!(output, [0x72; 32]);
        assert_eq!(
            random.fill_random32(&mut output),
            Err(RandomError::Unavailable)
        );
        assert_eq!(output, [0; 32]);
        assert_eq!(random.calls, 3);
    }

    #[test]
    fn every_partial_failure_leaves_no_output() {
        for prefix in 0..=32 {
            let mut output = [0x99; 32];
            assert_eq!(
                fill_checked(&mut output, |bytes| {
                    bytes[..prefix].fill(0x42);
                    Err(RandomError::Unavailable)
                }),
                Err(RandomError::Unavailable)
            );
            assert_eq!(output, [0; 32]);
        }
    }

    #[test]
    fn backend_unwind_cannot_publish_partial_randomness() {
        let mut output = [0x99; 32];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = fill_checked(&mut output, |bytes| {
                bytes[..16].fill(0x42);
                panic!("test backend panic");
            });
        }));
        assert!(result.is_err());
        assert_eq!(output, [0; 32]);
    }

    #[test]
    fn owner_cleanup_wipes_all_bytes() {
        let mut secret = Secret32::from_bytes([0x42; 32]);
        secret.clear();
        assert_eq!(secret.as_bytes(), &[0; 32]);
        secret.clear();
        assert_eq!(secret.as_bytes(), &[0; 32]);
    }

    #[test]
    fn default_service_needs_no_fixture_feature() {
        let mut source: Box<dyn RandomSource> = Box::new(UnavailableRandomSource);
        assert_eq!(
            source.fill_random32(&mut [0; 32]),
            Err(RandomError::Unavailable)
        );
    }

    #[test]
    fn unavailable_is_explicit_and_clears_output() {
        let mut output = [0x42; 32];
        assert_eq!(
            UnavailableRandomSource.fill_random32(&mut output),
            Err(RandomError::Unavailable)
        );
        assert_eq!(output, [0; 32]);
    }

    #[cfg(feature = "system-random")]
    #[test]
    fn system_service_fills_exact_requested_buffer() {
        let mut output = [0; 32];
        SystemRandomSource::default()
            .fill_random32(&mut output)
            .unwrap();
    }
}
