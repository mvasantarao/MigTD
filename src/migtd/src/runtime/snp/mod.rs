pub mod config;
#[cfg(feature = "SnpEmu")]
pub(crate) mod legacy;
#[cfg(feature = "SnpEmu")]
pub mod requests;

#[cfg(feature = "SnpUnderhillRuntime")]
pub mod pid1;

#[cfg(all(feature = "SnpEmu", feature = "snp-tcp-transport"))]
pub mod snpemu;
