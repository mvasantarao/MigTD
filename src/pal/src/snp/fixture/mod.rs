#[cfg(feature = "snp-mock-installation")]
pub mod platform_services;

/// Captured-fixture compatibility encoding, not the common V6 evidence format.
pub fn encode_legacy_ma_blob(
    evidence: &crate::types::MaEvidence,
    collateral: &crate::types::SnpVerificationCollateral,
) -> Result<Vec<u8>, crate::traits::PalError> {
    use crate::traits::PalError;
    use crate::types::{MaEvidenceBinding, SnpCollateralLeafKind};

    if evidence.binding() != MaEvidenceBinding::CapturedFixture
        || collateral.leaf_kind() != SnpCollateralLeafKind::Vcek
    {
        log::error!("legacy fixture encoding rejected non-fixture evidence or collateral");
        return Err(PalError::InvalidInput);
    }
    let mut blob = evidence.report().to_vec();
    for certificate in [collateral.leaf_der(), collateral.ask_der()] {
        if certificate.is_empty() || certificate.len() > super::limits::MAX_SNP_CERTIFICATE_SIZE {
            log::error!("legacy fixture encoding rejected invalid certificate size");
            return Err(PalError::InvalidInput);
        }
        let length = u32::try_from(certificate.len()).map_err(|_| {
            log::error!("legacy fixture certificate length cannot be encoded");
            PalError::InvalidInput
        })?;
        blob.extend_from_slice(&length.to_le_bytes());
        blob.extend_from_slice(certificate);
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::PalError;
    use crate::types::{
        MaEvidence, MaEvidenceBinding, SnpCollateralLeafKind, SnpVerificationCollateral,
    };

    #[test]
    fn legacy_encoder_cannot_relabel_live_evidence_or_vlek() {
        let fixture = MaEvidence::new([0x33; 1184], MaEvidenceBinding::CapturedFixture);
        let live = MaEvidence::new([0x44; 1184], MaEvidenceBinding::RequestedReportData);
        let vcek = SnpVerificationCollateral::new(vec![1], vec![2]);
        let vlek =
            SnpVerificationCollateral::new_with_leaf(SnpCollateralLeafKind::Vlek, vec![1], vec![2]);
        assert!(matches!(
            encode_legacy_ma_blob(&live, &vcek),
            Err(PalError::InvalidInput)
        ));
        assert!(matches!(
            encode_legacy_ma_blob(&fixture, &vlek),
            Err(PalError::InvalidInput)
        ));
    }

    #[test]
    fn legacy_encoder_validates_both_certificate_lengths() {
        let evidence = MaEvidence::new([0x33; 1184], MaEvidenceBinding::CapturedFixture);
        for invalid in [
            vec![],
            vec![0; super::super::limits::MAX_SNP_CERTIFICATE_SIZE + 1],
        ] {
            for collateral in [
                SnpVerificationCollateral::new(invalid.clone(), vec![2]),
                SnpVerificationCollateral::new(vec![1], invalid.clone()),
            ] {
                assert!(matches!(
                    encode_legacy_ma_blob(&evidence, &collateral),
                    Err(PalError::InvalidInput)
                ));
            }
        }
        let blob =
            encode_legacy_ma_blob(&evidence, &SnpVerificationCollateral::new(vec![1], vec![2]))
                .unwrap();
        assert_eq!(&blob[..1184], &[0x33; 1184]);
        assert_eq!(&blob[1184..], &[1, 0, 0, 0, 1, 1, 0, 0, 0, 2]);
    }
}
