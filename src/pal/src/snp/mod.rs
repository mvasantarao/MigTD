// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Provider-independent SNP contracts. Backend selection belongs to composition
//! roots; availability never authorizes policy, installation or replay effects.

pub mod authorization_result;
pub mod binding_manager;
pub mod collateral_set;
// Superseded V1 conformance models remain test-only historical evidence.
#[cfg(test)]
pub mod confirmation;
#[cfg(test)]
pub mod contribution_exchange;
#[cfg(test)]
pub mod control_exchange;
pub mod direct_authorization;
pub mod direct_exchange;
pub mod direct_key;
pub mod evidence_header;
pub mod host_control;
pub mod identity;
#[cfg(test)]
pub mod key_contribution;
pub mod key_ops;
pub mod limits;
pub mod local_handoff;
pub mod ma_evidence;
pub mod ma_policy;
pub mod migration_data;
pub mod migration_install;
pub mod peer_channel;
pub mod policy;
pub mod policy_identity;
pub mod purpose_binding;
pub mod qvl;
pub mod report_data_context;
#[cfg(test)]
pub mod tenant_authorization;
pub mod tenant_delivery;
pub mod tenant_evidence;
pub mod tenant_policy_context;
pub mod tenant_source;
pub mod wire;

#[cfg(test)]
mod golden_vectors;

#[cfg(test)]
mod property_tests;

#[cfg(feature = "snp-linux-hardware")]
pub mod hardware;

#[cfg(feature = "snp-fixture")]
pub mod fixture;
