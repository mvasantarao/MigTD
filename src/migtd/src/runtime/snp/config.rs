// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Runtime configuration for the unified SNP Migration Agent binary.

use std::fmt;

const STANDALONE_PEER_ADDR_DEFAULT: &str = "127.0.0.1:8001";
const PID1_SOURCE_HOST_ADDR_DEFAULT: &str = "127.0.0.1:8001";
const PID1_DEST_HOST_ADDR_DEFAULT: &str = "0.0.0.0:8002";
const PID1_SOURCE_PEER_ADDR_DEFAULT: &str = "10.0.2.2:9001";
const PID1_DEST_PEER_ADDR_DEFAULT: &str = "0.0.0.0:9001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationRole {
    Source,
    Destination,
}

impl MigrationRole {
    pub fn is_source(self) -> bool {
        matches!(self, Self::Source)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Destination => "destination",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "source" | "src" => Ok(Self::Source),
            "destination" | "dest" | "dst" | "target" => Ok(Self::Destination),
            _ => Err(format!("invalid migration role: {value}")),
        }
    }
}

impl fmt::Display for MigrationRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartMode {
    Autostart,
    Wfr,
}

impl StartMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Autostart => "autostart",
            Self::Wfr => "wfr",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "autostart" => Ok(Self::Autostart),
            "wfr" => Ok(Self::Wfr),
            _ => Err(format!("invalid start mode: {value}")),
        }
    }
}

impl fmt::Display for StartMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessMode {
    Standalone,
    Pid1,
}

impl ProcessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Pid1 => "pid1",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "standalone" => Ok(Self::Standalone),
            "pid1" => Ok(Self::Pid1),
            _ => Err(format!("invalid process mode: {value}")),
        }
    }
}

impl fmt::Display for ProcessMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformServicesMode {
    Fixture,
    Hardware,
}

impl PlatformServicesMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Hardware => "hardware",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "fixture" => Ok(Self::Fixture),
            "hardware" => Ok(Self::Hardware),
            _ => Err(format!("invalid platform services mode: {value}")),
        }
    }
}

impl fmt::Display for PlatformServicesMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostControlMode {
    None,
    Tcp,
}

impl HostControlMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tcp => "tcp",
        }
    }
}

impl fmt::Display for HostControlMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerTransportMode {
    TcpEmulation,
    Underhill,
}

impl PeerTransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TcpEmulation => "tcp-emulation",
            Self::Underhill => "underhill",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" | "tcp-emulation" => Ok(Self::TcpEmulation),
            "underhill" => Ok(Self::Underhill),
            _ => Err(format!("invalid peer transport mode: {value}")),
        }
    }
}

impl fmt::Display for PeerTransportMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    pub role: MigrationRole,
    pub start_mode: StartMode,
    pub process_mode: ProcessMode,
    pub platform_services: PlatformServicesMode,
    pub host_control: HostControlMode,
    pub peer_transport: PeerTransportMode,
    pub request_id: u64,
    pub target_uuid: [u32; 4],
    pub binding_handle: u64,
    pub peer_address: String,
    pub host_control_address: Option<String>,
}

pub enum ParseOutcome {
    Run(RuntimeConfig),
    Help,
}

impl RuntimeConfig {
    pub fn parse<I, S>(args: I) -> Result<ParseOutcome, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        if is_legacy_pid1_invocation(&args) {
            return parse_legacy_pid1(&args).map(ParseOutcome::Run);
        }

        let mut role = MigrationRole::Source;
        let mut start_mode = StartMode::Autostart;
        let mut start_mode_explicit = false;
        let mut process_mode = ProcessMode::Standalone;
        let mut process_mode_explicit = false;
        let mut platform_services = PlatformServicesMode::Fixture;
        let mut peer_transport = PeerTransportMode::TcpEmulation;
        let mut request_id = 1u64;
        let mut target_uuid = [1u32, 2, 3, 4];
        let mut binding_handle = 0x1234u64;
        let mut peer_address: Option<String> = None;
        let mut peer_ip: Option<String> = None;
        let mut peer_port: Option<u16> = None;
        let mut host_control_address: Option<String> = None;

        let mut index = 1;
        while index < args.len() {
            match args[index].as_str() {
                "--help" | "-h" => return Ok(ParseOutcome::Help),
                "--role" | "-m" => {
                    role = MigrationRole::parse(required_value(&args, index)?)?;
                    index += 2;
                }
                "--start-mode" => {
                    start_mode = StartMode::parse(required_value(&args, index)?)?;
                    start_mode_explicit = true;
                    index += 2;
                }
                "--autostart" => {
                    start_mode = StartMode::Autostart;
                    start_mode_explicit = true;
                    index += 1;
                }
                "--wfr" => {
                    start_mode = StartMode::Wfr;
                    start_mode_explicit = true;
                    index += 1;
                }
                "--process" => {
                    process_mode = ProcessMode::parse(required_value(&args, index)?)?;
                    process_mode_explicit = true;
                    index += 2;
                }
                "--platform-services" => {
                    platform_services = PlatformServicesMode::parse(required_value(&args, index)?)?;
                    index += 2;
                }
                "--peer-transport" => {
                    peer_transport = PeerTransportMode::parse(required_value(&args, index)?)?;
                    index += 2;
                }
                "--request-id" | "-r" => {
                    request_id = parse_u64(required_value(&args, index)?, "request ID")?;
                    index += 2;
                }
                "--uuid" | "-u" => {
                    if index + 4 >= args.len() {
                        return Err("--uuid requires four integer values".to_string());
                    }
                    for component in 0..4 {
                        target_uuid[component] =
                            args[index + component + 1].parse().map_err(|_| {
                                format!("invalid UUID component: {}", args[index + component + 1])
                            })?;
                    }
                    index += 5;
                }
                "--binding" | "-b" => {
                    binding_handle = parse_u64(required_value(&args, index)?, "binding handle")?;
                    index += 2;
                }
                "--peer-address" => {
                    peer_address = Some(required_value(&args, index)?.to_string());
                    index += 2;
                }
                "--host-address" | "--host-control-address" => {
                    host_control_address = Some(required_value(&args, index)?.to_string());
                    index += 2;
                }
                "--dest-ip" | "-d" => {
                    peer_ip = Some(required_value(&args, index)?.to_string());
                    index += 2;
                }
                "--dest-port" | "-t" => {
                    peer_port = Some(
                        required_value(&args, index)?
                            .parse()
                            .map_err(|_| format!("invalid peer port: {}", args[index + 1]))?,
                    );
                    index += 2;
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if process_mode_explicit && process_mode == ProcessMode::Pid1 && !start_mode_explicit {
            start_mode = StartMode::Wfr;
        }
        if process_mode == ProcessMode::Pid1 && start_mode != StartMode::Wfr {
            return Err("PID1 process mode requires WFR start mode".to_string());
        }

        let peer_address = match peer_address {
            Some(_) if peer_ip.is_some() || peer_port.is_some() => {
                return Err(
                    "--peer-address cannot be combined with --dest-ip or --dest-port".to_string(),
                )
            }
            Some(address) => address,
            None if peer_ip.is_some() || peer_port.is_some() => format!(
                "{}:{}",
                peer_ip.as_deref().unwrap_or("127.0.0.1"),
                peer_port.unwrap_or(8001)
            ),
            None => default_peer_address(process_mode, role).to_string(),
        };

        let host_control = match start_mode {
            StartMode::Autostart => {
                if host_control_address.is_some() {
                    return Err("--host-address is valid only with WFR start mode".to_string());
                }
                HostControlMode::None
            }
            StartMode::Wfr => {
                if host_control_address.is_none() {
                    host_control_address =
                        Some(default_host_control_address(process_mode, role).to_string());
                }
                HostControlMode::Tcp
            }
        };

        Ok(ParseOutcome::Run(Self {
            role,
            start_mode,
            process_mode,
            platform_services,
            host_control,
            peer_transport,
            request_id,
            target_uuid,
            binding_handle,
            peer_address,
            host_control_address,
        }))
    }
}

fn is_legacy_pid1_invocation(args: &[String]) -> bool {
    matches!(
        args.get(1).map(String::as_str),
        Some("source" | "dest" | "destination")
    )
}

fn parse_legacy_pid1(args: &[String]) -> Result<RuntimeConfig, String> {
    let role = MigrationRole::parse(&args[1])?;
    let (host_control_address, peer_address) = match role {
        MigrationRole::Source => (
            args.get(2)
                .cloned()
                .unwrap_or_else(|| PID1_SOURCE_HOST_ADDR_DEFAULT.to_string()),
            args.get(3)
                .cloned()
                .unwrap_or_else(|| PID1_SOURCE_PEER_ADDR_DEFAULT.to_string()),
        ),
        MigrationRole::Destination => (
            PID1_DEST_HOST_ADDR_DEFAULT.to_string(),
            args.get(2)
                .cloned()
                .unwrap_or_else(|| PID1_DEST_PEER_ADDR_DEFAULT.to_string()),
        ),
    };

    if args.len() > if role == MigrationRole::Source { 4 } else { 3 } {
        return Err("unexpected argument in legacy PID1 invocation".to_string());
    }

    Ok(RuntimeConfig {
        role,
        start_mode: StartMode::Wfr,
        process_mode: ProcessMode::Pid1,
        platform_services: PlatformServicesMode::Fixture,
        host_control: HostControlMode::Tcp,
        peer_transport: PeerTransportMode::TcpEmulation,
        request_id: 1,
        target_uuid: [1, 2, 3, 4],
        binding_handle: 0x1234,
        peer_address,
        host_control_address: Some(host_control_address),
    })
}

fn required_value(args: &[String], index: usize) -> Result<&str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{} requires a value", args[index]))
}

fn parse_u64(value: &str, field: &str) -> Result<u64, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid {field}: {value}"))
    } else {
        value
            .parse()
            .map_err(|_| format!("invalid {field}: {value}"))
    }
}

fn default_peer_address(process_mode: ProcessMode, role: MigrationRole) -> &'static str {
    match (process_mode, role) {
        (ProcessMode::Standalone, _) => STANDALONE_PEER_ADDR_DEFAULT,
        (ProcessMode::Pid1, MigrationRole::Source) => PID1_SOURCE_PEER_ADDR_DEFAULT,
        (ProcessMode::Pid1, MigrationRole::Destination) => PID1_DEST_PEER_ADDR_DEFAULT,
    }
}

fn default_host_control_address(_process_mode: ProcessMode, role: MigrationRole) -> &'static str {
    match role {
        MigrationRole::Source => PID1_SOURCE_HOST_ADDR_DEFAULT,
        MigrationRole::Destination => PID1_DEST_HOST_ADDR_DEFAULT,
    }
}

pub fn usage() -> &'static str {
    "Unified SNP MigTD usage:

  Standalone Autostart:
    migtd --process standalone --start-mode autostart --role <source|destination> \\
          [--peer-address <ip:port>] [--request-id <id>] \\
          [--uuid <u1> <u2> <u3> <u4>] [--binding <handle>]

  Standalone or PID1 TCP WFR:
    migtd --process <standalone|pid1> --start-mode wfr \\
          --role <source|destination> --host-address <ip:port> \\
          [--peer-address <ip:port>]

  Legacy PID1 syntax (preserved):
    migtd source <host-WFR-address> <peer-address>
    migtd dest <peer-listen-address>

  Provider/transport selections:
    --platform-services <fixture|hardware>
    --peer-transport <tcp-emulation|underhill>

  M1 rejects hardware platform services and the Underhill peer backend
  explicitly because those implementations are not available yet.

  Legacy standalone peer aliases:
    --dest-ip <ip> --dest-port <port>
"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> RuntimeConfig {
        match RuntimeConfig::parse(args.iter().copied()).unwrap() {
            ParseOutcome::Run(config) => config,
            ParseOutcome::Help => panic!("unexpected help outcome"),
        }
    }

    #[test]
    fn standalone_autostart_is_default_profile() {
        let config = parse(&["migtd", "--role", "destination"]);
        assert_eq!(config.process_mode, ProcessMode::Standalone);
        assert_eq!(config.start_mode, StartMode::Autostart);
        assert_eq!(config.host_control, HostControlMode::None);
        assert_eq!(config.role, MigrationRole::Destination);
        assert_eq!(config.peer_address, STANDALONE_PEER_ADDR_DEFAULT);
        assert_eq!(config.host_control_address, None);
    }

    #[test]
    fn standalone_wfr_uses_tcp_host_control() {
        let config = parse(&[
            "migtd",
            "--process",
            "standalone",
            "--wfr",
            "--role",
            "source",
            "--host-address",
            "127.0.0.1:8101",
            "--peer-address",
            "127.0.0.1:9101",
        ]);
        assert_eq!(config.start_mode, StartMode::Wfr);
        assert_eq!(config.host_control, HostControlMode::Tcp);
        assert_eq!(
            config.host_control_address.as_deref(),
            Some("127.0.0.1:8101")
        );
        assert_eq!(config.peer_address, "127.0.0.1:9101");
    }

    #[test]
    fn explicit_pid1_defaults_to_wfr() {
        let config = parse(&["migtd", "--process", "pid1", "--role", "destination"]);
        assert_eq!(config.process_mode, ProcessMode::Pid1);
        assert_eq!(config.start_mode, StartMode::Wfr);
        assert_eq!(
            config.host_control_address.as_deref(),
            Some(PID1_DEST_HOST_ADDR_DEFAULT)
        );
        assert_eq!(config.peer_address, PID1_DEST_PEER_ADDR_DEFAULT);
    }

    #[test]
    fn legacy_source_pid1_syntax_is_preserved() {
        let config = parse(&["migtd", "source", "10.0.2.2:8001", "10.0.2.2:9001"]);
        assert_eq!(config.process_mode, ProcessMode::Pid1);
        assert_eq!(config.start_mode, StartMode::Wfr);
        assert_eq!(config.role, MigrationRole::Source);
        assert_eq!(
            config.host_control_address.as_deref(),
            Some("10.0.2.2:8001")
        );
        assert_eq!(config.peer_address, "10.0.2.2:9001");
    }

    #[test]
    fn legacy_destination_pid1_syntax_is_preserved() {
        let config = parse(&["migtd", "dest", "0.0.0.0:9001"]);
        assert_eq!(config.process_mode, ProcessMode::Pid1);
        assert_eq!(config.role, MigrationRole::Destination);
        assert_eq!(
            config.host_control_address.as_deref(),
            Some(PID1_DEST_HOST_ADDR_DEFAULT)
        );
        assert_eq!(config.peer_address, "0.0.0.0:9001");
    }

    #[test]
    fn legacy_standalone_peer_flags_are_preserved() {
        let config = parse(&[
            "migtd",
            "--role",
            "source",
            "--dest-ip",
            "192.0.2.10",
            "--dest-port",
            "9010",
        ]);
        assert_eq!(config.peer_address, "192.0.2.10:9010");
    }

    #[test]
    fn pid1_autostart_is_rejected() {
        let error =
            RuntimeConfig::parse(["migtd", "--process", "pid1", "--start-mode", "autostart"])
                .err()
                .unwrap();
        assert!(error.contains("PID1 process mode requires WFR"));
    }

    #[test]
    fn host_address_is_rejected_for_autostart() {
        let error =
            RuntimeConfig::parse(["migtd", "--autostart", "--host-address", "127.0.0.1:8001"])
                .err()
                .unwrap();
        assert!(error.contains("valid only with WFR"));
    }

    #[test]
    fn hardware_platform_mode_is_representable() {
        let config = parse(&["migtd", "--platform-services", "hardware"]);
        assert_eq!(config.platform_services, PlatformServicesMode::Hardware);
    }

    #[test]
    fn underhill_peer_mode_is_representable() {
        let config = parse(&["migtd", "--peer-transport", "underhill"]);
        assert_eq!(config.peer_transport, PeerTransportMode::Underhill);
    }
}
