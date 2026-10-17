"""Configuration models for the Octopie head.

All limits and targets are configuration-driven. 42 is the default
simulation target, never a hard-coded architectural maximum.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class LimitsConfig:
    max_nodes: int = 42
    max_connections: int = 128
    max_concurrent_admissions: int = 8
    max_expansion_per_second: float = 4.0
    per_node_cpu_budget: float = 1.0
    per_node_memory_mb: int = 64
    recovery_max_attempts: int = 3
    recovery_backoff_seconds: float = 1.0
    shutdown_deadline_seconds: float = 30.0
    lease_duration_seconds: float = 60.0
    admission_timeout_seconds: float = 10.0
    health_check_interval_seconds: float = 5.0
    credential_ttl_seconds: float = 300.0
    expansion_retry_limit: int = 3

    def __post_init__(self) -> None:
        if self.max_nodes < 1:
            raise ValueError("max_nodes must be >= 1")
        if self.max_connections < 1:
            raise ValueError("max_connections must be >= 1")
        if self.max_concurrent_admissions < 1:
            raise ValueError("max_concurrent_admissions must be >= 1")
        if self.max_expansion_per_second <= 0:
            raise ValueError("max_expansion_per_second must be > 0")
        if self.recovery_max_attempts < 0:
            raise ValueError("recovery_max_attempts must be >= 0")
        if self.shutdown_deadline_seconds <= 0:
            raise ValueError("shutdown_deadline_seconds must be > 0")
        if self.admission_timeout_seconds <= 0:
            raise ValueError("admission_timeout_seconds must be > 0")
        if self.health_check_interval_seconds <= 0:
            raise ValueError("health_check_interval_seconds must be > 0")
        if self.credential_ttl_seconds <= 0:
            raise ValueError("credential_ttl_seconds must be > 0")
        if self.expansion_retry_limit < 0:
            raise ValueError("expansion_retry_limit must be >= 0")


@dataclass(frozen=True)
class SimulationConfig:
    seed: int = 42
    duration_seconds: float = 60.0
    target_nodes: int = 42

    def __post_init__(self) -> None:
        if self.duration_seconds <= 0:
            raise ValueError("duration_seconds must be > 0")
        if self.target_nodes < 1:
            raise ValueError("target_nodes must be >= 1")


@dataclass(frozen=True)
class AuditConfig:
    retention_events: int = 10_000
    diagnostic_verbosity: str = "normal"
    hash_link: bool = True
    policy_version: str = "1"

    def __post_init__(self) -> None:
        if self.retention_events < 1:
            raise ValueError("retention_events must be >= 1")
        if self.diagnostic_verbosity not in ("quiet", "normal", "verbose"):
            raise ValueError("diagnostic_verbosity must be quiet|normal|verbose")


@dataclass(frozen=True)
class HeadConfig:
    head_id: str = "head-0"
    target_nodes: int = 42
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    network_expansion_enabled: bool = False
    require_explicit_authorization: bool = True
    fail_closed_on_policy_error: bool = True
    seed: Optional[int] = None
    audit_log_path: Optional[str] = None
    persistence_dir: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.head_id or not self.head_id.strip():
            raise ValueError("head_id must be a non-empty string")
        if self.target_nodes < 1:
            raise ValueError("target_nodes must be >= 1")
        if self.network_expansion_enabled and not self.require_explicit_authorization:
            raise ValueError(
                "network_expansion_enabled requires require_explicit_authorization=True"
            )
        if self.limits.max_nodes < self.target_nodes:
            object.__setattr__(
                self,
                "limits",
                LimitsConfig(
                    max_nodes=self.target_nodes,
                    max_connections=self.limits.max_connections,
                    max_concurrent_admissions=self.limits.max_concurrent_admissions,
                    max_expansion_per_second=self.limits.max_expansion_per_second,
                    per_node_cpu_budget=self.limits.per_node_cpu_budget,
                    per_node_memory_mb=self.limits.per_node_memory_mb,
                    recovery_max_attempts=self.limits.recovery_max_attempts,
                    recovery_backoff_seconds=self.limits.recovery_backoff_seconds,
                    shutdown_deadline_seconds=self.limits.shutdown_deadline_seconds,
                    lease_duration_seconds=self.limits.lease_duration_seconds,
                    admission_timeout_seconds=self.limits.admission_timeout_seconds,
                    health_check_interval_seconds=self.limits.health_check_interval_seconds,
                    credential_ttl_seconds=self.limits.credential_ttl_seconds,
                    expansion_retry_limit=self.limits.expansion_retry_limit,
                ),
            )

    @classmethod
    def for_target(cls, n: int, **kwargs) -> "HeadConfig":
        limits = kwargs.pop("limits", None)
        if limits is None:
            limits = LimitsConfig(
                max_nodes=max(n, 42),
                max_expansion_per_second=float(max(n, 64)),
                max_concurrent_admissions=max(n, 16),
            )
        return cls(target_nodes=n, limits=limits, **kwargs)
