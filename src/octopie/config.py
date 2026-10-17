"""Configuration models for the Octopie head.

All limits and targets are configuration-driven. 42 is the default
simulation target, never a hard-coded architectural maximum.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class LimitsConfig:
    """Resource and rate limits enforced by the head."""

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


@dataclass(frozen=True)
class HeadConfig:
    """Top-level head configuration.

    network_expansion_enabled defaults to False. Real peer discovery
    stays opt-in and bounded until explicit policy enables it.
    """

    head_id: str = "head-0"
    target_nodes: int = 42
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    network_expansion_enabled: bool = False
    require_explicit_authorization: bool = True
    fail_closed_on_policy_error: bool = True
    seed: Optional[int] = None  # for deterministic simulation
    audit_log_path: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.head_id or not self.head_id.strip():
            raise ValueError("head_id must be a non-empty string")
        if self.target_nodes < 1:
            raise ValueError("target_nodes must be >= 1")
        # Ensure limits.max_nodes is at least target_nodes for the default case
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
                ),
            )

    @classmethod
    def for_target(cls, n: int, **kwargs) -> "HeadConfig":
        """Convenience factory for a given node target (8, 16, 32, 42, 64, …)."""
        limits = kwargs.pop("limits", None)
        if limits is None:
            # Generous expansion rate so simulation can fill the target in one pass
            limits = LimitsConfig(
                max_nodes=max(n, 42),
                max_expansion_per_second=float(max(n, 64)),
                max_concurrent_admissions=max(n, 16),
            )
        return cls(target_nodes=n, limits=limits, **kwargs)
