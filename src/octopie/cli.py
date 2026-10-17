"""Minimal CLI entry point."""

from __future__ import annotations

import argparse
import json

from .config import HeadConfig
from .simulation import NetworkSimulator


def main() -> None:
    parser = argparse.ArgumentParser(description="Octopie head simulation")
    parser.add_argument("--target", type=int, default=42, help="Node target (default 42)")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    parser.add_argument("--json", action="store_true", help="Emit status as JSON")
    args = parser.parse_args()

    cfg = HeadConfig.for_target(args.target, seed=args.seed)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities()
    admitted = sim.grow_to_target()
    status = sim.head.status()
    status["admitted_this_run"] = admitted

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print(f"Octopie head {status['head_id']}")
        print(f"  target={status['target_nodes']}  admitted={status['admitted']}  workers={status['active_workers']}")
        print(f"  running={status['running']}  paused={status['admissions_paused']}")


if __name__ == "__main__":
    main()
