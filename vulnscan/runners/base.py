from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod

from vulnscan.config import Config
from vulnscan.models import Finding
from vulnscan.target import Target


class Runner(ABC):
    name: str = "base"
    binary: str | None = None

    def is_available(self) -> bool:
        if self.binary is None:
            return True
        return shutil.which(self.binary) is not None

    @abstractmethod
    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        ...

    @staticmethod
    def run_cmd(cmd: list[str], *, timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=cwd,
                text=True,
                errors="replace",
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout if isinstance(e.stdout, str) else ""
            err = e.stderr if isinstance(e.stderr, str) else ""
            return -9, out + "\n[TIMEOUT]", err
        except FileNotFoundError:
            return -1, "", "binary not found"
