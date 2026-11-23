# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import aiohttp
from aiohttp import web
from libcrypto import HDWallet, Wallet
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# Optional faster JSON parser if installed
try:
    import orjson as _json_lib
    def _loads(raw: bytes | str) -> dict:
        return _json_lib.loads(raw)
except ImportError:
    import json as _json_lib
    def _loads(raw: bytes | str) -> dict:
        return _json_lib.loads(raw)


DEFAULT_CANDIDATE_SEEDS: list[str] = [
    "maze lizard hammer peanut globe few wolf swallow truly rough comfort legal,
    motor forest luxury describe arrest figure office garment leisure sentence use expand",
]


# ══════════════════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Config:
    """Application configuration settings."""

    API_BASE_URL: str = "https://litecoin.atomicwallet.io/api/address"
    API_TIMEOUT: float = 6.0
    API_RETRY_ATTEMPTS: int = 2
    API_RETRY_DELAY: float = 0.25

    # Candidate Seed Settings
    CANDIDATE_SEEDS_FILE: Optional[Path] = field(
        default_factory=lambda: Path(p) if (p := os.environ.get("CANDIDATE_SEEDS_FILE", "").strip()) else None
    )
    MNEMONIC_PASSPHRASE: str = field(
        default_factory=lambda: os.environ.get("MNEMONIC_PASSPHRASE", "")
    )

    # Pipeline & Concurrency Settings
    WORKERS: int = 16
    MAX_CONCURRENT_REQUESTS: int = 32
    REQUEST_DELAY: float = 0.0

    # Render / HTTP Port Binding & Winner Delivery
    HOST: str = "0.0.0.0"
    PORT: int = field(default_factory=lambda: int(os.environ.get("PORT", "10000")))
    STATUS_LOG_INTERVAL: float = 15.0
    WINNER_WEBHOOK_URL: str = field(
        default_factory=lambda: os.environ.get("WINNER_WEBHOOK_URL", "").strip()
    )
    WINNER_WEBHOOK_SECRET: str = field(
        default_factory=lambda: os.environ.get("WINNER_WEBHOOK_SECRET", "").strip()
    )
    MAX_RECENT_WINNERS: int = 50

    # Output Configuration
    OUTPUT_DIR: Path = field(default_factory=lambda: Path("output"))
    WINNER_FILE: str = "ltc_winners_{date}.txt"
    LOG_FILE: str = "ltc_scanner_{date}.log"

    # Display Settings
    REFRESH_PER_SECOND: int = 10

    def __post_init__(self) -> None:
        out = Path(self.OUTPUT_DIR)
        object.__setattr__(self, "OUTPUT_DIR", out)
        out.mkdir(parents=True, exist_ok=True)
        if self.CANDIDATE_SEEDS_FILE is not None:
            object.__setattr__(self, "CANDIDATE_SEEDS_FILE", Path(self.CANDIDATE_SEEDS_FILE))


# ══════════════════════════════════════════════════════════════════════════════
# Enums & Data Classes
# ══════════════════════════════════════════════════════════════════════════════

class AddressType(Enum):
    """Litecoin address types."""

    P2PKH = "p2pkh"
    P2SH_P2WPKH = "p2sh-p2wpkh"
    P2WPKH = "p2wpkh"

    @property
    def display_name(self) -> str:
        return {
            AddressType.P2PKH: "LTC-P2PKH",
            AddressType.P2SH_P2WPKH: "LTC-P2SH-P2WPKH",
            AddressType.P2WPKH: "LTC-P2WPKH",
        }[self]


ADDRESS_TYPES = tuple(AddressType)


@dataclass(slots=True)
class WalletAddress:
    """Represents a wallet address with its metadata."""

    address: str
    address_type: AddressType
    balance: int = 0
    total_received: int = 0
    total_sent: int = 0
    tx_count: int = 0

    @property
    def has_balance(self) -> bool:
        return self.balance > 0


@dataclass(slots=True)
class GeneratedWallet:
    """Represents a complete generated wallet derived from a candidate seed."""

    mnemonic: str
    private_key: str
    addresses: list[WalletAddress]
    generated_at: datetime = field(default_factory=datetime.now)

    @property
    def has_any_balance(self) -> bool:
        return any(addr.has_balance for addr in self.addresses)

    @property
    def total_balance(self) -> int:
        return sum(addr.balance for addr in self.addresses)

    def to_dict(self, include_secrets: bool = False) -> dict:
        data = {
            "generated_at": self.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "has_any_balance": self.has_any_balance,
            "total_balance": self.total_balance,
            "addresses": [
                {
                    "type": a.address_type.display_name,
                    "address": a.address,
                    "balance": a.balance,
                    "tx_count": a.tx_count,
                }
                for a in self.addresses
            ],
        }
        if include_secrets:
            data["mnemonic"] = self.mnemonic
            data["private_key"] = self.private_key
        return data


@dataclass(slots=True)
class ScannerStats:
    """Scanner statistics tracker."""

    total_scanned: int = 0
    winners_found: int = 0
    api_errors: int = 0
    start_dt: datetime = field(default_factory=datetime.now)

    @property
    def scan_rate(self) -> float:
        elapsed = (datetime.now() - self.start_dt).total_seconds()
        return self.total_scanned / max(elapsed, 0.001)

    @property
    def elapsed_time(self) -> str:
        elapsed = int((datetime.now() - self.start_dt).total_seconds())
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


# ══════════════════════════════════════════════════════════════════════════════
# Logging Setup
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging(config: Config) -> logging.Logger:
    """Configure application logging."""
    log_file = config.OUTPUT_DIR / config.LOG_FILE.format(
        date=datetime.now().strftime("%Y%m%d_%H%M%S")
    )

    logger = logging.getLogger("LTCScanner")
    logger.setLevel(logging.WARNING)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.WARNING)
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


# ══════════════════════════════════════════════════════════════════════════════
# Abstract Base Classes & Implementations
# ══════════════════════════════════════════════════════════════════════════════

class IBlockchainAPI(ABC):
    @abstractmethod
    async def get_address_info(self, address: str) -> dict:
        pass


class IWalletGenerator(ABC):
    @abstractmethod
    def generate(self) -> GeneratedWallet:
        pass


class IResultWriter(ABC):
    @abstractmethod
    async def write_winner(self, wallet: GeneratedWallet) -> None:
        pass


class DynamicSemaphore:
    """Asyncio semaphore whose concurrency limit can be adjusted at runtime."""

    def __init__(self, initial_limit: int) -> None:
        self._limit = max(1, int(initial_limit))
        self._active = 0
        self._cond = asyncio.Condition()

    @property
    def limit(self) -> int:
        return self._limit

    async def set_limit(self, new_limit: int) -> None:
        async with self._cond:
            self._limit = max(1, int(new_limit))
            self._cond.notify_all()

    async def acquire(self) -> None:
        async with self._cond:
            await self._cond.wait_for(lambda: self._active < self._limit)
            self._active += 1

    def release(self) -> None:
        async def _do_release() -> None:
            async with self._cond:
                self._active = max(0, self._active - 1)
                self._cond.notify(1)

        asyncio.create_task(_do_release())

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.release()


class LitecoinAPI(IBlockchainAPI):
    """High-throughput Litecoin blockchain API client with pooled connections."""

    def __init__(
        self,
        config: Config,
        logger: logging.Logger,
        session: aiohttp.ClientSession,
        semaphore: Optional[DynamicSemaphore] = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._session = session
        self._semaphore = semaphore or DynamicSemaphore(config.MAX_CONCURRENT_REQUESTS)
        self._timeout = aiohttp.ClientTimeout(total=config.API_TIMEOUT)
        self._base = config.API_BASE_URL.rstrip("/")

    async def get_address_info(self, address: str) -> dict:
        url = f"{self._base}/{address}?details=basic"

        async with self._semaphore:
            for attempt in range(self._config.API_RETRY_ATTEMPTS):
                try:
                    async with self._session.get(url, timeout=self._timeout) as resp:
                        if resp.status == 200:
                            raw = await resp.read()
                            return _loads(raw)
                        if resp.status == 429:
                            await asyncio.sleep(self._config.API_RETRY_DELAY * (attempt + 1))
                            continue
                except (asyncio.TimeoutError, aiohttp.ClientError):
                    pass

                if attempt < self._config.API_RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(self._config.API_RETRY_DELAY * (attempt + 1))

            return {"balance": 0, "error": True}


class CandidateSeedWalletGenerator(IWalletGenerator):
    """Derives Litecoin wallets from a list of candidate seed phrases."""

    def __init__(self, candidates: list[str], passphrase: str = "") -> None:
        cleaned = [c.strip() for c in candidates if c and c.strip()]
        self._candidates = cleaned if cleaned else list(DEFAULT_CANDIDATE_SEEDS)
        self._passphrase = passphrase
        self._index = 0

    def _private_key_from_mnemonic(self, mnemonic: str) -> str:
        try:
            hd = HDWallet.from_mnemonic(mnemonic, passphrase=self._passphrase)
            for attr in ("private_key_hex", "private_key", "privkey"):
                val = getattr(hd, attr, None)
                if isinstance(val, str) and len(val) == 64:
                    return val
        except Exception:
            pass

        seed_bytes = hashlib.pbkdf2_hmac(
            "sha512",
            mnemonic.encode("utf-8"),
            f"mnemonic{self._passphrase}".encode("utf-8"),
            2048,
            dklen=32,
        )
        return seed_bytes.hex()

    def generate(self) -> GeneratedWallet:
        mnemonic = self._candidates[self._index % len(self._candidates)]
        self._index += 1
        private_key = self._private_key_from_mnemonic(mnemonic)
        wallet = Wallet(private_key)

        addresses = [
            WalletAddress(
                address=wallet.get_address("litecoin", address_type=addr_type.value),
                address_type=addr_type,
            )
            for addr_type in ADDRESS_TYPES
        ]

        return GeneratedWallet(
            mnemonic=mnemonic,
            private_key=private_key,
            addresses=addresses,
        )


def load_candidate_seeds(config: Config) -> list[str]:
    """Loads candidate seed phrases from file if configured, else returns defaults."""
    if config.CANDIDATE_SEEDS_FILE and config.CANDIDATE_SEEDS_FILE.exists():
        lines = config.CANDIDATE_SEEDS_FILE.read_text(encoding="utf-8").splitlines()
        seeds = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
        if seeds:
            return seeds
    return list(DEFAULT_CANDIDATE_SEEDS)


class RenderResultWriter(IResultWriter):
    """Writes winners to file, stdout logs, panel memory buffer, and optional webhook."""

    def __init__(
        self,
        config: Config,
        logger: logging.Logger,
        session: Optional[aiohttp.ClientSession] = None,
        recent_winners: Optional[deque[dict]] = None,
    ) -> None:
        self._config = config
        self._logger = logger
        self._session = session
        self._recent_winners = recent_winners if recent_winners is not None else deque(
            maxlen=config.MAX_RECENT_WINNERS
        )
        self._file_path = config.OUTPUT_DIR / config.WINNER_FILE.format(
            date=datetime.now().strftime("%Y%m%d")
        )
        self._lock = asyncio.Lock()

    async def write_winner(self, wallet: GeneratedWallet) -> None:
        content = self._format_wallet(wallet)
        record = wallet.to_dict(include_secrets=True)

        async with self._lock:
            self._recent_winners.appendleft(record)
            await asyncio.to_thread(self._write_to_file, content)
            print(content, flush=True)
            self._logger.warning(f"Winner saved: Total balance {wallet.total_balance}")

        if self._config.WINNER_WEBHOOK_URL and self._session is not None:
            await self._send_webhook(record)

    async def _send_webhook(self, payload: dict) -> None:
        headers = {"Content-Type": "application/json"}
        if self._config.WINNER_WEBHOOK_SECRET:
            headers["X-Webhook-Secret"] = self._config.WINNER_WEBHOOK_SECRET

        try:
            async with self._session.post(
                self._config.WINNER_WEBHOOK_URL,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10.0),
            ) as resp:
                if resp.status >= 400:
                    self._logger.warning(f"Webhook returned status {resp.status}")
        except Exception as exc:
            self._logger.warning(f"Webhook delivery failed: {exc}")

    def _write_to_file(self, content: str) -> None:
        with open(self._file_path, "a", encoding="utf-8") as f:
            f.write(content)

    def _format_wallet(self, wallet: GeneratedWallet) -> str:
        lines = [
            f"{'═' * 60}",
            f"WINNER FOUND: {wallet.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Seed Phrase: {wallet.mnemonic}",
            f"Private Key: {wallet.private_key}",
            f"{'─' * 60}",
        ]
        for addr in wallet.addresses:
            lines.append(
                f"{addr.address_type.display_name}: {addr.address} | "
                f"Balance: {addr.balance} | TxCount: {addr.tx_count}"
            )
        lines.extend([f"{'═' * 60}", ""])
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# Display Manager
# ══════════════════════════════════════════════════════════════════════════════

class DisplayManager:
    """Manages rich console output."""

    def __init__(self, console: Console) -> None:
        self._console = console

    def create_wallet_table(
        self, wallet: Optional[GeneratedWallet], stats: ScannerStats
    ) -> Table:
        table = Table(
            title=self._create_title(stats),
            title_style="bold cyan",
            header_style="bold white on dark_green",
            border_style="bright_green",
            box=box.ROUNDED,
            show_lines=False,
            row_styles=["on grey15", "on grey11", "on grey15"],
            padding=(0, 1),
            expand=False,
        )

        table.add_column("Type", justify="right", style="green_yellow bold", width=18)
        table.add_column("Address", style="white", width=45)
        table.add_column("Balance", justify="right", style="gold1", width=15)
        table.add_column("TxCount", justify="right", style="cyan", width=10)

        if wallet is not None:
            for addr in wallet.addresses:
                balance_style = "bold green" if addr.has_balance else "dim"
                table.add_row(
                    addr.address_type.display_name,
                    addr.address,
                    f"[{balance_style}]{addr.balance:,}[/]",
                    str(addr.tx_count),
                )

        return table

    def create_stats_panel(self, stats: ScannerStats) -> Panel:
        content = (
            f"[cyan]Scanned:[/] {stats.total_scanned:,} | "
            f"[green]Winners:[/] {stats.winners_found} | "
            f"[yellow]Rate:[/] {stats.scan_rate:.2f}/s | "
            f"[magenta]Elapsed:[/] {stats.elapsed_time} | "
            f"[red]Errors:[/] {stats.api_errors}"
        )
        return Panel(content, title="Statistics", border_style="blue")

    def _create_title(self, stats: ScannerStats) -> str:
        return (
            f"[bold gold1]Litecoin Candidate Scanner[/] | "
            f"[cyan]Scan #{stats.total_scanned:,}[/] | "
            f"[green]Winners: {stats.winners_found}[/]"
        )

    def print_banner(self) -> None:
        banner = """
[bold cyan]╔══════════════════════════════════════════════════════════════════╗
║[/][bold gold1]       LITECOIN CANDIDATE SEED SCANNER - PRO EDITION        [/][bold cyan]║
║══════════════════════════════════════════════════════════════════║
║[/]  [dim]Targeted Candidate Seed & Litecoin Balance Checker[/]         [bold cyan]║
║[/]  [dim]Press Ctrl+C to stop scanning gracefully[/]                     [bold cyan]║
╚══════════════════════════════════════════════════════════════════╝[/]
"""
        self._console.print(banner)


# ══════════════════════════════════════════════════════════════════════════════
# Main Scanner Engine
# ══════════════════════════════════════════════════════════════════════════════

class LitecoinScanner:
    """Concurrent pipelined candidate seed scanner with live runtime controls."""

    def __init__(
        self,
        config: Config,
        api: IBlockchainAPI,
        generator: IWalletGenerator,
        writer: IResultWriter,
        display: DisplayManager,
        logger: logging.Logger,
        console: Console,
        semaphore: Optional[DynamicSemaphore] = None,
        recent_winners: Optional[deque[dict]] = None,
    ) -> None:
        self._config = config
        self._api = api
        self._generator = generator
        self._writer = writer
        self._display = display
        self._logger = logger
        self._console = console
        self._semaphore = semaphore or DynamicSemaphore(config.MAX_CONCURRENT_REQUESTS)
        self._recent_winners = recent_winners if recent_winners is not None else deque(
            maxlen=config.MAX_RECENT_WINNERS
        )
        self._stats = ScannerStats()
        self._running = True
        self._paused = False
        self._workers_target = max(1, config.WORKERS)
        self._request_delay = max(0.0, config.REQUEST_DELAY)
        self._latest_wallet: Optional[GeneratedWallet] = None
        self._worker_tasks: list[asyncio.Task] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def stats(self) -> ScannerStats:
        return self._stats

    def runtime_info(self) -> dict:
        s = self._stats
        return {
            "status": "stopped" if not self._running else ("paused" if self._paused else "running"),
            "paused": self._paused,
            "mode": "candidate-seeds",
            "workers": self._workers_target,
            "max_concurrent_requests": self._semaphore.limit,
            "request_delay": self._request_delay,
            "webhook_enabled": bool(self._config.WINNER_WEBHOOK_URL),
            "total_scanned": s.total_scanned,
            "winners_found": s.winners_found,
            "api_errors": s.api_errors,
            "scan_rate_per_sec": round(s.scan_rate, 2),
            "elapsed": s.elapsed_time,
            "latest_wallet": self._latest_wallet.to_dict(include_secrets=False) if self._latest_wallet else None,
            "recent_winners": list(self._recent_winners),
        }

    def _reconcile_workers(self) -> None:
        if not self._running or self._loop is None:
            return
        self._worker_tasks = [t for t in self._worker_tasks if not t.done()]
        desired = 0 if self._paused else self._workers_target
        while len(self._worker_tasks) < desired:
            self._worker_tasks.append(self._loop.create_task(self._worker()))
        while len(self._worker_tasks) > desired:
            task = self._worker_tasks.pop()
            task.cancel()

    async def set_paused(self, paused: bool) -> dict:
        self._paused = bool(paused)
        self._reconcile_workers()
        return self.runtime_info()

    async def update_runtime_config(
        self,
        workers: Optional[int] = None,
        max_concurrent_requests: Optional[int] = None,
        request_delay: Optional[float] = None,
    ) -> dict:
        if workers is not None:
            self._workers_target = max(1, min(256, int(workers)))
        if max_concurrent_requests is not None:
            await self._semaphore.set_limit(max(1, min(512, int(max_concurrent_requests))))
        if request_delay is not None:
            self._request_delay = max(0.0, min(60.0, float(request_delay)))
        self._reconcile_workers()
        return self.runtime_info()

    async def scan_once(self) -> dict:
        wallet = self._generator.generate()
        await self.process_wallet(wallet)
        return wallet.to_dict(include_secrets=False)

    async def _fetch_address_info(self, address: WalletAddress) -> None:
        try:
            info = await self._api.get_address_info(address.address)
            address.balance = int(info.get("balance", 0) or 0)
            address.total_received = int(info.get("totalReceived", 0) or 0)
            address.total_sent = int(info.get("totalSent", 0) or 0)
            address.tx_count = int(info.get("txs", 0) or 0)

            if info.get("error"):
                self._stats.api_errors += 1
        except (ValueError, TypeError) as e:
            self._logger.error(f"Error parsing response for {address.address}: {e}")
            self._stats.api_errors += 1

    async def process_wallet(self, wallet: GeneratedWallet) -> None:
        await asyncio.gather(*(self._fetch_address_info(a) for a in wallet.addresses))

        if wallet.has_any_balance:
            self._stats.winners_found += 1
            await self._writer.write_winner(wallet)

        self._stats.total_scanned += 1
        self._latest_wallet = wallet

    async def _worker(self) -> None:
        while self._running and not self._paused:
            wallet = self._generator.generate()
            await self.process_wallet(wallet)
            if self._request_delay > 0 and self._running and not self._paused:
                await asyncio.sleep(self._request_delay)

    async def _ui_loop(self, live: Live) -> None:
        layout = Layout()
        stats_layout = Layout(name="stats", size=3)
        table_layout = Layout(name="table")
        layout.split_column(stats_layout, table_layout)

        interval = 1.0 / max(self._config.REFRESH_PER_SECOND, 1)
        while self._running:
            stats_layout.update(self._display.create_stats_panel(self._stats))
            table_layout.update(
                self._display.create_wallet_table(self._latest_wallet, self._stats)
            )
            live.update(layout)
            await asyncio.sleep(interval)

    async def _headless_status_loop(self) -> None:
        while self._running:
            await asyncio.sleep(self._config.STATUS_LOG_INTERVAL)
            if not self._running:
                break
            state = "PAUSED" if self._paused else "RUNNING"
            print(
                f"[{state}] Scanned={self._stats.total_scanned:,} | "
                f"Winners={self._stats.winners_found} | "
                f"Rate={self._stats.scan_rate:.2f}/s | "
                f"Errors={self._stats.api_errors} | "
                f"Elapsed={self._stats.elapsed_time}",
                flush=True,
            )

    def stop(self) -> None:
        self._running = False
        for task in self._worker_tasks:
            task.cancel()

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._reconcile_workers()
        is_tty = sys.stdout.isatty()

        async def _watch_workers() -> None:
            while self._running:
                self._reconcile_workers()
                await asyncio.sleep(0.25)

        watcher = asyncio.create_task(_watch_workers())

        try:
            if is_tty:
                self._display.print_banner()
                with Live(
                    self._display.create_stats_panel(self._stats),
                    console=self._console,
                    refresh_per_second=self._config.REFRESH_PER_SECOND,
                    transient=True,
                ) as live:
                    ui_task = asyncio.create_task(self._ui_loop(live))
                    await watcher
                    ui_task.cancel()
            else:
                print(
                    f"Running candidate seed scanner on {self._config.HOST}:{self._config.PORT} "
                    f"(webhook={'ON' if self._config.WINNER_WEBHOOK_URL else 'OFF'})",
                    flush=True,
                )
                status_task = asyncio.create_task(self._headless_status_loop())
                await watcher
                status_task.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            watcher.cancel()
            for task in self._worker_tasks:
                task.cancel()
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
            self._print_summary(is_tty=is_tty)

    def _print_summary(self, is_tty: bool = True) -> None:
        if not is_tty:
            print(
                f"Scan complete | Scanned={self._stats.total_scanned:,} | "
                f"Winners={self._stats.winners_found} | "
                f"Errors={self._stats.api_errors} | "
                f"Rate={self._stats.scan_rate:.2f}/s | "
                f"Elapsed={self._stats.elapsed_time}",
                flush=True,
            )
            return

        summary = f"""
[bold green]╔══════════════════════════════════════════════════════════════════╗
║                        SCAN COMPLETE                             ║
╠══════════════════════════════════════════════════════════════════╣
║  Total Scanned  : {self._stats.total_scanned:>10,}               ║
║  Winners Found  : {self._stats.winners_found:>10,}               ║
║  API Errors     : {self._stats.api_errors:>10,}                  ║
║  Elapsed Time   : {self._stats.elapsed_time:>10}                 ║
║  Scan Rate      : {self._stats.scan_rate:>10.2f}/s               ║
╚══════════════════════════════════════════════════════════════════╝[/]
"""
        self._console.print(summary)


# ══════════════════════════════════════════════════════════════════════════════
# Render HTTP Server & Interactive HTML Panel
# ══════════════════════════════════════════════════════════════════════════════

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Litecoin Candidate Seed Scanner Panel</title>
  <style>
    :root {
      --bg: #0f1419;
      --card: #182028;
      --border: #2b3846;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #38bdf8;
      --green: #22c55e;
      --amber: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
    }
    .container { max-width: 960px; margin: 0 auto; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 20px;
    }
    h1 { margin: 0; font-size: 1.4rem; }
    .badge {
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.85rem;
      font-weight: 600;
      background: var(--card);
      border: 1px solid var(--border);
      display: inline-block;
      margin-left: 6px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 20px;
    }
    .label {
      color: var(--muted);
      font-size: 0.8rem;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .value { font-size: 1.35rem; font-weight: 700; font-variant-numeric: tabular-nums; }
    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: end;
      margin-bottom: 8px;
    }
    .field { display: flex; flex-direction: column; gap: 6px; }
    .field label { font-size: 0.8rem; color: var(--muted); }
    input {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      width: 130px;
      font-size: 0.95rem;
    }
    button {
      background: var(--accent);
      color: #081018;
      border: none;
      border-radius: 8px;
      padding: 9px 14px;
      font-weight: 600;
      cursor: pointer;
    }
    button.secondary {
      background: #25303d;
      color: var(--text);
      border: 1px solid var(--border);
    }
    button.small {
      padding: 5px 10px;
      font-size: 0.8rem;
    }
    button:hover { opacity: 0.92; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 9px 8px;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--muted); font-weight: 600; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
    .msg { color: var(--muted); font-size: 0.85rem; margin-top: 8px; min-height: 1.2em; }
    .winner-box {
      background: var(--bg);
      border: 1px solid var(--green);
      border-radius: 8px;
      padding: 12px;
      margin-top: 10px;
    }
    .winner-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 8px;
    }
    .winner-balance { color: var(--green); font-weight: 700; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Litecoin Candidate Seed Scanner Panel</h1>
      <div>
        <span id="modeBadge" class="badge">Candidate Seeds</span>
        <span id="webhookBadge" class="badge">Webhook: checking...</span>
        <span id="statusBadge" class="badge">Loading...</span>
      </div>
    </div>

    <div class="grid">
      <div class="card" style="margin-bottom:0;"><div class="label">Total Scanned</div><div id="scanned" class="value">0</div></div>
      <div class="card" style="margin-bottom:0;"><div class="label">Winners Found</div><div id="winners" class="value" style="color:var(--green);">0</div></div>
      <div class="card" style="margin-bottom:0;"><div class="label">Scan Rate</div><div id="rate" class="value">0.00/s</div></div>
      <div class="card" style="margin-bottom:0;"><div class="label">API Errors</div><div id="errors" class="value">0</div></div>
      <div class="card" style="margin-bottom:0;"><div class="label">Elapsed</div><div id="elapsed" class="value">00:00:00</div></div>
    </div>

    <div class="card">
      <div class="controls">
        <button id="toggleBtn" onclick="toggleRun()">Pause</button>
        <button class="secondary" onclick="scanOnce()">Scan 1 Candidate Now</button>
        <div class="field">
          <label for="workersInput">Workers</label>
          <input id="workersInput" type="number" min="1" max="256" step="1" />
        </div>
        <div class="field">
          <label for="concInput">Max Concurrent Reqs</label>
          <input id="concInput" type="number" min="1" max="512" step="1" />
        </div>
        <div class="field">
          <label for="delayInput">Request Delay (s)</label>
          <input id="delayInput" type="number" min="0" max="60" step="0.05" />
        </div>
        <button class="secondary" onclick="saveConfig()">Apply Settings</button>
      </div>
      <div id="feedback" class="msg"></div>
    </div>

    <div id="winnersCard" class="card">
      <div class="label">Winners Found</div>
      <div id="winnersPanel"><div class="msg">No winners found yet.</div></div>
    </div>

    <div class="card">
      <div class="label">Latest Checked Candidate (<span id="latestTime">-</span>)</div>
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Address</th>
            <th>Balance</th>
            <th>TxCount</th>
          </tr>
        </thead>
        <tbody id="walletRows">
          <tr><td colspan="4" style="color: var(--muted);">Waiting for scan data...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let inputsInitialized = false;

    function setFeedback(text) {
      document.getElementById("feedback").textContent = text;
    }

    function el(tag, className, text) {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined && text !== null) node.textContent = String(text);
      return node;
    }

    function copyText(text, btn) {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => { btn.textContent = orig; }, 1200);
      }).catch(() => {});
    }

    function buildAddressTable(addresses) {
      const table = document.createElement("table");
      const thead = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["Type", "Address", "Balance", "TxCount"].forEach(h => {
        headRow.appendChild(el("th", "", h));
      });
      thead.appendChild(headRow);
      table.appendChild(thead);

      const tbody = document.createElement("tbody");
      (addresses || []).forEach(a => {
        const tr = document.createElement("tr");
        tr.appendChild(el("td", "", a.type || ""));
        tr.appendChild(el("td", "mono", a.address || ""));
        tr.appendChild(el("td", "", Number(a.balance || 0).toLocaleString()));
        tr.appendChild(el("td", "", Number(a.tx_count || 0).toLocaleString()));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      return table;
    }

    function renderWinners(winners) {
      const container = document.getElementById("winnersPanel");
      container.replaceChildren();

      if (!Array.isArray(winners) || winners.length === 0) {
        container.appendChild(el("div", "msg", "No winners found yet."));
        return;
      }

      winners.forEach((w, idx) => {
        const box = el("div", "winner-box");
        const top = el("div", "winner-top");

        const meta = document.createElement("div");
        meta.appendChild(el("strong", "", `#${idx + 1}`));
        meta.appendChild(document.createTextNode(` · ${w.generated_at || ""} · `));
        meta.appendChild(
          el("span", "winner-balance", `Total Balance: ${Number(w.total_balance || 0).toLocaleString()}`)
        );

        const copySeedBtn = el("button", "secondary small", "Copy Seed");
        copySeedBtn.type = "button";
        copySeedBtn.addEventListener("click", () => copyText(w.mnemonic || "", copySeedBtn));

        top.appendChild(meta);
        top.appendChild(copySeedBtn);
        box.appendChild(top);

        const seedLine = el("div", "mono");
        seedLine.style.marginBottom = "6px";
        seedLine.appendChild(el("strong", "", "Seed Phrase: "));
        seedLine.appendChild(document.createTextNode(w.mnemonic || ""));
        box.appendChild(seedLine);

        const keyLine = el("div", "mono");
        keyLine.style.marginBottom = "8px";
        keyLine.appendChild(el("strong", "", "Private Key: "));
        keyLine.appendChild(document.createTextNode(w.private_key || ""));
        box.appendChild(keyLine);

        box.appendChild(buildAddressTable(w.addresses));
        container.appendChild(box);
      });
    }

    function renderLatestWallet(latest) {
      const tbody = document.getElementById("walletRows");
      if (!latest || !Array.isArray(latest.addresses) || latest.addresses.length === 0) {
        return;
      }
      document.getElementById("latestTime").textContent = latest.generated_at || "-";
      tbody.replaceChildren();
      latest.addresses.forEach(a => {
        const tr = document.createElement("tr");
        tr.appendChild(el("td", "", a.type || ""));
        tr.appendChild(el("td", "mono", a.address || ""));
        tr.appendChild(el("td", "", Number(a.balance || 0).toLocaleString()));
        tr.appendChild(el("td", "", Number(a.tx_count || 0).toLocaleString()));
        tbody.appendChild(tr);
      });
    }

    function renderState(data) {
      if (data.mode) {
        document.getElementById("modeBadge").textContent = `Mode: ${data.mode}`;
      }

      const status = data.status || "unknown";
      const badge = document.getElementById("statusBadge");
      badge.textContent = status.toUpperCase();
      badge.style.color = status === "running" ? "#22c55e" : "#f59e0b";

      const wh = document.getElementById("webhookBadge");
      const whOn = Boolean(data.webhook_enabled);
      wh.textContent = whOn ? "Webhook: ON" : "Webhook: OFF";
      wh.style.color = whOn ? "#22c55e" : "#8b949e";

      document.getElementById("scanned").textContent = Number(data.total_scanned || 0).toLocaleString();
      document.getElementById("winners").textContent = Number(data.winners_found || 0).toLocaleString();
      document.getElementById("rate").textContent = `${Number(data.scan_rate_per_sec || 0).toFixed(2)}/s`;
      document.getElementById("errors").textContent = Number(data.api_errors || 0).toLocaleString();
      document.getElementById("elapsed").textContent = data.elapsed || "00:00:00";
      document.getElementById("toggleBtn").textContent = data.paused ? "Resume" : "Pause";

      if (!inputsInitialized) {
        document.getElementById("workersInput").value = data.workers ?? 16;
        document.getElementById("concInput").value = data.max_concurrent_requests ?? 32;
        document.getElementById("delayInput").value = data.request_delay ?? 0;
        inputsInitialized = true;
      }

      renderWinners(data.recent_winners);
      renderLatestWallet(data.latest_wallet);
    }

    async function refreshStats() {
      try {
        const res = await fetch("/stats", { cache: "no-store" });
        if (!res.ok) return;
        const data = await res.json();
        renderState(data);
      } catch (_) {}
    }

    async function toggleRun() {
      const res = await fetch("/api/toggle", { method: "POST" });
      const data = await res.json();
      renderState(data);
      setFeedback(data.paused ? "Scanner paused." : "Scanner resumed.");
    }

    async function saveConfig() {
      const payload = {
        workers: Number(document.getElementById("workersInput").value),
        max_concurrent_requests: Number(document.getElementById("concInput").value),
        request_delay: Number(document.getElementById("delayInput").value),
      };
      const res = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      inputsInitialized = false;
      renderState(data);
      setFeedback("Settings updated.");
    }

    async function scanOnce() {
      setFeedback("Scanning single candidate...");
      const res = await fetch("/api/scan-once", { method: "POST" });
      const wallet = await res.json();
      renderLatestWallet(wallet);
      setFeedback("Single candidate check complete.");
      refreshStats();
    }

    refreshStats();
    setInterval(refreshStats, 1500);
  </script>
</body>
</html>
"""


async def start_render_server(config: Config, scanner: LitecoinScanner) -> web.AppRunner:
