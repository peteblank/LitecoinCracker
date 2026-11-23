# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
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
from libcrypto import Wallet
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

    # Pipeline & Concurrency Settings
    WORKERS: int = 32
    MAX_CONCURRENT_REQUESTS: int = 64
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
    MAX_RECENT_WINNERS: int = 25

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
    """Represents a complete generated wallet with all address types."""

    private_key: str
    addresses: list[WalletAddress]
    generated_at: datetime = field(default_factory=datetime.now)

    @property
    def has_any_balance(self) -> bool:
        return any(addr.has_balance for addr in self.addresses)

    @property
    def total_balance(self) -> int:
        return sum(addr.balance for addr in self.addresses)

    def to_dict(self, include_private_key: bool = False) -> dict:
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
        if include_private_key:
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


class LitecoinWalletGenerator(IWalletGenerator):
    """Generates Litecoin wallets using cryptographic randomness."""

    def generate(self) -> GeneratedWallet:
        private_key = os.urandom(32).hex()
        wallet = Wallet(private_key)

        addresses = [
            WalletAddress(
                address=wallet.get_address("litecoin", address_type=addr_type.value),
                address_type=addr_type,
            )
            for addr_type in ADDRESS_TYPES
        ]

        return GeneratedWallet(private_key=private_key, addresses=addresses)


class RenderResultWriter(IResultWriter):
    """Writes winners to file, stdout logs, memory buffer, and optional webhook."""

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
        record = wallet.to_dict(include_private_key=True)

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
            f"[bold gold1]Litecoin Scanner[/] | "
            f"[cyan]Scan #{stats.total_scanned:,}[/] | "
            f"[green]Winners: {stats.winners_found}[/]"
        )

    def print_banner(self) -> None:
        banner = """
[bold cyan]╔══════════════════════════════════════════════════════════════════╗
║[/][bold gold1]          LITECOIN WALLET SCANNER - PRO EDITION            [/][bold cyan]║
║══════════════════════════════════════════════════════════════════║
║[/]  [dim]High-Performance Address Generator & Balance Checker[/]         [bold cyan]║
║[/]  [dim]Press Ctrl+C to stop scanning gracefully[/]                     [bold cyan]║
╚══════════════════════════════════════════════════════════════════╝[/]
"""
        self._console.print(banner)


# ══════════════════════════════════════════════════════════════════════════════
# Main Scanner Engine
# ══════════════════════════════════════════════════════════════════════════════

class LitecoinScanner:
    """Concurrent pipelined scanner orchestrator with live runtime controls."""

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
            "workers": self._workers_target,
            "max_concurrent_requests": self._semaphore.limit,
            "request_delay": self._request_delay,
            "webhook_enabled": bool(self._config.WINNER_WEBHOOK_URL),
            "total_scanned": s.total_scanned,
            "winners_found": s.winners_found,
            "api_errors": s.api_errors,
            "scan_rate_per_sec": round(s.scan_rate, 2),
            "elapsed": s.elapsed_time,
            "latest_wallet": self._latest_wallet.to_dict(include_private_key=False) if self._latest_wallet else None,
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
        return wallet.to_dict(include_private_key=False)

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
                    f"Running in headless mode on {self._config.HOST}:{self._config.PORT} "
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
# Render HTTP Server & Interactive HTML Page
# ══════════════════════════════════════════════════════════════════════════════

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Litecoin Scanner Control</title>
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
    .container { max-width: 920px; margin: 0 auto; }
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
    }
    .label { color: var(--muted); font-size: 0.8rem; margin-bottom: 6px; }
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
    button:hover { opacity: 0.92; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--muted); font-weight: 600; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
    .msg { color: var(--muted); font-size: 0.85rem; margin-top: 8px; min-height: 1.2em; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Litecoin Scanner</h1>
      <div>
        <span id="webhookBadge" class="badge">Webhook: checking...</span>
        <span id="statusBadge" class="badge">Loading...</span>
      </div>
    </div>

    <div class="grid">
      <div class="card"><div class="label">Total Scanned</div><div id="scanned" class="value">0</div></div>
      <div class="card"><div class="label">Winners Found</div><div id="winners" class="value">0</div></div>
      <div class="card"><div class="label">Scan Rate</div><div id="rate" class="value">0.00/s</div></div>
      <div class="card"><div class="label">API Errors</div><div id="errors" class="value">0</div></div>
      <div class="card"><div class="label">Elapsed</div><div id="elapsed" class="value">00:00:00</div></div>
    </div>

    <div class="card" style="margin-bottom: 20px;">
      <div class="controls">
        <button id="toggleBtn" onclick="toggleRun()">Pause</button>
        <button class="secondary" onclick="scanOnce()">Scan 1 Wallet Now</button>
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

    <div class="card" style="margin-bottom: 20px;">
      <div class="label">Recent Winners (In-Memory Session Buffer)</div>
      <div id="recentWinners" class="msg">No winners found yet.</div>
    </div>

    <div class="card">
      <div class="label">Latest Checked Wallet (<span id="latestTime">-</span>)</div>
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

    function renderState(data) {
      const badge = document.getElementById("statusBadge");
      badge.textContent = data.status.toUpperCase();
      badge.style.color = data.status === "running" ? "#22c55e" : "#f59e0b";

      const wh = document.getElementById("webhookBadge");
      wh.textContent = data.webhook_enabled ? "Webhook: ON" : "Webhook: OFF";
      wh.style.color = data.webhook_enabled ? "#22c55e" : "#8b949e";

      document.getElementById("scanned").textContent = Number(data.total_scanned).toLocaleString();
      document.getElementById("winners").textContent = Number(data.winners_found).toLocaleString();
      document.getElementById("rate").textContent = `${Number(data.scan_rate_per_sec).toFixed(2)}/s`;
      document.getElementById("errors").textContent = Number(data.api_errors).toLocaleString();
      document.getElementById("elapsed").textContent = data.elapsed;
      document.getElementById("toggleBtn").textContent = data.paused ? "Resume" : "Pause";

      if (!inputsInitialized) {
        document.getElementById("workersInput").value = data.workers;
        document.getElementById("concInput").value = data.max_concurrent_requests;
        document.getElementById("delayInput").value = data.request_delay;
        inputsInitialized = true;
      }

      const rw = document.getElementById("recentWinners");
      if (Array.isArray(data.recent_winners) && data.recent_winners.length > 0) {
        rw.innerHTML = data.recent_winners.map(w => `
          <div style="margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid var(--border);">
            <div><strong>${w.generated_at}</strong> | Total Balance: <strong>${w.total_balance}</strong></div>
            <div class="mono">Key: ${w.private_key}</div>
          </div>
        `).join("");
      } else {
        rw.textContent = "No winners found yet.";
      }

      const tbody = document.getElementById("walletRows");
      const latest = data.latest_wallet;
      if (!latest || !latest.addresses || latest.addresses.length === 0) {
        return;
      }
      document.getElementById("latestTime").textContent = latest.generated_at;
      tbody.innerHTML = latest.addresses.map(a => `
        <tr>
          <td>${a.type}</td>
          <td class="mono">${a.address}</td>
          <td>${Number(a.balance).toLocaleString()}</td>
          <td>${Number(a.tx_count).toLocaleString()}</td>
        </tr>
      `).join("");
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
      setFeedback("Scanning single wallet...");
      const res = await fetch("/api/scan-once", { method: "POST" });
      const wallet = await res.json();
      document.getElementById("latestTime").textContent = wallet.generated_at;
      document.getElementById("walletRows").innerHTML = wallet.addresses.map(a => `
        <tr>
          <td>${a.type}</td>
          <td class="mono">${a.address}</td>
          <td>${Number(a.balance).toLocaleString()}</td>
          <td>${Number(a.tx_count).toLocaleString()}</td>
        </tr>
      `).join("");
      setFeedback("Single wallet check complete.");
      refreshStats();
    }

    refreshStats();
    setInterval(refreshStats, 1500);
  </script>
</body>
</html>
"""


async def start_render_server(config: Config, scanner: LitecoinScanner) -> web.AppRunner:
    """Bind an HTTP server to 0.0.0.0:$PORT with an interactive HTML UI and control API."""

    async def handle_index(_request: web.Request) -> web.Response:
        return web.Response(text=HTML_PAGE, content_type="text/html", status=200)

    async def handle_health(_request: web.Request) -> web.Response:
        return web.Response(text="ok", status=200)

    async def handle_stats(_request: web.Request) -> web.Response:
        return web.json_response(scanner.runtime_info())

    async def handle_toggle(_request: web.Request) -> web.Response:
        info = await scanner.set_paused(not scanner._paused)
        return web.json_response(info)

    async def handle_config(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        info = await scanner.update_runtime_config(
            workers=body.get("workers"),
            max_concurrent_requests=body.get("max_concurrent_requests"),
            request_delay=body.get("request_delay"),
        )
        return web.json_response(info)

    async def handle_scan_once(_request: web.Request) -> web.Response:
        result = await scanner.scan_once()
        return web.json_response(result)

    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_stats)
    app.router.add_post("/api/toggle", handle_toggle)
    app.router.add_post("/api/config", handle_config)
    app.router.add_post("/api/scan-once", handle_scan_once)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host=config.HOST, port=config.PORT)
    await site.start()
    return runner


# ══════════════════════════════════════════════════════════════════════════════
# Application Entry Point
# ══════════════════════════════════════════════════════════════════════════════

async def main() -> None:
    config = Config()
    console = Console()
    logger = setup_logging(config)
    semaphore = DynamicSemaphore(config.MAX_CONCURRENT_REQUESTS)
    recent_winners: deque[dict] = deque(maxlen=config.MAX_RECENT_WINNERS)

    connector = aiohttp.TCPConnector(
        limit=max(config.MAX_CONCURRENT_REQUESTS * 2, 128),
        limit_per_host=0,
        ttl_dns_cache=300,
    )

    runner: Optional[web.AppRunner] = None

    async with aiohttp.ClientSession(connector=connector) as session:
        api = LitecoinAPI(config, logger, session, semaphore=semaphore)
        generator = LitecoinWalletGenerator()
        writer = RenderResultWriter(config, logger, session=session, recent_winners=recent_winners)
        display = DisplayManager(console)

        scanner = LitecoinScanner(
            config=config,
            api=api,
            generator=generator,
            writer=writer,
            display=display,
            logger=logger,
            console=console,
            semaphore=semaphore,
            recent_winners=recent_winners,
        )

        runner = await start_render_server(config, scanner)

        loop = asyncio.get_running_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, scanner.stop)

        try:
            await scanner.run()
        except KeyboardInterrupt:
            scanner.stop()
        finally:
            if runner is not None:
                await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScanner terminated by user.")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
