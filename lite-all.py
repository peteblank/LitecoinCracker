# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
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

    # Render / HTTP Port Binding
    HOST: str = "0.0.0.0"
    PORT: int = field(default_factory=lambda: int(os.environ.get("PORT", "10000")))
    STATUS_LOG_INTERVAL: float = 15.0

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


class LitecoinAPI(IBlockchainAPI):
    """High-throughput Litecoin blockchain API client with pooled connections."""

    def __init__(
        self,
        config: Config,
        logger: logging.Logger,
        session: aiohttp.ClientSession,
    ) -> None:
        self._config = config
        self._logger = logger
        self._session = session
        self._semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_REQUESTS)
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


class FileResultWriter(IResultWriter):
    """Writes winning wallets to file."""

    def __init__(self, config: Config, logger: logging.Logger) -> None:
        self._config = config
        self._logger = logger
        self._file_path = config.OUTPUT_DIR / config.WINNER_FILE.format(
            date=datetime.now().strftime("%Y%m%d")
        )
        self._lock = asyncio.Lock()

    async def write_winner(self, wallet: GeneratedWallet) -> None:
        async with self._lock:
            content = self._format_wallet(wallet)
            await asyncio.to_thread(self._write_to_file, content)
            self._logger.warning(f"Winner saved: Total balance {wallet.total_balance}")

    def _write_to_file(self, content: str) -> None:
        with open(self._file_path, "a", encoding="utf-8") as f:
            f.write(content)

    def _format_wallet(self, wallet: GeneratedWallet) -> str:
        lines = [
            f"{'═' * 60}",
            f"Found: {wallet.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
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
    """Concurrent pipelined scanner orchestrator."""

    def __init__(
        self,
        config: Config,
        api: IBlockchainAPI,
        generator: IWalletGenerator,
        writer: IResultWriter,
        display: DisplayManager,
        logger: logging.Logger,
        console: Console,
    ) -> None:
        self._config = config
        self._api = api
        self._generator = generator
        self._writer = writer
        self._display = display
        self._logger = logger
        self._console = console
        self._stats = ScannerStats()
        self._running = True
        self._latest_wallet: Optional[GeneratedWallet] = None

    @property
    def stats(self) -> ScannerStats:
        return self._stats

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
        while self._running:
            wallet = self._generator.generate()
            await self.process_wallet(wallet)
            if self._config.REQUEST_DELAY > 0:
                await asyncio.sleep(self._config.REQUEST_DELAY)

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
            print(
                f"Scanned={self._stats.total_scanned:,} | "
                f"Winners={self._stats.winners_found} | "
                f"Rate={self._stats.scan_rate:.2f}/s | "
                f"Errors={self._stats.api_errors} | "
                f"Elapsed={self._stats.elapsed_time}",
                flush=True,
            )

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        workers = [asyncio.create_task(self._worker()) for _ in range(self._config.WORKERS)]
        is_tty = sys.stdout.isatty()

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
                    await asyncio.gather(*workers)
                    ui_task.cancel()
            else:
                print(
                    f"Running in headless mode on {self._config.HOST}:{self._config.PORT}",
                    flush=True,
                )
                status_task = asyncio.create_task(self._headless_status_loop())
                await asyncio.gather(*workers)
                status_task.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            await asyncio.gather(*workers, return_exceptions=True)
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
# Render HTTP Health / Status Server
# ══════════════════════════════════════════════════════════════════════════════

async def start_render_server(config: Config, scanner: LitecoinScanner) -> web.AppRunner:
    """Bind an HTTP server to 0.0.0.0:$PORT for Render Web Service health checks."""

    async def handle_health(_request: web.Request) -> web.Response:
        return web.Response(text="ok", status=200)

    async def handle_stats(_request: web.Request) -> web.Response:
        s = scanner.stats
        payload = {
            "status": "running" if scanner._running else "stopping",
            "total_scanned": s.total_scanned,
            "winners_found": s.winners_found,
            "api_errors": s.api_errors,
            "scan_rate_per_sec": round(s.scan_rate, 2),
            "elapsed": s.elapsed_time,
        }
        return web.json_response(payload)

    app = web.Application()
    app.router.add_get("/", handle_health)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/stats", handle_stats)

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

    connector = aiohttp.TCPConnector(
        limit=config.MAX_CONCURRENT_REQUESTS * 2,
        limit_per_host=config.MAX_CONCURRENT_REQUESTS,
        ttl_dns_cache=300,
    )

    runner: Optional[web.AppRunner] = None

    async with aiohttp.ClientSession(connector=connector) as session:
        api = LitecoinAPI(config, logger, session)
        generator = LitecoinWalletGenerator()
        writer = FileResultWriter(config, logger)
        display = DisplayManager(console)

        scanner = LitecoinScanner(
            config=config,
            api=api,
            generator=generator,
            writer=writer,
            display=display,
            logger=logger,
            console=console,
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
