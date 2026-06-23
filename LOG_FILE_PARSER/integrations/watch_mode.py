"""
integrations/watch_mode.py  -  Anomaly Hunter Pro
===================================================
Real-time log file monitoring using watchdog.

Watches a log file for new lines and runs the detection
pipeline on each batch of new events.

Usage:
  python main.py --log logs.csv --watch
  python main.py --log /var/log/syslog --watch --watch-interval 30
"""

import sys
import time
import logging
import threading
from datetime import datetime
from pathlib import Path

import pandas as pd

log = logging.getLogger("AnomalyHunter.WatchMode")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False
    log.warning("watchdog not installed — watch mode unavailable. pip install watchdog")


class LogFileHandler(FileSystemEventHandler):
    """Watchdog handler that tracks new lines appended to a log file."""

    def __init__(self, log_file: str, callback, schema_map=None,
                 min_batch: int = 10, max_wait: float = 5.0):
        self.log_file   = str(log_file)
        self.callback   = callback
        self.schema_map = schema_map
        self.min_batch  = min_batch
        self.max_wait   = max_wait
        self._position  = self._get_file_size()
        self._buffer    = []
        self._last_flush= time.time()
        self._header    = None
        self._lock      = threading.Lock()
        log.info("Watch mode: monitoring %s (position=%d)", log_file, self._position)

    def _get_file_size(self) -> int:
        try:
            return Path(self.log_file).stat().st_size
        except Exception:
            return 0

    def on_modified(self, event):
        if event.src_path != self.log_file:
            return
        self._read_new_lines()

    def _read_new_lines(self):
        try:
            current_size = self._get_file_size()
            if current_size <= self._position:
                return

            with open(self.log_file, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._position)
                new_content = f.read(current_size - self._position)
                self._position = f.tell()

            lines = new_content.splitlines()
            if not lines:
                return

            with self._lock:
                self._buffer.extend(lines)

            # Flush if batch large enough or time exceeded
            should_flush = (
                len(self._buffer) >= self.min_batch or
                (time.time() - self._last_flush) >= self.max_wait
            )
            if should_flush:
                self._flush_buffer()

        except Exception as e:
            log.error("Error reading new lines: %s", e)

    def _flush_buffer(self):
        with self._lock:
            if not self._buffer:
                return
            lines = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.time()

        try:
            # Re-parse lines as CSV using the header from first read
            if self._header is None:
                # Read header from file start
                with open(self.log_file, "r", encoding="utf-8") as f:
                    self._header = f.readline().strip()

            import io
            csv_content = self._header + "\n" + "\n".join(lines)
            new_df = pd.read_csv(io.StringIO(csv_content), low_memory=False).fillna("")
            if not new_df.empty:
                log.info("Watch: processing batch of %d new events", len(new_df))
                self.callback(new_df, self.schema_map)
        except Exception as e:
            log.error("Error processing batch: %s", e)

    def force_flush(self):
        """Force flush any remaining buffered lines."""
        self._flush_buffer()


def start_watch_mode(log_file: str, process_fn, schema_map=None,
                     interval: float = 2.0, notifiers=None):
    """
    Start watching a log file for new events.

    Args:
        log_file:   Path to the log CSV file to monitor
        process_fn: Callable(new_df, schema_map) called with each batch
        schema_map: Pre-built schema map (or None to auto-detect per batch)
        interval:   Check interval in seconds
        notifiers:  List of notifier callables for alert delivery
    """
    if not WATCHDOG_OK:
        log.error("watchdog library not available — install with: pip install watchdog")
        return

    log_path = Path(log_file)
    if not log_path.exists():
        log.error("Log file not found: %s", log_file)
        return

    def _wrapped_process(new_df, sm):
        """Process new events and optionally send notifications."""
        try:
            from schema_mapper import build_schema_map, normalise_dataframe
            from core.vectorised_detectors import run_vectorised_detectors
            from correlation.risk_engine import enrich_alerts

            # Use existing schema map or build fresh
            if sm is None:
                sm = build_schema_map(new_df)

            norm_df   = normalise_dataframe(new_df, sm)
            raw_alerts = run_vectorised_detectors(norm_df, sm)

            if raw_alerts.empty:
                return

            enriched = enrich_alerts(raw_alerts)
            critical = enriched[enriched["Severity"].isin(["CRITICAL", "HIGH"])]

            if critical.empty:
                return

            log.warning("WATCH ALERT: %d HIGH/CRITICAL alerts in new batch",
                        len(critical))

            # Print to terminal
            print(f"\n{'='*60}")
            print(f"  ⚠  ANOMALY HUNTER — LIVE ALERT  [{datetime.now().strftime('%H:%M:%S')}]")
            print(f"{'='*60}")
            for _, row in critical.head(5).iterrows():
                proc  = str(row.get("Process","")).split("\\")[-1]
                det   = str(row.get("Detection Type",""))[:50]
                score = row.get("Risk Score", 0)
                sev   = row.get("Severity","")
                print(f"  [{sev}] {proc}  |  {det}  |  score={score}")
            print(f"{'='*60}\n")

            # Send notifications
            if notifiers:
                for notify_fn in notifiers:
                    try:
                        notify_fn(critical)
                    except Exception as e:
                        log.error("Notifier failed: %s", e)

        except Exception as e:
            log.error("Watch mode processing error: %s", e, exc_info=True)

    handler  = LogFileHandler(log_file, _wrapped_process, schema_map)
    observer = Observer()
    observer.schedule(handler, str(log_path.parent), recursive=False)
    observer.start()

    log.info("Watch mode active — monitoring %s (Ctrl+C to stop)", log_file)
    print(f"\n  Anomaly Hunter — Watch Mode")
    print(f"  Monitoring: {log_file}")
    print(f"  Press Ctrl+C to stop\n")

    try:
        while True:
            time.sleep(interval)
            handler.force_flush()
    except KeyboardInterrupt:
        log.info("Watch mode stopped by user")
        observer.stop()
    finally:
        observer.join()
        log.info("Watch mode: observer joined")
