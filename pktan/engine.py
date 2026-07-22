"""Glue: a background thread that pulls frames, decodes, filters and feeds Stats."""
from __future__ import annotations

import threading
from typing import Callable

from .capture import file_frames, live_frames
from .decode import Packet, decode
from .pcap import PcapWriter
from .stats import Stats


class Engine:
    def __init__(self, iface: str | None = None, read: str | None = None,
                 flt: Callable[[Packet], bool] = lambda p: True,
                 write: str | None = None, max_mb: float = 50, count: int = 0,
                 realtime: bool = False, promisc: bool = True,
                 on_packet: Callable[[Packet], None] | None = None,
                 notifier=None, archiver=None, known=None, engine: str = "python",
                 feature_log=None, forest=None, flush_windows: bool = False):
        """engine: "python" (pure stdlib) or "c" (csrc/pktcap does capture and L2-L4)."""
        self.iface, self.read, self.flt = iface, read, flt
        self.engine = engine
        self.count, self.realtime, self.promisc = count, realtime, promisc
        self.on_packet = on_packet
        self.notifier, self.archiver = notifier, archiver
        self.stats = Stats(on_alert=notifier.notify if notifier else None, known=known,
                           feature_log=feature_log, forest=forest)
        self.flush_windows = flush_windows      # close the last partial window at the end
        self.writer = PcapWriter(write, int(max_mb * 1024 * 1024),
                                 on_rotate=archiver.rotated if archiver else None) if write else None
        self.error: BaseException | None = None
        self.done = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="pktan-capture", daemon=True)

    def start(self) -> "Engine":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _frames(self):
        stop = self._stop.is_set
        if self.read:
            return file_frames(self.read, realtime=self.realtime, stop=stop)
        return live_frames(self.iface, promisc=self.promisc, stop=stop)

    def _packets(self):
        """Yield (Packet, raw frame or None, linktype) from the chosen engine."""
        if self.engine == "c":
            from .cengine import c_packets
            yield from c_packets(self.iface, self.read, all_frames=self.writer is not None,
                                 promisc=self.promisc, stop=self._stop.is_set,
                                 on_snapshot=self.stats.set_engine_snapshot)
            return
        for ts, data, orig, lt, ifname in self._frames():
            yield decode(data, ts, orig, lt, ifname), data, lt

    def _run(self) -> None:
        matched = 0
        try:
            uses_aws = self.notifier is not None or self.archiver is not None
            if uses_aws:
                from .aws import is_own_traffic
            for p, data, lt in self._packets():
                if not self.flt(p):
                    continue
                matched += 1
                # pktan's own uploads are real traffic for the counters, but must not
                # be saved (they'd be uploaded again, forever) or count as anomalies
                own = uses_aws and p.proto == "TCP" and is_own_traffic(p.sport, p.dport)
                self.stats.add(p, features=not own)
                if self.writer and data is not None and not own:
                    self.writer.write(p.ts, data, p.length, lt)
                if self.on_packet:
                    self.on_packet(p)
                if self.count and matched >= self.count:
                    break
        except BaseException as e:   # surfaced to the main thread
            self.error = e
        finally:
            with self.stats.lock:
                self.stats.known.save(force=True)
                if self.flush_windows and self.stats.windows:
                    self.stats.windows.flush()
            if self.writer:
                if self.archiver:
                    # upload the last file here, synchronously, before exiting
                    self.writer.on_rotate = self.archiver.queue
                    self.writer.finish()
                    self.archiver.drain()
                else:
                    self.writer.close()
            if self.notifier:
                self.notifier.close()
            self.done.set()
