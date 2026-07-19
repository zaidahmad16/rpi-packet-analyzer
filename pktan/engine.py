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
                 notifier=None, archiver=None, known=None):
        self.iface, self.read, self.flt = iface, read, flt
        self.count, self.realtime, self.promisc = count, realtime, promisc
        self.on_packet = on_packet
        self.notifier, self.archiver = notifier, archiver
        self.stats = Stats(on_alert=notifier.notify if notifier else None, known=known)
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

    def _run(self) -> None:
        matched = 0
        try:
            for ts, data, orig, lt, ifname in self._frames():
                p = decode(data, ts, orig, lt, ifname)
                if not self.flt(p):
                    continue
                matched += 1
                self.stats.add(p)
                if self.writer:
                    self.writer.write(ts, data, orig, lt)
                if self.on_packet:
                    self.on_packet(p)
                if self.count and matched >= self.count:
                    break
        except BaseException as e:   # surfaced to the main thread
            self.error = e
        finally:
            with self.stats.lock:
                self.stats.known.save(force=True)
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
