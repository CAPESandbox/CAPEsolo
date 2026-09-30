# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import configparser
from contextlib import suppress

import bson
import errno
import json
import logging
import os
import socket
import struct
import time
from threading import Event, Thread

import gevent.pool
import gevent.server
import gevent.socket

# https://github.com/cuckoosandbox/cuckoo/blob/13cbe0d9e457be3673304533043e992ead1ea9b2/cuckoo/core/resultserver.py#L9
from .config_paths import config_paths
from .utils import open_exclusive, open_inclusive
from .path_utils import path_exists, path_get_filename

# from lib.cuckoo.common.netlog import BsonParser
from .utils import Singleton, create_folder, default_converter

log = logging.getLogger(__name__)

# Maximum line length to read for netlog messages, to avoid memory exhaustion
MAX_NETLOG_LINE = 4 * 1024

# Ceiling on how long shutdown waits for in-flight uploads to finish draining to disk.
# Kept at the old blind sleep's duration so the worst case is never slower than before,
# but it now returns as soon as the handlers are actually done.
DRAIN_TIMEOUT = 10.0
# How long to wait for the server thread to publish its instance and hub.
READY_TIMEOUT = 5.0
# Headroom on top of drain_timeout before the caller gives up on the server thread.
# gevent follows its own pool.join(drain_timeout) with pool.kill(block=True, timeout=1),
# so without this the join would expire exactly as the drain finishes and escalate for
# nothing.
STOP_GRACE = 2.0

# How long a FILE upload may take to send its header lines. capemon writes them
# immediately after connecting, so this only fires on a peer that has gone away.
HEADER_TIMEOUT = 30

# Shipped defaults for the optional [resultserver] section. The caps default to 0, meaning
# disabled, because enforcing them loses analysis data: a full pool makes gevent stop
# accepting, so once the listen backlog fills the OS refuses connections the server never
# sees, and an idle timeout truncates analysis.log and the BSON behavior log, which hold one
# connection for the whole run and are legitimately idle while a sample sleeps.
RESULTSERVER_DEFAULTS = {
    "pool_size": 0,
    "upload_max_size": 2000000000,
    "idle_timeout": 0,
    "drain_timeout": DRAIN_TIMEOUT,
}

# Maximum number of bytes to buffer for a single connection
BUFSIZE = 16 * 1024

# Prevent malicious clients from using potentially dangerous filenames
# E.g. C API confusion by using null, or using the colon on NTFS (Alternate
# Data Streams); XXX: just replace illegal chars?
BANNED_PATH_CHARS = b"\x00:"

# Directories in which analysis-related files will be stored; also acts as
# whitelist
RESULT_UPLOADABLE = (
    b"CAPE",
    b"aux_",
    b"aux_/amsi",
    b"aux_/js_console",
    # sslkeylogfile uploads to "aux/sslkeylogfile/sslkeys.log". Every aux_ subdirectory has to
    # be listed individually - the check is an exact match on the directory, not a prefix - so
    # without this the TLS secrets were refused and the client disconnected.
    b"aux_/sslkeylogfile",
    b"debugger",
    b"tlsdump",
    b"files",
    b"procdump",
    b"evtx",
    b"htmldump",
)
RESULT_DIRECTORIES = RESULT_UPLOADABLE + (b"reports", b"logs")


def read_resultserver_settings():
    """Read the optional [resultserver] section; fallbacks apply even when it is absent.

    A bad value must not stop an analysis starting, so it logs and falls back rather than
    raising. Negative values are treated as the default for the same reason.
    """
    paths = config_paths()
    config = configparser.ConfigParser()
    try:
        read = config.read(paths)
    except configparser.Error as e:
        log.warning("Could not parse cfg.ini for [resultserver]: %s", e)
        return dict(RESULTSERVER_DEFAULTS)

    settings = {}
    for key, default in RESULTSERVER_DEFAULTS.items():
        getter = config.getfloat if isinstance(default, float) else config.getint
        try:
            value = getter("resultserver", key, fallback=default)
        except ValueError:
            log.warning(
                "Invalid [resultserver] %s in %s, using %s", key, read or paths, default
            )
            value = default
        if value < 0:
            log.warning("Negative [resultserver] %s, using %s", key, default)
            value = default
        settings[key] = value

    return settings


def netlog_sanitize_fname(path):
    """Validate agent-provided path for result files"""
    path = path.replace(b"\\", b"/")
    dir_part, name = os.path.split(path)
    if b"aux" in dir_part:
        dir_part = dir_part.replace(b"aux", b"aux_")
        path = path.replace(b"aux", b"aux_")
    if dir_part not in RESULT_DIRECTORIES:
        log.error(f"Netlog client requested banned path: {path}")
        raise Disconnect
    if any(c in BANNED_PATH_CHARS for c in name):
        for c in BANNED_PATH_CHARS:
            path = path.replace(bytes([c]), b"X")

    return path


class Disconnect(Exception):
    pass


class TransferStats:
    """Counts what the result server actually managed to store.

    Reported once at shutdown so an operator has a single line to check, rather than
    having to notice individual errors scattered through the log.
    """

    def __init__(self):
        self.complete = 0
        self.incomplete = 0
        self.truncated = 0

    def record(self, complete, truncated=False):
        if complete:
            self.complete += 1
        else:
            self.incomplete += 1
        if truncated:
            self.truncated += 1

    def reset(self):
        self.complete = 0
        self.incomplete = 0
        self.truncated = 0

    def summary(self):
        # A truncated transfer is also counted as complete: we chose to stop writing at
        # upload_max_size, so no bytes were lost that we were willing to store.
        summary = f"transfers complete={self.complete} incomplete={self.incomplete}"
        if self.truncated:
            summary += f" truncated={self.truncated}"
        return summary

    def snapshot(self):
        """Machine-readable counterpart to summary(), for the capture manifest.

        Taken before shutdown resets the counters, so the manifest records what this run
        actually stored rather than nothing.
        """
        return {
            "complete": self.complete,
            "incomplete": self.incomplete,
            "truncated": self.truncated,
        }


STATS = TransferStats()


class ProtocolHandler:
    """Abstract class for protocol handlers coming out of the analysis."""

    def __init__(self, ctx, version=None):
        self.handler = ctx
        self.fd = None
        self.version = version

    def __enter__(self):
        self.init()

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.fd:
            self.fd.close()
            self.fd = None

    def handle(self):
        raise NotImplementedError


class HandlerContext:
    """Holds context for protocol handlers.
    Can safely be cancelled from another thread, though in practice this will
    not occur often -- usually the connection between VM and the ResultServer
    will be reset during shutdown."""

    def __init__(self, storagepath, sock, settings=None):
        self.command = None

        # The path where artifacts will be stored
        self.storagepath = storagepath
        self.sock = sock
        self.buf = b""
        self.settings = settings or dict(RESULTSERVER_DEFAULTS)
        # Applied by read(). None means block indefinitely, which is what every handler
        # wants except while reading a FILE upload's header lines.
        self.timeout = None

    def __repr__(self):
        return f"<Context for {self.command}>"

    def cancel(self):
        """Cancel this context; gevent might complain about this with an
        exception later on."""
        try:
            self.sock.shutdown(socket.SHUT_RD)
        except socket.error:
            pass

    def read(self):
        """Read the next chunk from the peer.

        Returns b"" only for a genuine end of stream. Anything else - a timeout, a socket
        error, an unexpected exception - raises Disconnect, because returning b"" for those
        made a truncated transfer indistinguishable from a complete one and let callers
        report a short file as a successful upload.

        Applies self.timeout rather than forcing None, which used to clobber the timeout
        every handler tried to set and so made all of them dead code.
        """
        try:
            self.sock.settimeout(self.timeout)
            return self.sock.recv(16384)
        except socket.timeout as e:
            log.error("Timed out reading from %s: %s", self, e)
            raise Disconnect from e
        except socket.error as e:
            if e.errno == errno.EBADF:
                # The socket was closed under us, e.g. by cancel() during shutdown.
                raise Disconnect from e
            strerror = (e.strerror or str(e)).lower()
            log.error("Socket error reading from %s: %s", self, strerror)
            raise Disconnect from e
        except Exception as e:
            log.exception("Unexpected error reading from %s", self)
            raise Disconnect from e

    def drain_buffer(self):
        """Drain buffer and end buffering"""
        buf, self.buf = self.buf, None
        return buf

    def read_newline(self):
        """Read until the next newline character, but never more than
        `MAX_NETLOG_LINE`."""
        while True:
            pos = self.buf.find(b"\n")
            if pos < 0:
                if len(self.buf) >= MAX_NETLOG_LINE:
                    log.error("Received overly long line")
                buf = self.read()
                if buf == b"":
                    raise EOFError
                self.buf += buf
                continue
            line, self.buf = self.buf[:pos], self.buf[pos + 1 :]
            return line

    def copy_to_fd(self, fd, max_size=None):
        """Stream the rest of the connection into `fd`.

        Returns (bytes_written, complete, capped). `complete` is False when the peer went
        away mid-transfer or a write failed, so the caller can record a partial artifact
        instead of reporting a successful upload. `capped` means we deliberately stopped at
        max_size, which is a different thing from losing data.
        """
        limiter = WriteLimiter(fd, max_size) if max_size else None
        sink = limiter or fd
        written = 0
        complete = False
        try:
            chunk = self.drain_buffer() or b""
            sink.write(chunk)
            written += len(chunk)
            while True:
                buf = self.read()
                if buf == b"":
                    complete = True
                    break
                sink.write(buf)
                written += len(buf)
        except Disconnect:
            log.error("Transfer for %s ended early after %s bytes", self, written)
        finally:
            with suppress(Exception):
                sink.flush()

        if limiter and limiter.failed:
            complete = False

        return written, complete, bool(limiter and limiter.capped)

    def discard(self):
        """Drain and throw away the rest of the connection, so a peer that is still
        sending is not left blocked when we cannot store what it sends."""
        with suppress(Disconnect):
            self.drain_buffer()
            while self.read():
                pass

    def __del__(self):
        if self.sock:
            self.sock.close()


class WriteLimiter:
    def __init__(self, fd, remain):
        self.fd = fd
        self.remain = remain
        self.warned = False
        # Set when bytes we were sent could not be stored, so copy_to_fd can report the
        # artifact as incomplete rather than logging it as a successful upload.
        self.failed = False
        self.capped = False

    def write(self, buf):
        size = len(buf)
        write = min(size, self.remain)
        try:
            if write:
                self.fd.write(buf[:write])
                self.remain -= write
            if size and size != write:
                self.capped = True
                if not self.warned:
                    log.warning(
                        "Uploaded file length larger than upload_max_size, stopping upload"
                    )
                    self.warned = True
        except Exception:
            if not self.failed:
                log.exception("Failed writing %s bytes of uploaded data", size)
            self.failed = True

    def flush(self):
        with suppress(Exception):
            self.fd.flush()

    def __del__(self):
        if self.fd:
            self.fd.close()

class FileUpload(ProtocolHandler):
    def init(self):
        self.upload_max_size = self.handler.settings["upload_max_size"]
        self.storagepath = self.handler.storagepath
        self.fd = None
        self.filelog = os.path.join(self.handler.storagepath, "files.json")

    def __del__(self):
        if self.fd:
            self.fd.close()

    def handle(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin
        self.handler.timeout = HEADER_TIMEOUT
        dump_path = netlog_sanitize_fname(self.handler.read_newline())

        if (self.version or 0) >= 2:
            # NB: filepath is only used as metadata
            filepath = self.handler.read_newline()
            pids = list(map(int, self.handler.read_newline().split()))
            ppids = list(map(int, self.handler.read_newline().split()))
            metadata = self.handler.read_newline()
            category = self.handler.read_newline()
            duplicated = int(self.handler.read_newline()) or 0
        else:
            filepath, pids, ppids, metadata, category, duplicated = (
                None,
                [],
                [],
                b"",
                b"",
                False,
            )

        log.debug("Uploading file %s", dump_path.decode())
        if not duplicated:
            file_path = os.path.join(self.storagepath, dump_path.decode())

            try:
                if file_path.endswith("_script.log"):
                    self.fd = open_inclusive(file_path)
                elif not path_exists(file_path):
                    # open_exclusive will fail if file_path already exists
                    self.fd = open_exclusive(file_path)
                else:
                    log.error(
                        "Cannot store upload %s: %s already exists, discarding the data "
                        "the analyzer sent for it",
                        dump_path.decode(),
                        file_path,
                    )
            except OSError as e:
                log.error(
                    "Cannot store upload %s at %s: %s", dump_path.decode(), file_path, e
                )

        # Transfer before recording the metadata, so files.json never advertises an
        # artifact that was never stored. A duplicated upload sends no content, so it is
        # complete by definition.
        written, complete, capped = 0, True, False
        if not duplicated:
            if self.fd:
                self.handler.timeout = self.handler.settings["idle_timeout"] or None
                written, complete, capped = self.handler.copy_to_fd(
                    self.fd, self.upload_max_size
                )
                if complete:
                    log.debug("Uploaded file %s of length: %s", dump_path.decode(), written)
                else:
                    log.error(
                        "Incomplete upload for %s: stored %s bytes", dump_path.decode(), written
                    )
            else:
                # Nowhere to store it. Drain anyway so the analyzer is not left blocked
                # waiting on a reader that will never consume.
                complete = False
                self.handler.discard()

        STATS.record(complete, capped)

        # ToDo we need Windows path
        # keep aux, debugger, tlsdump, evtx and htmldump uploads out of files.json
        if not dump_path.startswith(
            (
                b"aux_/",
                b"debugger/",
                b"tlsdump/",
                b"evtx",
                b"htmldump/",
            )
        ):
            entry = {
                "path": dump_path.decode("utf-8", "replace"),
                "filepath": (filepath.decode("utf-8", "replace") if filepath else ""),
                "pids": pids,
                "ppids": ppids,
                "metadata": metadata.decode("utf-8", "replace"),
                "category": (
                    category.decode()
                    if category in (b"CAPE", b"files", b"procdump")
                    else ""
                ),
            }
            if not complete:
                # Additive key: existing consumers ignore it, but the artifact is no longer
                # advertised as if it were whole. A partial payload is still worth keeping.
                entry["incomplete"] = True
            if capped:
                # Also additive. Distinct from "incomplete": the stream arrived intact, we
                # just stopped storing it at upload_max_size.
                entry["truncated"] = True
            # Append-writes are atomic
            with open(self.filelog, "a") as f:
                print(json.dumps(entry, ensure_ascii=False), file=f)


class LogHandler(ProtocolHandler):
    """The live analysis log. Can only be opened once in a single session."""

    def init(self):
        self.logpath = os.path.join(self.handler.storagepath, "analysis.log")
        try:
            self.fd = open_inclusive(self.logpath)
        except OSError as e:
            log.error("Failed to open live log analysis.log: %s", e)
            return

        log.debug("Live log analysis.log initialized")

    def handle(self):
        if not self.fd:
            # Drain rather than dropping the connection, so the analyzer is not left
            # blocked writing into a socket nobody reads.
            log.error("Discarding live log stream: %s could not be opened", self.logpath)
            STATS.record(False)
            self.handler.discard()
            return

        self.handler.timeout = self.handler.settings["idle_timeout"] or None
        written, complete, _ = self.handler.copy_to_fd(self.fd)
        STATS.record(complete)
        if not complete:
            log.error("Live log stream ended early after %s bytes", written)

    def __del__(self):
        if self.fd:
            self.fd.close()

TYPECONVERTERS = {
    "h": lambda v: f"0x{default_converter(v):08x}",
    "p": lambda v: f"0x{default_converter(v):08x}",
}


def check_names_for_typeinfo(arginfo):
    argnames = [i[0] if isinstance(i, (list, tuple)) else i for i in arginfo]

    converters = []
    for i in arginfo:
        if isinstance(i, (list, tuple)):
            r = TYPECONVERTERS.get(i[1])
            if not r:
                log.debug("Analyzer sent unknown format specifier '%s'", i[1])
                r = default_converter
            converters.append(r)
        else:
            converters.append(default_converter)

    return argnames, converters


class BsonStore(ProtocolHandler):
    def init(self):
        if self.version is None:
            log.warning(
                "Agent is sending BSON files without PID parameter."
            )
            self.fd = None
            return

        self.infomap = {}
        self.fd = open(
            os.path.join(self.handler.storagepath, "logs", f"{self.version}.bson"), "wb"
        )

    def parse_message(self, buffer):
        while True:
            data = buffer[:4]
            if not data:
                return

            blen = struct.unpack("I", data)[0]
            data = buffer[:blen]
            buffer = buffer[blen:]

            if len(data) < blen:
                log.debug("BsonParser lacking data")
                return

            try:
                dec = bson.decode(data)
            except Exception as e:
                log.warning(
                    "BsonParser decoding problem %s on data[:50] %s", e, data[:50]
                )
                return

            mtype = dec.get("type", "none")
            index = dec.get("I", -1)

            if mtype == "info":
                name = dec.get("name", "NONAME")
                arginfo = dec.get("args", [])
                category = dec.get("category")

                if not category:
                    category = "unknown"

                argnames, converters = check_names_for_typeinfo(arginfo)
                self.infomap[index] = name, arginfo, argnames, converters, category

            else:
                if index not in self.infomap:
                    log.warning(
                        "Got API with unknown index - monitor needs to explain first: %s",
                        dec,
                    )
                    return

                apiname, arginfo, argnames, converters, category = self.infomap[index]
                args = dec.get("args", [])

                if len(args) != len(argnames):
                    log.warning(
                        "Inconsistent arg count (compared to arg names) on %s: %s names %s",
                        dec,
                        argnames,
                        apiname,
                    )
                    continue

                argdict = {
                    argnames[i]: converters[i](arg) for i, arg in enumerate(args)
                }

                if apiname == "__process__":

                    # pid = argdict["ProcessIdentifier"]
                    ppid = argdict["ParentProcessIdentifier"]
                    modulepath = argdict["ModulePath"]
                    procname = path_get_filename(modulepath)

                    log.info(
                        "Process %d (parent %d): %s, path %s",
                        self.version,
                        ppid,
                        procname,
                        modulepath.decode(),
                    )

    def handle(self):
        """Read a BSON stream, attempting at least basic validation, and
        log failures."""
        self.parse_message(self.handler.buf)
        if not self.fd:
            # Without a PID there is nowhere to put the stream. Drain it so the analyzer
            # is not blocked, and say so plainly - this loses the whole behavior log for
            # the process, which used to pass with only a warning.
            log.error(
                "Discarding BSON behavior stream: agent sent no PID, so there is no "
                "logs/<pid>.bson to write to"
            )
            STATS.record(False)
            self.handler.discard()
            return

        self.handler.timeout = self.handler.settings["idle_timeout"] or None
        written, complete, _ = self.handler.copy_to_fd(self.fd)
        STATS.record(complete)
        if not complete:
            log.error("BSON behavior stream ended early after %s bytes", written)

    def __del__(self):
        if self.fd:
            self.fd.close()


class GeventResultServerWorker(gevent.server.StreamServer):
    """The new ResultServer, providing a huge performance boost as well as
    implementing a new dropped file storage format avoiding small fd limits.
    """

    commands = {
        b"BSON": BsonStore,
        b"FILE": FileUpload,
        b"LOG": LogHandler,
    }

    def __init__(self, *args, **kwargs):
        self.storagepath = kwargs.pop("storagepath", "")
        self.settings = kwargs.pop("settings", None) or dict(RESULTSERVER_DEFAULTS)
        self.saturation_logged = False
        super(GeventResultServerWorker, self).__init__(*args, **kwargs)
        # set_spawn() assigns self.full = self.pool.full as an *instance* attribute, which
        # shadows any method we define, so the saturation check has to be wrapped here
        # rather than overridden. Only applies when pool_size is configured non-zero.
        # Only meaningful when a bound is configured; an unbounded pool is never full.
        if self.pool is not None and self.settings["pool_size"]:
            self._pool_full = self.full
            self.full = self._full_and_warn

    def _full_and_warn(self):
        """Report pool saturation once, then defer to gevent's own check.

        While the pool is full gevent stops accepting, so connections pile up in the listen
        backlog already accepted by the OS. Those are invisible to us: if the analysis ends
        while any are queued they are discarded unhandled, with no artifact and no
        files.json entry, and the shutdown drain cannot help because stop() waits for
        running handlers rather than for the backlog. Measured: pool_size=8 against 200
        uploads lost 55 of them outright. Hence the warning, and hence pool_size=0 default.
        """
        saturated = self._pool_full()
        if saturated and not self.saturation_logged:
            self.saturation_logged = True
            log.warning(
                "ResultServer pool of %s is saturated; connections are queuing unaccepted "
                "and any still queued when the analysis ends will be lost silently. Set "
                "[resultserver] pool_size = 0 in cfg.ini to remove the limit.",
                self.settings["pool_size"],
            )
        return saturated

    def do_run(self):
        # serve_forever's own teardown is what actually drains: on stop it does
        # `Greenlet.spawn(self.stop, timeout=stop_timeout).join()`, and with no argument
        # that falls back to self.stop_timeout. gevent's default is 1 second, which
        # silently capped the drain no matter what shutdown_server was asked for - the
        # monitor keeps logging for seconds after the analyzer returns, and everything
        # past that 1s was lost. shutdown_server sets stop_timeout before stopping.
        self.serve_forever()

    def create_folders(self):
        for folder in list(RESULT_UPLOADABLE) + [b"logs"]:
            try:
                create_folder(self.storagepath, folder=folder.decode())
            except Exception as e:
                log.error(e, exc_info=True)

    def handle(self, sock, ipaddr):
        """Handle the incoming connection.
        Gevent will close the socket when the function returns."""
        protocol = None

        # Create all missing folders for this analysis.
        self.create_folders()

        ctx = HandlerContext(self.storagepath, sock, self.settings)
        try:
            try:
                protocol = self.negotiate_protocol(ctx)
            except EOFError:
                return

            if protocol is None:
                # Unknown command; negotiate_protocol already logged it. Returning here
                # avoids an AttributeError being logged as if it were a handler failure.
                return

            try:
                with protocol:
                    protocol.handle()
            except Exception as e:
                log.error(e, exc_info=True)
            finally:
                ctx.cancel()
                if ctx.buf:
                    # This is usually not a good sign
                    log.warning(
                        "Protocol %s has unprocessed data before getting disconnected",
                        protocol,
                    )
        finally:
            # protocol stays None when the peer connected but never completed a header
            # line, which is normal at shutdown; "NoneType" read like a bug in the log.
            handler = protocol.__class__.__name__ if protocol else "unnegotiated"
            log.info(f"Closing connection handle: {handler}, fd: {sock.fileno()}")

    def negotiate_protocol(self, ctx):
        header = ctx.read_newline()
        if b" " in header:
            command, version = header.split()
            version = int(version)
        else:
            command, version = header, None
        klass = self.commands.get(command)
        if not klass:
            log.warning(
                "Unknown netlog protocol requested (%s), terminating connection",
                command,
            )
            return
        ctx.command = command
        return klass(ctx, version)

    def shutdown(self):
        self.stop()
        self.close()


class ResultServer(metaclass=Singleton):
    """Manager for the ResultServer worker and task state."""

    def __init__(
        self,
        server_ip="localhost",
        server_port=9999,
        *args,
    ):

        ip = server_ip
        port = server_port
        self.settings = read_resultserver_settings()
        self.drain_timeout = self.settings["drain_timeout"]
        pool_size = self.settings["pool_size"]
        self.storagepath = args[0]
        STATS.reset()

        sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # On Windows SO_REUSEADDR lets a second socket bind a port that is already being
        # listened on, so two CAPEsolo processes could both hold 9999 and split the
        # monitor's connections between them - each storing part of the analysis.
        # SO_EXCLUSIVEADDRUSE refuses that; elsewhere SO_REUSEADDR keeps its usual meaning.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((ip, port))
            log.info(f"ResultServer running on {ip}:{port}.")
        except (OSError, socket.error) as e:
            # Raise rather than carrying on: continuing to listen()/serve on an unbound
            # socket produced a server that looked started and silently collected nothing.
            if e.errno == errno.EADDRINUSE:
                log.error(f"Cannot bind ResultServer on port {port} because it is in use.")
            elif e.errno == errno.EADDRNOTAVAIL:
                log.error(f"Unable to bind ResultServer on {ip}:{port}. IP address not available.")
            else:
                log.error(f"Unable to bind ResultServer on {ip}:{port} error: {e}.")
            with suppress(Exception):
                sock.close()
            raise

        # We allow user to specify port 0 to get a random port, report it back
        # here
        _, self.port = sock.getsockname()
        sock.listen(128)

        self.instance = None
        self.hub = None
        # Published by create_server once instance and hub are both assigned, so
        # shutdown_server never races against a server that is still being built.
        self.ready = Event()

        self.thread = Thread(target=self.create_server, args=(sock, pool_size))
        self.thread.daemon = True
        self.thread.start()

    def create_server(self, sock, pool_size):
        # Always spawn into a Pool, even when unbounded. With spawn="default" gevent has no
        # pool to join, so stop() returns without waiting for in-flight handlers ("If the
        # server does not use a pool, then this merely stops accepting connections") and the
        # thread exits with handler greenlets mid-write - silently truncating an artifact
        # with no error and no files.json entry. Pool(None) is unbounded, so nothing is
        # throttled, but stop(timeout) can now actually drain.
        if pool_size:
            log.info("ResultServer limiting concurrent connections to %s", pool_size)
        pool = gevent.pool.Pool(pool_size or None)
        self.instance = GeventResultServerWorker(
            sock, spawn=pool, storagepath=self.storagepath, settings=self.settings
        )
        # gevent hubs are per-thread. Record the one that owns this server so shutdown can
        # stop it from the thread that actually drives its watchers.
        self.hub = gevent.get_hub()
        self.ready.set()
        self.instance.do_run()

    def shutdown_server(self, drain_timeout=None):
        """Stop the server, giving in-flight handlers a chance to finish writing.

        Handlers are still draining uploaded bytes to disk when this is called, so the
        stop has to *wait* for them. It also has to run on the thread that owns the
        server's gevent hub - stopping from another thread corrupts watcher state and
        cannot wait reliably. Each escalation step is logged so a stuck shutdown is
        diagnosable rather than mysterious.
        """
        if drain_timeout is None:
            # Callers pass nothing, so the configured value has to be applied here or it
            # would never take effect. An explicit argument still wins.
            drain_timeout = self.drain_timeout
        log.info("Shutting down the server...")
        deadline = time.monotonic() + drain_timeout + STOP_GRACE

        if not self.ready.wait(timeout=min(drain_timeout, READY_TIMEOUT)):
            log.warning("ResultServer never finished starting; shutting down what exists")

        instance = self.instance
        if instance is None:
            log.warning("ResultServer was never constructed, nothing to stop")
            self._report_summary()
            self._forget_instance()
            return

        # Read by serve_forever's teardown when it spawns the stop. Set here rather than at
        # construction so an explicit shutdown_server(drain_timeout=...) still governs.
        instance.stop_timeout = drain_timeout

        stopped = False
        if self.hub is not None:
            # Step 1: ask the owning hub to stop the server, and wait for it there.
            try:
                # close() only sets the stop event and closes the listener; it does not
                # block, so unlike stop() it is legal inside a loop callback. Setting the
                # event is all that is needed - serve_forever's finally then runs the real
                # drain on the thread that owns the hub, bounded by the stop_timeout
                # do_run passed it.
                self.hub.loop.run_callback_threadsafe(instance.close)
                stopped = self._join(deadline)
            except Exception:
                log.exception("Threadsafe ResultServer stop failed, falling back")

        if not stopped:
            # Step 2: stop directly. Cross-thread, but better than leaving it running.
            log.warning("ResultServer did not stop via its own hub, stopping directly")
            with suppress(Exception):
                instance.stop(timeout=max(0.0, deadline - time.monotonic()))
            stopped = self._join(deadline)

        if not stopped and not instance.closed:
            # Step 3: force the listener closed.
            log.error("ResultServer did not stop cleanly, forcing close")
            with suppress(Exception):
                instance.close()
            stopped = self._join(deadline)

        if stopped:
            log.info("Resultserver shut down.")
        else:
            log.error(
                "ResultServer thread still alive after %.1fs; in-flight uploads may be "
                "incomplete", drain_timeout
            )

        self._report_summary()
        self._forget_instance()

    def _join(self, deadline):
        """Wait for the server thread to exit, bounded by the shared deadline."""
        remaining = max(0.0, deadline - time.monotonic())
        self.thread.join(timeout=remaining)
        return not self.thread.is_alive()

    @staticmethod
    def _report_summary():
        # One line an operator can check instead of hunting for scattered errors.
        summary = STATS.summary()
        if STATS.incomplete:
            log.error("ResultServer %s - some analysis data was NOT stored", summary)
        else:
            log.info("ResultServer %s", summary)

    @staticmethod
    def _forget_instance():
        """Drop the Singleton entry so a later ResultServer(...) builds a working server
        instead of silently handing back this stopped one with the old storagepath."""
        Singleton._instances.pop(ResultServer, None)
