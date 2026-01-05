# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
from contextlib import suppress

import bson
import errno
import json
import logging
import os
import socket
import struct
from threading import Thread

import gevent.pool
import gevent.server
import gevent.socket

# https://github.com/cuckoosandbox/cuckoo/blob/13cbe0d9e457be3673304533043e992ead1ea9b2/cuckoo/core/resultserver.py#L9
from .utils import open_exclusive, open_inclusive
from .path_utils import path_exists, path_get_filename

# from lib.cuckoo.common.netlog import BsonParser
from .utils import Singleton, create_folder, default_converter

log = logging.getLogger(__name__)

# Maximum line length to read for netlog messages, to avoid memory exhaustion
MAX_NETLOG_LINE = 4 * 1024

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
    b"curtain",
    b"debugger",
    b"tlsdump",
    b"files",
    b"procdump",
    b"shots",
    b"sysmon",
    b"evtx",
    b"htmldump",
)
RESULT_DIRECTORIES = RESULT_UPLOADABLE + (b"reports", b"logs")


def netlog_sanitize_fname(path):
    """Validate agent-provided path for result files"""
    path = path.replace(b"\\", b"/")
    dir_part, name = os.path.split(path)
    if b"aux" in dir_part:
        dir_part = dir_part.replace(b"aux", b"aux_")
        path = path.replace(b"aux", b"aux_")
    if dir_part not in RESULT_DIRECTORIES:
        log.error(f"Netlog client requested banned path: {path}")
    if any(c in BANNED_PATH_CHARS for c in name):
        for c in BANNED_PATH_CHARS:
            path.replace(bytes([c]), b"X")

    return path


class Disconnect(Exception):
    pass


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

    def __init__(self, storagepath, sock):
        self.command = None

        # The path where artifacts will be stored
        self.storagepath = storagepath
        self.sock = sock
        self.buf = b""

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
        try:
            # Test
            self.sock.settimeout(None)
            return self.sock.recv(16384)
        except socket.timeout as e:
            print(f"Do we need to fix it?. <Context for {self.command}>", e)
            return b""
        except socket.error as e:
            if e.errno == errno.EBADF:
                return b""

            if e.errno != errno.ECONNRESET:
                pass
            log.debug("Error: %s for %s", e.strerror.lower(), self)
            return b""
        except Exception as e:
            print(e)

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
        if max_size:
            fd = WriteLimiter(fd, max_size)
        fd.write(self.drain_buffer())
        while True:
            buf = self.read()
            if buf == b"":
                break
            fd.write(buf)
        fd.flush()

    def discard(self):
        self.drain_buffer()
        while _ := self.read():
            pass

    def __del__(self):
        if self.sock:
            self.sock.close()


class WriteLimiter:
    def __init__(self, fd, remain):
        self.fd = fd
        self.remain = remain
        self.warned = False

    def write(self, buf):
        size = len(buf)
        write = min(size, self.remain)
        try:
            if write:
                self.fd.write(buf[:write])
                self.remain -= write
            if size and size != write:
                if not self.warned:
                    log.warning(
                        "Uploaded file length larger than upload_max_size, stopping upload"
                    )
                    self.fd.write(b"... (truncated)")
                    self.warned = True
        except Exception as e:
            log.debug("Failed to upload file due to '%s'", e)

    def flush(self):
        self.fd.flush()

    def __del__(self):
        if self.fd:
            self.fd.close()

class FileUpload(ProtocolHandler):
    def init(self):
        self.upload_max_size = 2000000000
        self.storagepath = self.handler.storagepath
        self.fd = None
        self.filelog = os.path.join(self.handler.storagepath, "files.json")

    def __del__(self):
        if self.fd:
            self.fd.close()

    def handle(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin
        self.handler.sock.settimeout(30)
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
            except OSError as e:
                log.debug("File upload error for %s (task #%s)", dump_path)
                if e.errno == errno.EEXIST:
                    log.error(
                        "Analyzer tried to overwrite an existing file: %s", file_path
                    )

        # ToDo we need Windows path
        # filter screens/curtain/sysmon
        if not dump_path.startswith(
            (
                b"shots/",
                b"curtain/",
                b"aux_/",
                b"sysmon/",
                b"debugger/",
                b"tlsdump/",
                b"evtx",
                b"htmldump/",
            )
        ):
            # Append-writes are atomic
            with open(self.filelog, "a") as f:
                print(
                    json.dumps(
                        {
                            "path": dump_path.decode("utf-8", "replace"),
                            "filepath": (
                                filepath.decode("utf-8", "replace") if filepath else ""
                            ),
                            "pids": pids,
                            "ppids": ppids,
                            "metadata": metadata.decode("utf-8", "replace"),
                            "category": (
                                category.decode()
                                if category in (b"CAPE", b"files", b"procdump")
                                else ""
                            ),
                        },
                        ensure_ascii=False,
                    ),
                    file=f,
                )

        if not duplicated:
            self.handler.sock.settimeout(None)
            try:
                return self.handler.copy_to_fd(self.fd, self.upload_max_size)
            except Exception as e:
                if self.fd:
                    log.debug(
                        "Failed to uploaded file %s of length %s due to '%s'",
                        dump_path.decode(),
                        self.fd.tell(),
                        e,
                    )
                else:
                    log.debug(
                        "Failed to uploaded file %s due to '%s'",
                        dump_path.decode(),
                        e,
                    )
            else:
                log.debug(
                    "Uploaded file %s of length: %s",
                    dump_path.decode(),
                    self.fd.tell(),
                )


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
        if self.fd:
            return self.handler.copy_to_fd(self.fd)

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
        if self.fd:
            self.handler.sock.settimeout(None)
            return self.handler.copy_to_fd(self.fd)

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
        super(GeventResultServerWorker, self).__init__(*args, **kwargs)

    def do_run(self):
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

        ctx = HandlerContext(self.storagepath, sock)
        try:
            try:
                protocol = self.negotiate_protocol(ctx)
            except EOFError:
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
            handler = protocol.__class__.__name__
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
        pool_size = 0
        self.storagepath = args[0]

        sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((ip, port))
            log.info(f"ResultServer running on {ip}:{port}.")
        except (OSError, socket.error) as e:
            if e.errno == errno.EADDRINUSE:
                log.error(
                    f"Cannot bind ResultServer on port {port} because it is in use. Exiting."
                )
            elif e.errno == errno.EADDRNOTAVAIL:
                log.error(
                    f"Unable to bind ResultServer on {ip}:{port}. IP address not available. Exiting."
                )
            else:
                log.error(
                    f"Unable to bind ResultServer on {ip}:{port} error: {e}. Exiting."
                )

        # We allow user to specify port 0 to get a random port, report it back
        # here
        _, self.port = sock.getsockname()
        sock.listen(128)

        self.thread = Thread(target=self.create_server, args=(sock, pool_size))
        self.thread.daemon = True
        self.thread.start()

    def create_server(self, sock, pool_size):
        if pool_size:
            pool = gevent.pool.Pool(pool_size)
        else:
            pool = "default"
        self.instance = GeventResultServerWorker(
            sock, spawn=pool, storagepath=self.storagepath
        )
        self.instance.do_run()

    def shutdown_server(self):
        log.info("Shutting down the server...")
        with suppress(Exception):
            self.instance.stop()
        gevent.sleep(10)
        if not self.instance.closed:
            self.instance.shutdown()
            log.info("Resultserver forceful shut down.")
        else:
            log.info("Resultserver shut down.")
