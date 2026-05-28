# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import binascii
import contextlib
import hashlib
import logging
import magic
import struct
import subprocess
import tlsh
from pathlib import Path

import pefile

from .parse_pe import IMAGE_FILE_MACHINE_AMD64, IsPEImage

log = logging.getLogger(__name__)


class File:
    """Basic file object class with all useful utilities."""

    def __init__(self, file_path, guest_paths=None, file_name=None):
        """@param file_path: file path."""
        self.file_name = file_name
        self.file_path = file_path
        self.file_path_ansii = (
            file_path if isinstance(file_path, str) else file_path.decode()
        )
        self.guest_paths = guest_paths
        self.path_object = Path(self.file_path_ansii)

        # these will be populated when first accessed
        self._file_data = None
        self._crc32 = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._sha512 = None
        self._sha3_384 = None
        self._tlsh_hash = None
        self._pefile = False
        self.file_type = None
        self.pe = None

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        return self.file_name or Path(self.file_path).name

    def valid(self):
        return (
            self.path_object.exists()
            and self.path_object.is_file()
            and self.path_object.stat().st_size
        )

    def get_data(self):
        """Read file contents.
        @return: data.
        """
        return self.file_data

    def get_chunks(self, size=16):
        """Read file contents in chunks (generator)."""
        chunk_size = size * 1024
        with open(self.file_path, "rb") as fd:
            while True:
                chunk = fd.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def calc_hashes(self):
        """Calculate all possible hashes for this file."""
        crc = 0
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        sha3_384 = hashlib.sha3_384()
        tlsh_data = bytearray()

        for chunk in self.get_chunks():
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            sha3_384.update(chunk)
            tlsh_data += chunk

        self._crc32 = "".join(f"{(crc >> i) & 0xFF:02X}" for i in (24, 16, 8, 0))
        self._md5 = md5.hexdigest()
        self._sha1 = sha1.hexdigest()
        self._sha256 = sha256.hexdigest()
        self._sha512 = sha512.hexdigest()
        self._sha3_384 = sha3_384.hexdigest()
        with contextlib.suppress(Exception):
            result = tlsh.hash(bytes(tlsh_data))
            if result:
                self._tlsh_hash = result

    @property
    def file_data(self):
        if not self._file_data:
            if self.path_object.exists():
                self._file_data = self.path_object.read_bytes()
        return self._file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return self.path_object.stat().st_size if self.path_object.exists() else 0

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        if not self._crc32:
            self.calc_hashes()
        return self._crc32

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        if not self._md5:
            self.calc_hashes()
        return self._md5

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        if not self._sha1:
            self.calc_hashes()
        return self._sha1

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        if not self._sha256:
            self.calc_hashes()
        return self._sha256

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        if not self._sha512:
            self.calc_hashes()
        return self._sha512

    def get_sha3_384(self):
        """
        Get SHA3_384.
        @return: SHA3_384.
        """
        if not self._sha3_384:
            self.calc_hashes()
        return self._sha3_384

    def get_tlsh(self):
        """
        Get TLSH.
        @return: TLSH.
        """
        if not hasattr(self, "_tlsh_hash"):
            return None
        if not self._tlsh_hash:
            self.calc_hashes()
        return self._tlsh_hash

    def get_rh_hash(self):
        if not self.pe:
            return None

        # source https://github.com/RichHeaderResearch/RichPE/blob/master/richpe.py#L34
        rich_header = self.pe.parse_rich_header()
        if rich_header is None:
            return None

        # Get list of @Comp.IDs and counts from Rich header
        # Elements in rich_fields at even indices are @Comp.IDs
        # Elements in rich_fields at odd indices are counts
        rich_fields = rich_header.get("values")
        if len(rich_fields) % 2 != 0:
            return None

        # The RichPE hash of a file is computed by computing the md5 of specific
        # metadata within  the Rich header and the PE header
        md5 = hashlib.md5()

        # Update hash using @Comp.IDs and masked counts from Rich header
        while len(rich_fields):
            compid = rich_fields.pop(0)
            count = rich_fields.pop(0)
            mask = 2 ** (count.bit_length() // 2 + 1) - 1
            count |= mask
            md5.update(struct.pack("<L", compid))
            md5.update(struct.pack("<L", count))

        # Update hash using metadata from the PE header
        md5.update(struct.pack("<L", self.pe.FILE_HEADER.Machine))
        md5.update(struct.pack("<L", self.pe.FILE_HEADER.Characteristics))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.Subsystem))
        md5.update(struct.pack("<B", self.pe.OPTIONAL_HEADER.MajorLinkerVersion))
        md5.update(struct.pack("<B", self.pe.OPTIONAL_HEADER.MinorLinkerVersion))
        md5.update(
            struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
        )
        md5.update(
            struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
        )
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorImageVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorImageVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorSubsystemVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorSubsystemVersion))

        # Close PE file and return RichPE hash digest
        return md5.hexdigest()

    def get_content_type(self):
        """Get MIME content file type (example: image/jpeg).
        @return: file content type.
        """
        file_type = None
        if self.path_object.exists():
            fn = False
            if hasattr(magic, "detect_from_filename"):
                fn = magic.detect_from_filename
            if hasattr(magic, "from_file"):
                fn = magic.from_file
            if fn:
                try:
                    file_type = fn(self.file_path_ansii)
                except magic.MagicException as e:
                    log.error("Magic error: %s", str(e))
                except Exception as e:
                    log.error(e, exc_info=True)
            if not file_type and hasattr(magic, "open"):
                try:
                    ms = magic.open(magic.MAGIC_MIME | magic.MAGIC_SYMLINK)
                    ms.load()
                    file_type = ms.file(self.file_path)
                    ms.close()
                except Exception as e:
                    log.error(e, exc_info=True)

        if file_type is None:
            try:
                magic_path = Path(magic.__file__, "libmagic", "magic.mgc")
                p = subprocess.Popen(
                    [
                        "bin\\file.exe",
                        "-b",
                        "--mime-type",
                        "-m",
                        str(magic_path),
                        self.file_path,
                    ],
                    universal_newlines=True,
                    stdout=subprocess.PIPE,
                )
                file_type = p.stdout.read().strip()
            except Exception as e:
                log.error(e, exc_info=True)

        return file_type

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        if self.file_type:
            return self.file_type
        if self.file_path:
            try:
                if IsPEImage(self.file_data):
                    self._pefile = True
                    try:
                        self.pe = pefile.PE(data=self.file_data, fast_load=True)
                    except pefile.PEFormatError:
                        self.file_type = "PE image for MS Windows"
                        log.debug(
                            "Unable to instantiate pefile on image: %s",
                            self.file_path,
                        )
                    if self.pe:
                        is_dll = self.pe.is_dll()
                        is_x64 = self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64
                        gui_type = (
                            "console"
                            if self.pe.OPTIONAL_HEADER.Subsystem == 3
                            else "GUI"
                        )
                        dotnet_string = ""
                        with contextlib.suppress(AttributeError, IndexError):
                            dotnet_string = (
                                " Mono/.Net assembly"
                                if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                                    pefile.DIRECTORY_ENTRY[
                                        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"
                                    ]
                                ].VirtualAddress
                                != 0
                                else ""
                            )
                        # Emulate magic for now
                        if is_dll and is_x64:
                            self.file_type = f"PE32+ executable (DLL) (GUI) x86-64{dotnet_string}, for MS Windows"
                        elif is_dll:
                            self.file_type = f"PE32 executable (DLL) (GUI) Intel 80386{dotnet_string}, for MS Windows"
                        elif is_x64:
                            self.file_type = f"PE32+ executable ({gui_type}) x86-64{dotnet_string}, for MS Windows"
                        else:
                            self.file_type = f"PE32 executable ({gui_type}) Intel 80386{dotnet_string}, for MS Windows"

            except Exception as e:
                log.error(e, exc_info=True)
        if not self.file_type:
            self.file_type = self.get_content_type()

        return self.file_type

    def get_all_hashes(self):
        return {
            "crc32": self.get_crc32(),
            "md5": self.get_md5(),
            "sha1": self.get_sha1(),
            "sha256": self.get_sha256(),
            "sha512": self.get_sha512(),
            "rh_hash": self.get_rh_hash(),
            "sha3_384": self.get_sha3_384(),
            "tlsh": self.get_tlsh(),
        }

    def get_all(self):
        """Get all information available.
        @return: information dict.
        """

        infos = {
            "type": self.get_type(),
            "name": self.get_name(),
            "path": self.file_path,
            "guest_paths": self.guest_paths,
            "size": self.get_size(),
            "crc32": self.get_crc32(),
            "md5": self.get_md5(),
            "sha1": self.get_sha1(),
            "sha256": self.get_sha256(),
            "sha512": self.get_sha512(),
            "rh_hash": self.get_rh_hash(),
            "sha3_384": self.get_sha3_384(),
            "tlsh": self.get_tlsh(),
        }

        return infos, self.pe
