"""Read-only pure-Python reader for Berkeley DB Btree files.

Only what the id2entry.db database of 389-ds (FreeIPA) needs: unencrypted
Btree files written by BDB 4.4+ (on-disk version 9). No dependencies beyond
the standard library - bsddb3 is not packaged for every platform IPAHound
runs on, and shelling out to db_dump would require system utilities.

On-disk layout (dbinc/db_page.h, stable since BDB 4.4):

    generic page header (26 bytes):
        lsn(8) pgno(4) prev_pgno(4) next_pgno(4) entries(u16)
        hf_offset(u16) level(u8) type(u8)

    metadata page (page 0) keeps its own shorter header:
        lsn(8) pgno(4) magic(u32@12) version(u32@16) pagesize(u32@20)
        encrypt_alg(u8@24) type(u8@25)

    btree leaf page: u16 item offsets grow upward right after the page
        header (offset 26 + 2*i); items alternate key, data, key, data ...
        - B_KEYDATA:  u16 data_len, u8 type, data[data_len]
        - BOVERFLOW:  u16 unused, u8 type, u8 unused, u32 pgno, u32 tlen

    overflow page: data starts at byte 26 and occupies hf_offset bytes;
        next_pgno in the page header chains to the next overflow page.

The reader does not walk the internal B-tree at all: every page in the file
is scanned, leaf pages are parsed directly, and pairs are sorted by key
afterwards (id2entry keys are 4-byte big-endian entry IDs, for which byte
order equals numeric order). This avoids depending on BTMETA field offsets
and internal page item formats.
"""

import struct
from typing import Iterator, List, Tuple

BTREE_MAGIC = 0x00053162
BTREE_VERSION = 9

PAGE_HEADER_SIZE = 26

P_INVALID = 0
P_IBTREE = 3
P_LBTREE = 5
P_OVERFLOW = 7
P_BTREE_META = 9

B_KEYDATA = 1
B_DUPLICATE = 2
B_OVERFLOW = 3
B_DELETE = 0x80

MIN_PAGE_SIZE = 512
MAX_PAGE_SIZE = 65536


class BdbError(Exception):
    """Raised when a file is not a supported Berkeley DB Btree database."""


class BdbBtreeReader:

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self._data = f.read()
        self._pagesize = 0
        self._endian = "<"
        self._load_meta()

    def _load_meta(self) -> None:
        if len(self._data) < PAGE_HEADER_SIZE + 32:
            raise BdbError("File is too small to be a Berkeley DB database")

        magic, = struct.unpack_from("<I", self._data, 12)
        if magic == BTREE_MAGIC:
            self._endian = "<"
        else:
            magic, = struct.unpack_from(">I", self._data, 12)
            if magic != BTREE_MAGIC:
                raise BdbError("Not a Berkeley DB Btree file (bad magic number)")
            self._endian = ">"

        version, pagesize = struct.unpack_from(
            self._endian + "II", self._data, 16
        )
        if version < BTREE_VERSION:
            raise BdbError(
                f"Unsupported Berkeley DB Btree version {version} "
                f"(version {BTREE_VERSION}+ is required)"
            )

        encrypt_alg = self._data[24]
        if encrypt_alg != 0:
            raise BdbError("Encrypted Berkeley DB files are not supported")

        if (
            pagesize < MIN_PAGE_SIZE
            or pagesize > MAX_PAGE_SIZE
            or pagesize & (pagesize - 1) != 0
            or len(self._data) % pagesize != 0
        ):
            raise BdbError(f"Invalid page size {pagesize}")

        page_type = self._data[25]
        if page_type != P_BTREE_META:
            raise BdbError(
                f"Unexpected metadata page type {page_type}, "
                f"expected {P_BTREE_META} (Btree)"
            )

        self._pagesize = pagesize

    @property
    def pagesize(self) -> int:
        return self._pagesize

    def _page_type(self, pgno: int) -> int:
        return self._data[pgno * self._pagesize + 25]

    def _u16(self, pgno: int, offset: int) -> int:
        value, = struct.unpack_from(
            self._endian + "H", self._data, pgno * self._pagesize + offset
        )
        return value

    def _u32(self, pgno: int, offset: int) -> int:
        value, = struct.unpack_from(
            self._endian + "I", self._data, pgno * self._pagesize + offset
        )
        return value

    def _page_count(self) -> int:
        return len(self._data) // self._pagesize

    def _read_overflow(self, pgno: int, total_length: int) -> bytes:
        chunks: List[bytes] = []
        collected = 0
        visited = set()

        while collected < total_length:
            if (
                pgno >= self._page_count()
                or pgno in visited
                or self._page_type(pgno) != P_OVERFLOW
            ):
                raise BdbError(
                    f"Broken overflow chain at page {pgno} "
                    f"(collected {collected} of {total_length} bytes)"
                )
            visited.add(pgno)

            used = self._u16(pgno, 22)
            start = pgno * self._pagesize + PAGE_HEADER_SIZE
            chunks.append(self._data[start:start + used])
            collected += used

            pgno = self._u32(pgno, 16)

        value = b"".join(chunks)
        if len(value) != total_length:
            raise BdbError(
                f"Overflow chain produced {len(value)} bytes, "
                f"expected {total_length}"
            )
        return value

    def _parse_leaf_page(self, pgno: int) -> List[Tuple[bytes, bytes]]:
        page_start = pgno * self._pagesize
        entries = self._u16(pgno, 20)
        if entries % 2 != 0:
            raise BdbError(
                f"Odd item count {entries} on leaf page {pgno}"
            )

        items: List[Tuple[bool, bytes]] = []
        for i in range(entries):
            item_offset = self._u16(pgno, PAGE_HEADER_SIZE + 2 * i)
            if (
                item_offset < PAGE_HEADER_SIZE + 2 * entries
                or item_offset >= self._pagesize
            ):
                raise BdbError(
                    f"Item offset {item_offset} out of range on page {pgno}"
                )

            item_type = self._data[page_start + item_offset + 2]
            deleted = bool(item_type & B_DELETE)
            item_type &= ~B_DELETE

            if item_type == B_KEYDATA:
                data_len, = struct.unpack_from(
                    self._endian + "H", self._data, page_start + item_offset
                )
                value_start = page_start + item_offset + 3
                value = self._data[value_start:value_start + data_len]
                if len(value) != data_len:
                    raise BdbError(f"Truncated item on page {pgno}")
            elif item_type == B_OVERFLOW:
                first_pgno, total_length = struct.unpack_from(
                    self._endian + "II",
                    self._data,
                    page_start + item_offset + 4,
                )
                value = self._read_overflow(first_pgno, total_length)
            else:
                raise BdbError(
                    f"Unsupported item type {item_type} on leaf page {pgno}"
                )

            items.append((deleted, value))

        pairs: List[Tuple[bytes, bytes]] = []
        for i in range(0, len(items), 2):
            key_deleted, key = items[i]
            value_deleted, value = items[i + 1]
            if key_deleted or value_deleted:
                continue
            pairs.append((key, value))
        return pairs

    def items(self) -> Iterator[Tuple[bytes, bytes]]:
        """Yield all (key, value) pairs in key order."""
        pairs: List[Tuple[bytes, bytes]] = []

        for pgno in range(1, self._page_count()):
            page_type = self._page_type(pgno)
            if page_type in (P_INVALID, P_IBTREE, P_OVERFLOW, P_BTREE_META):
                continue
            if page_type == P_LBTREE:
                pairs.extend(self._parse_leaf_page(pgno))
                continue
            raise BdbError(
                f"Unsupported page type {page_type} on page {pgno}"
            )

        pairs.sort(key=lambda pair: pair[0])
        yield from pairs
