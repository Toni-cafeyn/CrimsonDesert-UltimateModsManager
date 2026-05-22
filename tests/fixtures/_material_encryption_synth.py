"""Tiny synthetic PAMT + PAZ pair for material-encryption tests.

No game asset committed. Layout matches what _parse_pamt_impl
expects: one folder ("test"), three files inside it. Each file's
content sits in `0.paz` at a known offset.

Returned plan dict carries the entry paths so tests can assert
encryption verdicts by path without hardcoding indices.
"""

import os
import struct
from pathlib import Path

from cdumm.archive.paz_crypto import encrypt


def build_synthetic_pamt_paz(tmp_path: Path):
    """Build a minimal PAMT + PAZ pair under tmp_path.

    Returns:
        (pamt_path, paz_path, plan)

        plan is a dict with the entry paths:
            {
              'xml_path': 'test/foo.xml',
              'material_path': 'test/water.material',
              'bin_path': 'test/data.bin',
            }
    """
    # ---- PAZ payload ----
    xml_plain = b'\xef\xbb\xbf<root>hello</root>\r\n'
    xml_crypt = encrypt(xml_plain, 'foo.xml')

    mat_plain = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
    mat_crypt = encrypt(mat_plain, 'water.material')

    # All-printable ASCII so the sniff classifies this slot as NOT
    # encrypted (looks_like_plaintext_head returns True). The test
    # asserts _encrypted_override is False for this entry.
    bin_plain = b'PLAINBINARYRECORDPADDING01234567'  # 32 printable bytes

    # Pad each slot to keep offsets aligned and >= 32 bytes so the
    # sniff has a full head to read.
    def _padded(data: bytes, size: int = 64) -> bytes:
        assert len(data) <= size
        return data + b'\x00' * (size - len(data))

    xml_slot = _padded(xml_crypt)
    mat_slot = _padded(mat_crypt)
    bin_slot = _padded(bin_plain)

    paz_blob = xml_slot + mat_slot + bin_slot
    xml_off = 0
    mat_off = len(xml_slot)
    bin_off = len(xml_slot) + len(mat_slot)

    paz_path = tmp_path / "0.paz"
    paz_path.write_bytes(paz_blob)

    # ---- PAMT structure ----
    # Magic (4 bytes, value irrelevant; _parse_pamt_impl just skips it).
    magic = b'PAMT'

    # paz_count = 1 (single .paz file).
    paz_count = struct.pack('<I', 1)
    hash_zero = struct.pack('<II', 0, 0)

    # PAZ table: paz_count entries each with hash(4) + size(4). The
    # separator(4) between consecutive entries is skipped when
    # paz_count == 1 (see _parse_pamt_impl loop condition
    # `if i < paz_count - 1`).
    paz_table = struct.pack('<II', 0, len(paz_blob))

    # ---- Folder section ----
    # One folder named "test", parent = 0xFFFFFFFF (root). The impl
    # sets folder_prefix = "test" when it sees parent == 0xFFFFFFFF.
    folder_name = b'test'
    folder_record = struct.pack('<I', 0xFFFFFFFF) + bytes([len(folder_name)]) + folder_name
    # folder_section = size(4) + records
    folder_section = struct.pack('<I', len(folder_record)) + folder_record

    # ---- Node section ----
    # Three nodes for the file basenames. Each node has parent =
    # 0xFFFFFFFF so build_path terminates after one hop, yielding
    # just the bare filename. The key stored in nodes{} is
    # `rel = off - node_start`, i.e. the byte offset within the
    # node section bytes. We record that offset in rels{} so the
    # file records reference them correctly.
    nodes = []
    rels = {}
    node_bytes = bytearray()
    for name in (b'foo.xml', b'water.material', b'data.bin'):
        rels[bytes(name)] = len(node_bytes)
        node_bytes += struct.pack('<I', 0xFFFFFFFF) + bytes([len(name)]) + name
    # node_section = size(4) + node bytes
    node_section = struct.pack('<I', len(node_bytes)) + bytes(node_bytes)

    # ---- Folder record section ----
    # _parse_pamt_impl reads folder_count then skips folder_count * 16
    # bytes. Emit 1 stub folder record (all zeros).
    folder_records = struct.pack('<I', 1) + b'\x00' * 16

    # ---- File record section ----
    # Each record: node_ref(4) + paz_offset(4) + comp_size(4) +
    # orig_size(4) + flags(4). flags low byte = paz_index (= 0).
    # compression_type lives at bits 16..19; leave at 0 (uncompressed).
    file_count = struct.pack('<I', 3)
    file_records = b''
    for name, off, content_plain, content_slot in (
        (b'foo.xml',        xml_off, xml_plain, xml_slot),
        (b'water.material', mat_off, mat_plain, mat_slot),
        (b'data.bin',       bin_off, bin_plain, bin_slot),
    ):
        node_ref = rels[name]
        file_records += struct.pack(
            '<IIIII',
            node_ref,
            off,
            len(content_slot),   # comp_size = slot size
            len(content_plain),  # orig_size = original plaintext size
            0,                   # flags (paz_index=0, comp_type=0)
        )

    pamt_blob = (
        magic
        + paz_count
        + hash_zero
        + paz_table
        + folder_section
        + node_section
        + folder_records
        + file_count
        + file_records
    )

    pamt_path = tmp_path / "0.pamt"
    pamt_path.write_bytes(pamt_blob)

    plan = {
        'xml_path': 'test/foo.xml',
        'material_path': 'test/water.material',
        'bin_path': 'test/data.bin',
    }
    return pamt_path, paz_path, plan
