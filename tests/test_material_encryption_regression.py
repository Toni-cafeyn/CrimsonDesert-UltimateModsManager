"""Regression tests for the silent .material / .technique / .thtml
encryption-at-repack bug.

See docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md
for full context.
"""

import os
import struct

import pytest

from cdumm.archive.paz_crypto import (
    looks_like_plaintext_head,
)


# Sample 16 bytes of ChaCha20 ciphertext-looking content (high entropy)
CIPHERTEXT_SAMPLE = bytes.fromhex(
    "6aa180abd44aefdb818674dd78859415"
)


class TestLooksLikePlaintextHead:
    def test_xml_with_utf8_bom_is_plaintext(self):
        assert looks_like_plaintext_head(
            b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        ) is True

    def test_indented_xml_is_plaintext(self):
        assert looks_like_plaintext_head(b'    <root>\n  <a/></root>') is True

    def test_plain_ascii_is_plaintext(self):
        assert looks_like_plaintext_head(b'<Technique Name="x"/>') is True

    def test_ciphertext_sample_is_not_plaintext(self):
        assert looks_like_plaintext_head(CIPHERTEXT_SAMPLE) is False

    def test_empty_bytes_is_not_plaintext(self):
        assert looks_like_plaintext_head(b'') is False

    def test_whitespace_only_is_not_plaintext(self):
        assert looks_like_plaintext_head(b'    \r\n\t') is False

    def test_bom_alone_is_not_plaintext(self):
        # Just the BOM with nothing after must not be classified as plaintext.
        assert looks_like_plaintext_head(b'\xef\xbb\xbf') is False
