"""Regression tests for the silent .material / .technique / .thtml
encryption-at-repack bug.

See docs/superpowers/specs/2026-05-22-material-encryption-fix-design.md
for full context.
"""

from cdumm.archive.paz_crypto import (
    detect_encryption_from_head,
    encrypt,
    looks_like_plaintext_head,
    lz4_compress,
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


PLAINTEXT_XML = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'


class TestDetectEncryptionFromHead:
    """2x2 matrix: compression_type in {0, 2} x {plaintext, ciphertext}."""

    def test_uncompressed_plaintext(self):
        # Slot stored as plaintext, no compression.
        head = PLAINTEXT_XML[:32]
        assert detect_encryption_from_head(
            head, compression_type=0, orig_size=len(PLAINTEXT_XML)
        ) is False

    def test_uncompressed_encrypted(self):
        # Slot stored as ChaCha20 ciphertext, no compression.
        ciphertext = encrypt(PLAINTEXT_XML, 'water.material')
        head = ciphertext[:32]
        assert detect_encryption_from_head(
            head, compression_type=0, orig_size=len(PLAINTEXT_XML)
        ) is True

    def test_lz4_compressed_plaintext(self):
        # Slot stored as raw LZ4 (not encrypted).
        # Use a payload that compresses to at least 32 bytes so the
        # head we pass to detect is a complete LZ4 block prefix.
        payload = (b'<root><a/></root>' * 64)
        compressed = lz4_compress(payload)
        assert len(compressed) >= 32, "test payload didn't compress enough"
        head = compressed[:32]
        assert detect_encryption_from_head(
            head, compression_type=2, orig_size=len(payload)
        ) is False

    def test_lz4_compressed_then_encrypted(self):
        # Slot stored as LZ4(plaintext) then encrypted.
        payload = (b'<root><a/></root>' * 64)
        compressed = lz4_compress(payload)
        encrypted = encrypt(compressed, 'foo.material')
        head = encrypted[:32]
        assert detect_encryption_from_head(
            head, compression_type=2, orig_size=len(payload)
        ) is True

    def test_empty_head_uncompressed(self):
        # Truncated read: empty head, no compression. Fail-safe to
        # "encrypted" so we never mistakenly write plaintext into a
        # slot we don't understand.
        assert detect_encryption_from_head(
            b'', compression_type=0, orig_size=0
        ) is True

    def test_empty_head_compressed(self):
        # Empty head on a compressed slot. lz4_decompress raises, so
        # classification is "encrypted" (fail-safe).
        assert detect_encryption_from_head(
            b'', compression_type=2, orig_size=10
        ) is True
