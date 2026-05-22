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
from cdumm.archive.paz_parse import (
    PazEntry,
    _populate_encryption_overrides,
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


class TestPazEntryEncryptedWhitelist:
    """Whitelist regression: when _encrypted_override is None (entries
    built by hand or via the IOError fallback), the property falls
    back to a hard-coded extension whitelist. v3.0 narrowed it to
    .xml only and re-introduced the v2.1.2 regression; v3.x+ keeps
    .xml/.css/.html/.js; this fix adds the three extensions known to
    cause silent corruption in-game when missed: .material,
    .technique, .thtml.
    """

    def _make_entry(self, path: str) -> PazEntry:
        return PazEntry(
            path=path,
            paz_file='dummy.paz',
            offset=0,
            comp_size=0,
            orig_size=0,
            flags=0,
            paz_index=0,
        )

    def test_xml_is_encrypted(self):
        assert self._make_entry('ui/xml/foo.xml').encrypted is True

    def test_css_is_encrypted(self):
        assert self._make_entry('ui/xml/theme.css').encrypted is True

    def test_html_is_encrypted(self):
        assert self._make_entry('ui/page.html').encrypted is True

    def test_js_is_encrypted(self):
        assert self._make_entry('ui/script.js').encrypted is True

    def test_material_is_encrypted(self):
        # Regression: this returned False before the fix and caused
        # silent water/dissolve material corruption in
        # InternalGraphicsMod v3.1.2.
        assert self._make_entry('technique/water.material').encrypted is True

    def test_technique_is_encrypted(self):
        assert self._make_entry('technique/foo.technique').encrypted is True

    def test_thtml_is_encrypted(self):
        assert self._make_entry('ui/template.thtml').encrypted is True

    def test_unknown_extension_is_not_encrypted(self):
        assert self._make_entry('models/character.bin').encrypted is False

    def test_override_true_wins_over_whitelist_miss(self):
        e = self._make_entry('models/foo.bin')
        e._encrypted_override = True
        assert e.encrypted is True

    def test_override_false_wins_over_whitelist_hit(self):
        e = self._make_entry('ui/page.html')
        e._encrypted_override = False
        assert e.encrypted is False


class TestPopulateEncryptionOverrides:
    """Unit tests for the parse-time sniff helper."""

    def _make_entry(self, path: str, paz_file: str, offset: int,
                     comp_size: int, orig_size: int,
                     compression_type: int = 0) -> PazEntry:
        # PAMT flags pack compression_type at bits 16..19.
        flags = (compression_type & 0xF) << 16
        return PazEntry(
            path=path,
            paz_file=paz_file,
            offset=offset,
            comp_size=comp_size,
            orig_size=orig_size,
            flags=flags,
            paz_index=0,
        )

    def test_uncompressed_plaintext_slot_sets_override_false(self, tmp_path):
        paz = tmp_path / "0.paz"
        plaintext = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        paz.write_bytes(plaintext)
        entry = self._make_entry(
            'technique/water.material', str(paz), 0,
            comp_size=len(plaintext), orig_size=len(plaintext)
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is False

    def test_uncompressed_encrypted_slot_sets_override_true(self, tmp_path):
        paz = tmp_path / "0.paz"
        plaintext = b'\xef\xbb\xbf<Technique Name="Water"/>\r\n'
        ciphertext = encrypt(plaintext, 'water.material')
        paz.write_bytes(ciphertext)
        entry = self._make_entry(
            'technique/water.material', str(paz), 0,
            comp_size=len(ciphertext), orig_size=len(plaintext)
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is True

    def test_multiple_entries_in_same_paz_share_one_open(self, tmp_path):
        """Sanity check that grouping doesn't break correctness for
        multiple entries in the same PAZ at different offsets."""
        paz = tmp_path / "0.paz"
        # Both blocks must be exactly 32 bytes so the second entry's
        # offset aligns cleanly and detect_encryption_from_head gets a
        # full 32-byte read. Null padding makes looks_like_plaintext_head
        # return False (< 90% printable), so use real XML padding instead.
        plaintext = b'\xef\xbb\xbf<root><element/></root>\r\n\r\n'
        ciphertext = encrypt(b'\xef\xbb\xbf<root><element/></root>\r\n\r\n',
                             'foo.material')
        paz.write_bytes(plaintext + ciphertext)

        plain_entry = self._make_entry(
            'ui/a.xml', str(paz), 0,
            comp_size=len(plaintext), orig_size=len(plaintext)
        )
        crypt_entry = self._make_entry(
            'technique/foo.material', str(paz), len(plaintext),
            comp_size=len(ciphertext), orig_size=len(ciphertext)
        )

        _populate_encryption_overrides([plain_entry, crypt_entry])

        assert plain_entry._encrypted_override is False
        assert crypt_entry._encrypted_override is True

    def test_missing_paz_leaves_override_none(self, tmp_path):
        """IOError fallback: when the PAZ can't be opened, the
        override stays None so PazEntry.encrypted falls through to
        the widened extension whitelist."""
        entry = self._make_entry(
            'technique/water.material',
            str(tmp_path / "does_not_exist.paz"), 0,
            comp_size=100, orig_size=100
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is None
        # Whitelist still classifies .material as encrypted.
        assert entry.encrypted is True

    def test_truncated_slot_classified_as_encrypted(self, tmp_path):
        """A PAZ shorter than the declared offset returns 0 bytes;
        detect_encryption_from_head treats empty head as encrypted
        (fail-safe)."""
        paz = tmp_path / "0.paz"
        paz.write_bytes(b'\x00' * 10)
        entry = self._make_entry(
            'technique/foo.material', str(paz), 1000,
            comp_size=2315, orig_size=2315
        )

        _populate_encryption_overrides([entry])

        assert entry._encrypted_override is True


class TestParsePamtPopulatesOverrides:
    """End-to-end: parse_pamt runs the sniff and downstream code
    sees correct .encrypted verdicts on .material entries."""

    def test_parse_pamt_populates_override_on_material_entry(self, tmp_path):
        from tests.fixtures._material_encryption_synth import (
            build_synthetic_pamt_paz,
        )
        from cdumm.archive.paz_parse import parse_pamt

        pamt_path, _paz_path, plan = build_synthetic_pamt_paz(tmp_path)

        entries = parse_pamt(str(pamt_path), paz_dir=str(tmp_path))

        by_path = {e.path: e for e in entries}
        # The synthetic fixture lays out one entry per content category.
        material = by_path[plan['material_path']]
        xml = by_path[plan['xml_path']]
        binary = by_path[plan['bin_path']]

        # .material was encrypted in the fixture; sniff must catch it
        # even though no extension widening is needed (the whitelist
        # also covers .material now, but we want to prove the sniff
        # itself wrote the override).
        assert material._encrypted_override is True
        assert material.encrypted is True

        # .xml was encrypted: override True.
        assert xml._encrypted_override is True

        # Plaintext .bin: override False (sniff wins over the
        # whitelist, which would have said False anyway).
        assert binary._encrypted_override is False
        assert binary.encrypted is False
