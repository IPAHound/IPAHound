import os

import pytest

from ipahound.lib.bdb_reader import BdbBtreeReader, BdbError

SAMPLE_DB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "id2entry.db"
)

requires_sample_db = pytest.mark.skipif(
    not os.path.isfile(SAMPLE_DB),
    reason="sample id2entry.db is not present in the repository root",
)


@requires_sample_db
class TestBdbBtreeReaderSample:

    def test_reads_all_records(self):
        reader = BdbBtreeReader(SAMPLE_DB)
        items = list(reader.items())
        assert len(items) == 600

    def test_keys_are_unique_and_sorted(self):
        reader = BdbBtreeReader(SAMPLE_DB)
        keys = [key for key, _ in reader.items()]
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))

    def test_first_record_is_domain_entry(self):
        reader = BdbBtreeReader(SAMPLE_DB)
        key, value = next(iter(reader.items()))
        assert key == b"\x00\x00\x00\x01"
        assert value.startswith(b"rdn: dc=positive,dc=ipa\n")

    def test_overflow_chain_is_followed(self):
        # uid=admin (entryid 40) is the largest record and lives on a chain
        # of overflow pages
        reader = BdbBtreeReader(SAMPLE_DB)
        sizes = [len(value) for _, value in reader.items()]
        assert max(sizes) > 30000

    def test_values_are_nul_terminated_ldif(self):
        reader = BdbBtreeReader(SAMPLE_DB)
        for _, value in reader.items():
            assert value.endswith(b"\x00")
            assert b"\x00" not in value[:-1]
            assert value.startswith(b"rdn: ")


class TestBdbBtreeReaderErrors:

    def test_not_a_database(self, tmp_path):
        target = tmp_path / "notadb.bin"
        target.write_bytes(b"definitely not a berkeley db file" * 32)
        with pytest.raises(BdbError):
            BdbBtreeReader(str(target))

    def test_truncated_file(self, tmp_path):
        target = tmp_path / "tiny.bin"
        target.write_bytes(b"\x00" * 16)
        with pytest.raises(BdbError):
            BdbBtreeReader(str(target))
