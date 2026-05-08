"""
Unit tests for .NET metadata extraction helpers.
"""

import os
import sys

# Add workers directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static_worker import StaticWorker


class _FakeIndex:
    def __init__(self, row_index):
        self.row_index = row_index


class TestDotNetMetadataExtractHelpers:
    def setup_method(self):
        self.worker = StaticWorker()

    def test_resolve_mdt_row_indices_from_expanded_list(self):
        result = self.worker._resolve_mdt_row_indices(
            [_FakeIndex(2), _FakeIndex(3), _FakeIndex(4)],
            total_rows=10,
        )

        assert result == [2, 3, 4]

    def test_resolve_mdt_row_indices_from_start_and_next(self):
        result = self.worker._resolve_mdt_row_indices(
            _FakeIndex(5),
            _FakeIndex(8),
            total_rows=12,
        )

        assert result == [5, 6, 7]

    def test_resolve_mdt_row_indices_handles_missing_or_invalid_values(self):
        assert self.worker._resolve_mdt_row_indices(None, total_rows=10) == []
        assert self.worker._resolve_mdt_row_indices([], total_rows=10) == []
        assert self.worker._resolve_mdt_row_indices("bad", total_rows=10) == []
