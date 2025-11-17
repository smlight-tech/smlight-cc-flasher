"""Tests for firmware module."""

import binascii

import pytest

from smlight_cc_flasher.firmware import Segment


class TestSegment:
    """Tests for Segment dataclass."""

    def test_segment_creation(self):
        """Test creating a segment with valid data."""
        data = bytearray(b"\x01\x02\x03\x04\xff")
        segment = Segment(start=0x1000, end=0x1004, bytes=data)

        assert segment.start == 0x1000
        assert segment.end == 0x1004
        assert segment.size == 4
        assert len(segment.bytes) == 4
        assert segment.bytes == bytearray(b"\x01\x02\x03\x04")

    def test_segment_size_calculation(self):
        """Test that segment size is calculated correctly."""
        data = bytearray(b"\xaa\xbb\xcc\xff")
        segment = Segment(start=0x2000, end=0x2003, bytes=data)

        assert segment.size == 3
        assert segment.end - segment.start == 3

    def test_segment_crc32_calculated(self):
        """Test that CRC32 is calculated during initialization."""
        data = bytearray(b"\x01\x02\x03\x04\xff")
        segment = Segment(start=0x0, end=0x4, bytes=data)

        assert hasattr(segment, "crc32")
        assert isinstance(segment.crc32, int)
        expected_crc = binascii.crc32(bytearray(b"\x01\x02\x03\x04")) & 0xFFFFFFFF
        assert segment.crc32 == expected_crc

    def test_segment_invalid_end_byte(self):
        """Test that segment requires 0xFF as last byte."""
        data = bytearray(b"\x01\x02\x03\x04")
        with pytest.raises(AssertionError, match="Segment data does not end with 0xFF"):
            Segment(start=0x0, end=0x4, bytes=data)

    def test_segment_size_mismatch(self):
        """Test that segment validates size matches data."""
        data = bytearray(b"\x01\x02\xff")
        with pytest.raises(
            AssertionError, match="Segment size does not match data size"
        ):
            Segment(start=0x0, end=0x10, bytes=data)
