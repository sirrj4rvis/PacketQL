"""Bitmap index for a low-cardinality column (protocol).

One bitmap per distinct value: bit r is set iff row r holds that value. Combining
predicates is a bitmap AND/OR; at 1M rows a protocol bitmap is ~125 KB. Stored as
Python big integers (one bit per row), so AND/OR are just ``&`` / ``|``.
"""

from __future__ import annotations


class BitmapIndex:
    def __init__(self, values, row_count: int) -> None:
        self.row_count = row_count
        self._bitmaps: dict[int, int] = {}
        for row, value in enumerate(values):
            self.add(value, row)

    def add(self, value: int, row: int) -> None:
        self._bitmaps[value] = self._bitmaps.get(value, 0) | (1 << row)
        if row + 1 > self.row_count:
            self.row_count = row + 1

    def bitmap(self, value: int) -> int:
        return self._bitmaps.get(value, 0)

    def count(self, value: int) -> int:
        return bin(self._bitmaps.get(value, 0)).count("1")

    def rows_for(self, value: int) -> list[int]:
        bm = self._bitmaps.get(value, 0)
        rows = []
        r = 0
        while bm:
            if bm & 1:
                rows.append(r)
            bm >>= 1
            r += 1
        return rows
