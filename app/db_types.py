"""Column types shared by the models.

`CompressedText` stores large JSON text zstd-compressed, as text, so no DDL changes: the column
stays `TEXT` on SQLite and PostgreSQL alike, Alembic sees no type change, and a database
written before it existed reads unchanged. Measured on the development data: `Finding.details`
compresses 4.8x per row and relationship evidence samples 20x.
"""

from __future__ import annotations

import base64

from sqlalchemy.types import Text, TypeDecorator

from app.compression_utils import compress, decompress

#: Marks an encoded value. JSON text starts with `[`, `{` or `"`, so no plaintext row of a
#: column this type is used on can begin with it.
PREFIX = "zs1:"
#: Below this, the frame header and base64 make the encoded form no smaller.
MIN_CHARS = 512


class CompressedText(TypeDecorator):
    """JSON text stored as `zs1:` + base64(zstd) when that is shorter; plaintext otherwise.

    Only for columns nothing reads inside SQL: a LIKE, `length()` or JSON function would see
    the encoded form. `tests/test_compressed_columns.py` pins that for every column using it.
    Base64 rather than bytes because a `bytea` value in a `text` column is an error on
    PostgreSQL; it costs a third of the gain and keeps the column a column of text.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None or len(value) < MIN_CHARS or value.startswith(PREFIX):
            return value
        packed = PREFIX + base64.b64encode(compress(value.encode("utf-8"))).decode("ascii")
        return packed if len(packed) < len(value) else value

    def process_result_value(self, value, dialect):
        if value is None or not value.startswith(PREFIX):
            return value
        return decompress(base64.b64decode(value[len(PREFIX) :])).decode("utf-8")
