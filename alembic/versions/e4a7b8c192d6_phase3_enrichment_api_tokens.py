"""phase 3: pluggable enrichment + api tokens

Revision ID: e4a7b8c192d6
Revises: d8f2a91e4c7b
Create Date: 2026-05-25 09:00:00.000000
"""

import json
from typing import Sequence, Union

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

revision: str = "e4a7b8c192d6"
down_revision: Union[str, None] = "d8f2a91e4c7b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mirror of the legacy ENRICHMENT_LINKS dict in app/routers/intel.py at migration time.
# Future schema changes should NOT update this; new presets go through the admin UI.
_LEGACY_ENRICHMENT_LINKS = {
    "ip_address": [
        ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{value}"),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{value}"),
        ("Shodan", "https://www.shodan.io/host/{value}"),
        ("GreyNoise", "https://viz.greynoise.io/ip/{value}"),
    ],
    "domain": [
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{value}"),
        ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search={value}"),
        ("SecurityTrails", "https://securitytrails.com/domain/{value}"),
    ],
    "hash": [
        ("VirusTotal", "https://www.virustotal.com/gui/file/{value}"),
        ("MalwareBazaar", "https://bazaar.abuse.ch/sample/{value}/"),
        ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query={value}"),
    ],
    "executable": [
        ("VirusTotal", "https://www.virustotal.com/gui/search/{value}"),
    ],
}


def upgrade() -> None:
    enrichment = op.create_table(
        "enrichment_service",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("provider_key", sa.String(length=40), nullable=True),
        sa.Column("entity_types", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("link_template", sa.String(length=500), nullable=True),
        sa.Column("api_template", sa.String(length=500), nullable=True),
        sa.Column("api_method", sa.String(length=10), nullable=False, server_default="GET"),
        sa.Column("api_headers_json", sa.Text(), nullable=True),
        sa.Column("api_token_encrypted", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("display_order", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_enrichment_service_enabled"), "enrichment_service", ["enabled"], unique=False)

    # Seed from legacy ENRICHMENT_LINKS — one row per (service, entity_type) pair, since the
    # URL template often differs per type (e.g. VirusTotal /ip-address/, /domain/, /file/).
    # Row names are suffixed with " (type)" only when the same service appears for >1 type.
    name_to_types: dict[str, list[str]] = {}
    for etype, items in _LEGACY_ENRICHMENT_LINKS.items():
        for name, _ in items:
            name_to_types.setdefault(name, []).append(etype)

    seed_rows = []
    order = 10
    for etype, items in _LEGACY_ENRICHMENT_LINKS.items():
        for name, url in items:
            disambiguated = name if len(name_to_types[name]) == 1 else f"{name} ({etype})"
            seed_rows.append({
                "name": disambiguated,
                "provider_key": None,
                "entity_types": json.dumps([etype]),
                "link_template": url,
                "api_template": None,
                "api_method": "GET",
                "api_headers_json": None,
                "api_token_encrypted": None,
                "enabled": True,
                "display_order": order,
                "notes": None,
            })
            order += 10
    if seed_rows:
        op.bulk_insert(enrichment, seed_rows)

    op.create_table(
        "api_token",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("prefix", sa.String(length=8), nullable=False),
        sa.Column("scopes_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_by_user_id", GUID(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(op.f("ix_api_token_token_hash"), "api_token", ["token_hash"], unique=False)
    op.create_index(op.f("ix_api_token_revoked_at"), "api_token", ["revoked_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_api_token_revoked_at"), table_name="api_token")
    op.drop_index(op.f("ix_api_token_token_hash"), table_name="api_token")
    op.drop_table("api_token")

    op.drop_index(op.f("ix_enrichment_service_enabled"), table_name="enrichment_service")
    op.drop_table("enrichment_service")
