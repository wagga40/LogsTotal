"""Tier-1 tests for the columnar graph wire format — no DB, no FastAPI.

The encoder is the contract between `app/intel/graph.py` and four client modules, and
almost every field is an *index* into `client_schema()`. A drift between the two is not a
crash: it is a node painted the wrong colour or a `label:` filter that silently matches
nothing. These tests pin the round trip in both directions.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from app.constants import SEVERITY_ORDER
from app.intel.graph_payload import (
    ATTR_FLAG_NAMES,
    EDGE_CODE_FINDING,
    EDGE_CODE_JOB,
    EDGE_KIND_TYPED_BASE,
    GRAPH_PAYLOAD_VERSION,
    NODE_FLAGS,
    SUBTYPES,
    GraphEdge,
    GraphNode,
    NodeThreat,
    build_payload,
    client_schema,
    to_graphml,
)
from app.intel.queries import ATTR_FILTERS
from app.intel.relationships import RELATIONSHIP_TYPES

NS = {"g": "http://graphml.graphdrawing.org/xmlns"}


def _nodes(*specs) -> list[GraphNode]:
    return list(specs)


LOLBIN = '{"is_lolbin": true, "is_gtfobin": false}'
PUBLIC_IP = '{"version": "v4", "is_private": false, "category": "public"}'
PRIVATE_IP = '{"version": "v4", "is_private": true, "category": "rfc1918"}'


class TestSchema:
    def test_flags_and_subtypes_cover_attr_filters_exactly(self):
        """A key in neither is a `label:`/`attr:` filter the graph can never evaluate."""
        assert set(ATTR_FLAG_NAMES) | set(SUBTYPES) == set(ATTR_FILTERS)
        assert not set(ATTR_FLAG_NAMES) & set(SUBTYPES)

    def test_every_flag_is_a_distinct_power_of_two(self):
        bits = list(NODE_FLAGS.values())
        assert len(set(bits)) == len(bits)
        for b in bits:
            assert b > 0 and (b & (b - 1)) == 0

    def test_view_flags_come_first_so_a_new_attribute_cannot_renumber_them(self):
        assert NODE_FLAGS["watchlist"] == 1
        assert NODE_FLAGS["allowlisted"] == 2
        assert NODE_FLAGS["focal"] == 4
        assert NODE_FLAGS["in_case"] == 8

    def test_schema_ships_a_colour_for_every_enum_member(self):
        s = client_schema()
        for t in s["types"]:
            assert s["colors"]["type"][t].startswith("#")
        for sev in s["severities"]:
            assert s["colors"]["severity"][sev].startswith("#")
        for tac in s["tactics"]:
            assert s["colors"]["tactic"][tac].startswith("#")
        for kind in (*s["edge_kinds"], "typed"):
            key = kind if kind in s["colors"]["kind"] else "typed"
            assert s["colors"]["kind"][key].startswith("#")

    def test_schema_ships_a_label_for_every_relationship_type(self):
        s = client_schema()
        assert set(s["rels"]) == set(RELATIONSHIP_TYPES)
        for rel in s["rels"]:
            assert s["labels"]["rels"][rel]

    def test_severity_enum_ends_with_unknown(self):
        s = client_schema()
        assert s["severities"] == [*SEVERITY_ORDER, "unknown"]


class TestNodeEncoding:
    def test_indices_resolve_against_the_schema(self):
        s = client_schema()
        p = build_payload(
            scope="entity",
            focal_id=1,
            nodes=_nodes(GraphNode(1, "cmd.exe", "executable", 4, attributes_json=LOLBIN)),
            edges=[],
            stats={},
        )
        assert s["types"][p["n"]["ty"][0]] == "executable"
        assert p["n"]["fl"][0] & NODE_FLAGS["lolbin"]
        assert not p["n"]["fl"][0] & NODE_FLAGS["gtfobin"]
        assert p["n"]["fl"][0] & NODE_FLAGS["focal"]

    def test_subtype_is_one_plus_index_and_zero_means_none(self):
        s = client_schema()
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "1.2.3.4", "ip_address", attributes_json=PUBLIC_IP), GraphNode(2, "bob", "user")),
            edges=[],
            stats={},
        )
        assert s["subtypes"][p["n"]["sub"][0] - 1] == "public"
        assert p["n"]["sub"][1] == 0

    def test_malformed_attributes_json_yields_no_flags_rather_than_raising(self):
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "x", "user", attributes_json="{not json")), edges=[], stats={})
        assert p["n"]["fl"][0] == 0

    def test_duplicate_node_ids_collapse_to_one(self):
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(1, "a", "user")), edges=[], stats={})
        assert p["n"]["id"] == [1]

    def test_focal_flag_only_on_the_focal_node(self):
        p = build_payload(scope="entity", focal_id=2, nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")), edges=[], stats={})
        assert not p["n"]["fl"][0] & NODE_FLAGS["focal"]
        assert p["n"]["fl"][1] & NODE_FLAGS["focal"]


class TestSparseColumns:
    def test_sparse_columns_are_omitted_not_empty(self):
        """`"tg" in n` has to mean "were tags computed", not "does any node have one"."""
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "a", "user")), edges=[], stats={})
        assert "tg" not in p["n"]
        assert "ca" not in p["n"]
        assert "mt" not in p["n"]
        assert "dict" not in p

    def test_tags_intern_into_a_shared_dictionary(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")),
            edges=[],
            stats={},
            tags={1: ["apt28", "c2"], 2: ["apt28"]},
        )
        words = p["dict"]["tags"]
        rows = {r[0]: [words[i] for i in r[1:]] for r in p["n"]["tg"]}
        assert rows[0] == ["apt28", "c2"]
        assert rows[1] == ["apt28"]
        assert len(words) == 2

    def test_tag_rows_reference_node_indices_not_entity_ids(self):
        p = build_payload(scope="case", nodes=_nodes(GraphNode(77, "a", "user")), edges=[], stats={}, tags={77: ["x"]})
        assert p["n"]["tg"][0][0] == 0

    def test_matches_become_node_indices_and_partial_is_flagged(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(10, "a", "user"), GraphNode(20, "b", "user")),
            edges=[],
            stats={},
            matches={20},
            matches_partial=True,
        )
        assert p["n"]["mt"] == [1]
        assert p["n"]["mt_partial"] is True

    def test_a_match_for_an_absent_node_is_dropped(self):
        p = build_payload(scope="case", nodes=_nodes(GraphNode(10, "a", "user")), edges=[], stats={}, matches={999})
        assert "mt" not in p["n"]

    def test_case_membership_sets_the_in_case_flag(self):
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "a", "user")), edges=[], stats={}, cases={1: [4, 9]})
        assert p["n"]["fl"][0] & NODE_FLAGS["in_case"]
        assert p["n"]["ca"] == [[0, 4, 9]]


class TestThreatColumns:
    def test_severity_tactic_and_verdict_are_one_plus_index(self):
        s = client_schema()
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")),
            edges=[],
            stats={},
            threat={1: NodeThreat(severity="high", tactic="execution", verdict=4)},
        )
        assert s["severities"][p["n"]["sv"][0] - 1] == "high"
        assert s["tactics"][p["n"]["tc"][0] - 1] == "execution"
        assert p["n"]["en"][0] == 4
        assert p["n"]["sv"][1] == 0 and p["n"]["tc"][1] == 0 and p["n"]["en"][1] == 0

    @pytest.mark.parametrize("rank", [len(SEVERITY_ORDER), 99, "bogus"])
    def test_unrecognised_severity_clamps_onto_unknown(self, rank):
        """`severity_rank_sql()` returns len(SEVERITY_ORDER) for a value it doesn't know."""
        s = client_schema()
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "a", "user")), edges=[], stats={}, threat={1: NodeThreat(severity=rank)})
        assert s["severities"][p["n"]["sv"][0] - 1] == "unknown"

    def test_severity_rank_integers_resolve_positionally(self):
        s = client_schema()
        p = build_payload(scope="case", nodes=_nodes(GraphNode(1, "a", "user")), edges=[], stats={}, threat={1: NodeThreat(severity=0)})
        assert s["severities"][p["n"]["sv"][0] - 1] == SEVERITY_ORDER[0]


class TestEdgeEncoding:
    def test_edges_reference_node_indices(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(50, "a", "user"), GraphNode(60, "b", "user")),
            edges=[GraphEdge(50, 60, "job", 3)],
            stats={},
        )
        assert p["e"]["s"] == [0] and p["e"]["t"] == [1]

    def test_every_edge_endpoint_is_a_valid_node_index(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")),
            edges=[GraphEdge(1, 2, "job"), GraphEdge(1, 999, "job"), GraphEdge(2, 2, "job")],
            stats={},
        )
        n = len(p["n"]["id"])
        assert len(p["e"]["s"]) == 1, "dangling and self edges must be dropped"
        assert all(0 <= i < n for i in p["e"]["s"] + p["e"]["t"])

    def test_kind_codes_split_undirected_from_typed(self):
        s = client_schema()
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "executable"), GraphNode(2, "b", "hash")),
            edges=[GraphEdge(1, 2, "job"), GraphEdge(1, 2, "finding"), GraphEdge(1, 2, "hashes_to", 9)],
            stats={},
        )
        assert p["e"]["k"] == [EDGE_CODE_JOB, EDGE_CODE_FINDING, EDGE_KIND_TYPED_BASE + s["rels"].index("hashes_to")]

    def test_an_unknown_kind_is_dropped_not_guessed(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")),
            edges=[GraphEdge(1, 2, "invented_relationship")],
            stats={},
        )
        assert p["e"]["s"] == []

    def test_parallel_typed_edges_between_one_pair_all_survive(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "executable"), GraphNode(2, "b", "executable")),
            edges=[GraphEdge(1, 2, "parent_of", 3), GraphEdge(1, 2, "loads", 1)],
            stats={},
        )
        assert len(p["e"]["k"]) == 2

    def test_weight_is_never_zero(self):
        p = build_payload(
            scope="case",
            nodes=_nodes(GraphNode(1, "a", "user"), GraphNode(2, "b", "user")),
            edges=[GraphEdge(1, 2, "job", 0)],
            stats={},
        )
        assert p["e"]["w"] == [1]


class TestVersion:
    def test_payload_and_schema_agree_on_the_version(self):
        assert build_payload(scope="case", nodes=[], edges=[], stats={})["v"] == GRAPH_PAYLOAD_VERSION
        assert client_schema()["v"] == GRAPH_PAYLOAD_VERSION


class TestGraphml:
    def _xml(self, **kw):
        payload = build_payload(stats={}, **kw)
        return ET.fromstring(to_graphml(payload, name=kw.pop("name", "logstotal-graph"))), payload

    def test_empty_payload_is_well_formed(self):
        root = ET.fromstring(to_graphml(build_payload(scope="case", nodes=[], edges=[], stats={})))
        assert root.tag.endswith("graphml")
        assert len(root.findall("g:graph", NS)) == 1

    def test_graph_name_and_undirected_default(self):
        xml = to_graphml(build_payload(scope="case", nodes=[], edges=[], stats={}), name="my-case-42")
        g = ET.fromstring(xml).find("g:graph", NS)
        assert g.get("id") == "my-case-42"
        assert g.get("edgedefault") == "undirected"

    def test_node_ids_keep_the_e_prefix_and_carry_their_attributes(self):
        xml = to_graphml(
            build_payload(
                scope="entity",
                focal_id=1,
                nodes=_nodes(GraphNode(1, "1.2.3.4", "ip_address", 5, watchlist=True, attributes_json=PRIVATE_IP)),
                edges=[],
                stats={},
            )
        )
        node = ET.fromstring(xml).find(".//g:node", NS)
        assert node.get("id") == "e1"
        keys = {d.get("key"): d.text for d in node.findall("g:data", NS)}
        assert keys["label"] == "1.2.3.4"
        assert keys["entity_type"] == "ip_address"
        assert keys["subtype"] == "rfc1918"
        assert keys["watchlist"] == "true"
        assert keys["allowlisted"] == "false"
        assert keys["job_count"] == "5"
        assert keys["focal"] == "true"

    def test_only_typed_edges_are_marked_directed(self):
        xml = to_graphml(
            build_payload(
                scope="case",
                nodes=_nodes(GraphNode(1, "a", "executable"), GraphNode(2, "b", "hash")),
                edges=[GraphEdge(1, 2, "job", 2), GraphEdge(1, 2, "hashes_to", 4)],
                stats={},
            )
        )
        edges = ET.fromstring(xml).findall(".//g:edge", NS)
        assert len(edges) == 2
        by_kind = {e.find('g:data[@key="kind"]', NS).text: e for e in edges}
        assert by_kind["job"].get("directed") is None
        assert by_kind["typed"].get("directed") == "true"
        assert by_kind["typed"].find('g:data[@key="rel_type"]', NS).text == "hashes_to"

    def test_edge_endpoints_are_entity_ids_not_indices(self):
        xml = to_graphml(
            build_payload(
                scope="case",
                nodes=_nodes(GraphNode(41, "a", "user"), GraphNode(77, "b", "user")),
                edges=[GraphEdge(41, 77, "finding", 2)],
                stats={},
            )
        )
        edge = ET.fromstring(xml).find(".//g:edge", NS)
        assert edge.get("source") == "e41"
        assert edge.get("target") == "e77"

    def test_edge_ids_are_unique_across_parallel_edges(self):
        xml = to_graphml(
            build_payload(
                scope="case",
                nodes=_nodes(GraphNode(1, "a", "executable"), GraphNode(2, "b", "executable")),
                edges=[GraphEdge(1, 2, "parent_of"), GraphEdge(1, 2, "loads"), GraphEdge(1, 2, "job")],
                stats={},
            )
        )
        ids = [e.get("id") for e in ET.fromstring(xml).findall(".//g:edge", NS)]
        assert len(set(ids)) == len(ids) == 3

    def test_special_characters_are_escaped_in_labels_and_the_graph_name(self):
        xml = to_graphml(
            build_payload(scope="case", nodes=_nodes(GraphNode(1, "danger <script>", "user")), edges=[], stats={}),
            name='evil" onload="x',
        )
        assert "<script>" not in xml
        assert "&lt;script&gt;" in xml
        ET.fromstring(xml)

    def test_all_keys_are_declared(self):
        root = ET.fromstring(to_graphml(build_payload(scope="case", nodes=[], edges=[], stats={})))
        declared = {k.get("id") for k in root.findall("g:key", NS)}
        assert {"label", "entity_type", "subtype", "watchlist", "allowlisted", "job_count", "focal", "kind", "weight", "rel_type"} <= declared


def test_graphml_survives_a_control_character_in_a_label():
    """XML 1.0 cannot carry C0 controls other than tab, LF and CR — not even escaped. An
    entity value with an ESC in it (a crafted task or service name) made the whole export a
    file no XML parser, yEd or Gephi would open."""
    from app.intel.graph_payload import to_graphml

    doc = to_graphml({"n": {"id": [1, 2], "lb": ["svc\x1bname\x00", "ok\ttab"], "ty": [0, 0], "sub": [0, 0], "fl": [0, 0], "jc": [1, 1]}, "e": {}})
    root = ET.fromstring(doc)
    labels = [d.text for d in root.iter("{http://graphml.graphdrawing.org/xmlns}data") if d.get("key") == "label"]
    assert labels == ["svcname", "ok\ttab"]
