"""交换协议源的字段、字节与摘要交叉检查；不实现通用 Schema 或密码验证器。"""

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import contract

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "api/realtime/message.schema.json").read_text())
DEFINITIONS = SCHEMA["$defs"]
VECTORS = json.loads((ROOT / "api/realtime/vectors.json").read_text())
REQUEST = "ConsistencyExchangeRequestStatement"
PACKAGE = "ConsistencyExchangePackageStatement"


class ExchangeContractTests(unittest.TestCase):
    def test_typed_statement_fields_are_complete_and_strict(self):
        common = ("protocol_version", "service_id", "conversation_id", "source", "target")
        expected = {
            REQUEST: common + ("source_fingerprint", "target_fingerprint", "challenge"),
            PACKAGE: common + ("challenge", "request_sha256", "predecessor", "record"),
        }
        for name, fields in expected.items():
            with self.subTest(definition=name):
                definition = DEFINITIONS[name]
                self.assertEqual(tuple(definition["properties"]), fields)
                self.assertEqual(tuple(definition["required"]), fields)
                self.assertFalse(definition["additionalProperties"])
                for field in ("source", "target"):
                    self.assertEqual(definition["properties"][field], {"$ref": "#/$defs/Identity"})
        self.assertEqual(DEFINITIONS[PACKAGE]["properties"]["predecessor"],
                         {"$ref": "#/$defs/PermissionCheckpoint"})
        self.assertEqual(DEFINITIONS[PACKAGE]["properties"]["record"],
                         {"$ref": "#/$defs/PermissionRecord"})

    def test_signed_wrappers_preserve_distinct_domains_and_byte_limits(self):
        for kind, statement, byte_schema, limit in (
                ("Request", REQUEST, "HeaderBytes", 16 * 1024),
                ("Package", PACKAGE, "PayloadBytes", 512 * 1024)):
            with self.subTest(kind=kind):
                definition = DEFINITIONS["SignedConsistencyExchange" + kind]
                self.assertEqual(tuple(definition["required"]), ("statement_bytes", "signature_bytes"))
                self.assertFalse(definition["additionalProperties"])
                self.assertEqual(definition["properties"]["statement_bytes"],
                                 {"$ref": "#/$defs/" + byte_schema})
                self.assertEqual(definition["properties"]["signature_bytes"],
                                 {"$ref": "#/$defs/PermissionSignatureBytes"})
                self.assertEqual(definition["x-statement-schema"], {"$ref": "#/$defs/" + statement})
                self.assertEqual(definition["x-signing-domain-utf8"],
                                 f"Rocket-IM/POC/consistency-exchange-{kind.lower()}/v1\0")
                self.assertEqual(DEFINITIONS[byte_schema]["x-max-decoded-bytes"], limit)
                self.assertEqual(DEFINITIONS[statement]["x-max-utf8-json-bytes"], limit)

    def test_cli_variants_are_tagged_and_do_not_create_http_operations(self):
        operation_schema = DEFINITIONS["ConsistencyExchangeOperation"]
        tags = []
        for entry in operation_schema["oneOf"]:
            definition = DEFINITIONS[entry["$ref"].split("/")[-1]]
            self.assertFalse(definition["additionalProperties"])
            self.assertEqual(set(definition["required"]), set(definition["properties"]))
            tags.append(definition["properties"]["operation"]["const"])
        expected = {"consistency_exchange_" + action
                    for action in ("begin", "export", "import", "cancel", "inspect")}
        self.assertEqual(set(tags), expected)
        self.assertEqual(len(tags), len(set(tags)))
        self.assertFalse(expected & contract.OPERATIONS)
        self.assertEqual(SCHEMA["oneOf"], [{"$ref": "#/$defs/Envelope"}, {"$ref": "#/$defs/EventSlot"}])
        self.assertEqual(operation_schema["x-max-active-exchanges"], 1)
        self.assertEqual(operation_schema["x-max-exported-packages"], 128)
        self.assertEqual(operation_schema["x-max-imported-packages"], 128)
        self.assertEqual(operation_schema["x-max-utf8-json-bytes"], contract.MAX_REQUEST_BYTES)
        self.assertEqual(operation_schema["x-max-snapshot-bytes"], 16 * 1024 * 1024)

    def test_fixed_vectors_check_only_the_named_boundary(self):
        # 不递归解释 Schema，也不把这些检查计作签名、可信前驱或完整协议验证。
        names = set()
        for vector in VECTORS["consistency_exchange_vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertNotIn(vector["name"], names)
                names.add(vector["name"])
                definition = DEFINITIONS[vector["schema_ref"].split("/")[-1]]
                value = vector["value"]
                boundary = vector["boundary"]
                if boundary == "object_fields":
                    try:
                        contract.fields(value, definition["required"])
                        valid = True
                    except contract.ProtocolError:
                        valid = False
                elif boundary == "hash_field":
                    pattern = definition["properties"][vector["field"]]["pattern"]
                    valid = isinstance(value, str) and re.search(pattern, value) is not None
                    try:
                        contract.validate_state_ref(value)
                        runtime_valid = True
                    except contract.ProtocolError:
                        runtime_valid = False
                    self.assertEqual(valid, runtime_valid)
                elif boundary == "constant_field":
                    valid = value == definition["properties"][vector["field"]]["const"]
                elif boundary == "enum_field":
                    valid = value in definition["properties"][vector["field"]]["enum"]
                else:
                    self.fail("存在未声明的固定边界向量")
                self.assertEqual(valid, vector["expected_boundary_valid"])

    def test_request_digest_matches_fixed_original_byte_vector(self):
        vector = VECTORS["consistency_exchange_request_digest_vector"]
        request = vector["request"]
        serialized = json.dumps({field: request[field] for field in ("statement_bytes", "signature_bytes")},
                                separators=(",", ":")).encode()
        self.assertEqual(serialized.decode(), vector["serialized_utf8"])
        self.assertEqual(hashlib.sha256(serialized).hexdigest(), vector["request_sha256"])
        self.assertEqual(json.loads(base64.b64decode(request["statement_bytes"])), vector["decoded_statement"])
        # 外层 JSON 重排不影响 typed SignedRecord 的固定序列化顺序。
        reordered = {field: request[field] for field in ("signature_bytes", "statement_bytes")}
        normalized = {field: reordered[field] for field in ("statement_bytes", "signature_bytes")}
        self.assertEqual(json.dumps(normalized, separators=(",", ":")).encode(), serialized)
        for field in ("statement_bytes", "signature_bytes"):
            changed = copy.deepcopy(request)
            raw = base64.b64decode(changed[field])
            raw = raw + b" " if field == "statement_bytes" else bytes([1]) * 64
            changed[field] = base64.b64encode(raw).decode()
            self.assertNotEqual(hashlib.sha256(json.dumps(changed, separators=(",", ":")).encode()).hexdigest(),
                                vector["request_sha256"])

    def test_fingerprints_cover_the_complete_public_keys(self):
        vector = VECTORS["consistency_exchange_request_digest_vector"]["decoded_statement"]
        for field, raw in (("source_fingerprint", bytes([2]) * 32),
                           ("target_fingerprint", bytes([1]) * 32)):
            self.assertEqual(vector[field], hashlib.sha256(raw).hexdigest())
            self.assertEqual(len(vector[field]), 64)
        self.assertNotEqual(vector["source"], vector["target"])

    def test_decoded_size_limits_and_noncanonical_base64(self):
        for scalar_name in ("HeaderBytes", "PayloadBytes"):
            limit = DEFINITIONS[scalar_name]["x-max-decoded-bytes"]
            exact = base64.b64encode(b"x" * limit).decode()
            self.assertEqual(len(contract.decode_bytes(exact, "statement_bytes", limit)), limit)
            for invalid in (base64.b64encode(b"x" * (limit + 1)).decode(), "AB==", "", "AA==\n"):
                with self.subTest(scalar=scalar_name, encoded_size=len(invalid)):
                    with self.assertRaises(contract.ProtocolError):
                        contract.decode_bytes(invalid, "statement_bytes", limit)
        for invalid in (b'{"challenge":"a","challenge":"b"}', b'{"challenge":"\xff"}',
                        b" " * (contract.MAX_REQUEST_BYTES + 1)):
            with self.assertRaises(contract.ProtocolError):
                contract.parse_json(invalid)


if __name__ == "__main__":
    unittest.main()
