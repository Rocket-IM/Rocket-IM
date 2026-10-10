"""执行固定协议字节向量与输入边界；不替代完整 OpenAPI/JSON Schema 验证器。"""

import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import contract

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "api/realtime/vectors.json").read_text())
SCHEMA_PATH = ROOT / "api/realtime/message.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text())
OPENAPI_PATH = ROOT / "api/http/poc.openapi.json"
OPENAPI = json.loads(OPENAPI_PATH.read_text())


class ContractTests(unittest.TestCase):
    def assert_code(self, code, call):
        with self.assertRaises(contract.ProtocolError) as raised:
            call()
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(raised.exception.outcome, "not_recorded")

    def test_fixed_wire_vectors(self):
        for vector in VECTORS["vectors"]:
            with self.subTest(vector=vector["name"]):
                if vector["kind"] == "request":
                    call = lambda: contract.validate_request(vector["operation"], vector["value"])
                elif vector["kind"] == "message_acceptance":
                    from receipt_contract import validate_message_acceptance
                    call = lambda: validate_message_acceptance(vector["value"])
                elif vector["kind"] == "consistency_head":
                    from receipt_contract import validate_consistency_head
                    call = lambda: validate_consistency_head(vector["value"])
                else:
                    raw = base64.b64decode(vector["raw_base64"], validate=True)
                    call = lambda: contract.parse_json(raw)
                if vector["expected_code"] is None:
                    call()
                else:
                    self.assert_code(vector["expected_code"], call)

    def test_header_bytes_are_not_reconstructed(self):
        original = VECTORS["header_vector"]
        reordered = VECTORS["same_semantics_different_bytes"]
        header, raw = contract.validate_header_bytes(original["header_bytes"])
        header_two, raw_two = contract.validate_header_bytes(reordered["header_bytes"])
        self.assertEqual(header, original["decoded_header"])
        self.assertEqual(header, header_two)
        self.assertEqual(raw.decode(), original["utf8_text"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), original["sha256"])
        self.assertEqual(hashlib.sha256(raw_two).hexdigest(), reordered["sha256"])
        self.assertNotEqual(raw, raw_two)

    def test_permission_proof_digest_matches_fixed_domain_and_length_vector(self):
        from receipt_contract import proof_digest
        vector = VECTORS["permission_proof_digest_vector"]
        self.assertEqual(proof_digest(vector["change"]), vector["sha256"])
        changed = copy.deepcopy(vector["change"])
        changed["commit_bytes"] = base64.b64encode(base64.b64decode(changed["commit_bytes"]) + b"x").decode()
        self.assertNotEqual(proof_digest(changed), vector["sha256"])

    def test_message_digest_binds_original_bytes_and_segment_lengths(self):
        from receipt_contract import message_envelope_digest, validate_message_acceptance
        vector = VECTORS["message_envelope_digest_vector"]
        header, payload = (base64.b64decode(vector["envelope"][name]) for name in ("header_bytes", "payload_bytes"))
        self.assertEqual(message_envelope_digest(header, payload), vector["sha256"])
        self.assertEqual(validate_message_acceptance(vector["receipt"]), vector["statement"])
        self.assertNotEqual(message_envelope_digest(header + b" ", payload), vector["sha256"])
        self.assertNotEqual(message_envelope_digest(header, payload + b"x"), vector["sha256"])
        self.assertNotEqual(message_envelope_digest(b"ab", b"c"), message_envelope_digest(b"a", b"bc"))

    def test_history_digests_bind_request_signatures_and_ciphertext_segments(self):
        from history_contract import ciphertext_digest, package_digest, request_digest, validate_history_receipt
        vector = VECTORS["history_digest_vector"]
        self.assertEqual(request_digest(vector["request"]), vector["request_sha256"])
        self.assertEqual(package_digest(vector["package"]), vector["package_sha256"])
        self.assertEqual(ciphertext_digest(vector["package"]), vector["ciphertext_sha256"])
        self.assertEqual(validate_history_receipt(vector["receipt"]), vector["receipt_statement"])
        changed = copy.deepcopy(vector["request"])
        changed["signature_bytes"] = base64.b64encode(bytes([1]) * 64).decode()
        self.assertNotEqual(request_digest(changed), vector["request_sha256"])
        changed = copy.deepcopy(vector["package"])
        changed["kem_output"] = base64.b64encode(bytes([1]) * 32).decode()
        self.assertNotEqual(package_digest(changed), vector["package_sha256"])
        self.assertNotEqual(ciphertext_digest(changed), vector["ciphertext_sha256"])

    def test_decode_limits_are_bytes_not_only_encoded_length(self):
        exact = b"x" * contract.MAX_PAYLOAD_BYTES
        self.assertEqual(contract.decode_bytes(base64.b64encode(exact).decode(),
                                               "payload", len(exact)), exact)
        over = base64.b64encode(exact + b"x").decode()
        self.assert_code("invalid_envelope", lambda: contract.decode_bytes(over, "payload", len(exact)))
        self.assert_code("invalid_envelope", lambda: contract.decode_bytes("", "payload", 10))

    def test_raw_request_and_header_limits(self):
        self.assert_code("invalid_envelope", lambda: contract.parse_json(b" " * (contract.MAX_REQUEST_BYTES + 1)))
        header = base64.b64encode(b" " * (contract.MAX_HEADER_BYTES + 1)).decode()
        self.assert_code("invalid_envelope", lambda: contract.validate_header_bytes(header))

    def test_nested_and_duplicate_header_json(self):
        nested = b'{"a":' * 40 + b"0" + b"}" * 40
        self.assert_code("invalid_envelope", lambda: contract.parse_json(nested))
        repeated = b'{"protocol_version":"rim-poc-1","protocol_version":"rim-poc-1"}'
        self.assert_code("invalid_envelope", lambda: contract.validate_header_bytes(base64.b64encode(repeated).decode()))

    def test_lists_and_page_limits(self):
        for value in ("0", "101", "18446744073709551616", True, None):
            request = {"service_id": "S1", "after_seq": "0", "limit": value}
            for operation in ("pull_events", "pull_events_signed"):
                self.assert_code("invalid_envelope", lambda: contract.validate_request(operation, request))
        for value in ([], ["K"] * 101, [None]):
            request = {"service_id": "S1", "acceptance_ids": value}
            self.assert_code("invalid_envelope", lambda: contract.validate_request("report_read", request))

    def test_schema_scalar_patterns_match_boundary_rules(self):
        # 对独立标准源中的关键边界做交叉核对，不手写通用 Schema 验证器。
        pattern = SCHEMA["$defs"]["U64"]["pattern"]
        numbers = ["0", "1", "9007199254740993", str(contract.MAX_U64),
                   str(contract.MAX_U64 + 1), "99999999999999999999", "01", "1\n", "-1"]
        for number in numbers:
            with self.subTest(number=number):
                try:
                    contract.parse_u64(number)
                    valid = True
                except contract.ProtocolError:
                    valid = False
                self.assertEqual(bool(re.search(pattern, number)), valid)
        for name, valid, invalid in (("Identifier", "A1", "A1\n"),
                                     ("StateRef", "0" * 64, "0" * 63 + "G"),
                                     ("PayloadBytes", "AA==", "AB==")):
            pattern = SCHEMA["$defs"][name]["pattern"]
            self.assertIsNotNone(re.search(pattern, valid))
            self.assertIsNone(re.search(pattern, invalid))

    def test_terminal_reference_capability_is_only_in_signed_pull_schema(self):
        plain = SCHEMA["$defs"]["PullRequest"]
        signed = SCHEMA["$defs"]["SignedPullRequest"]
        self.assertNotIn("include_terminal_references", plain["properties"])
        self.assertFalse(plain["additionalProperties"])
        self.assertFalse(signed["additionalProperties"])
        self.assertEqual(signed["required"], plain["required"])
        self.assertEqual(signed["anyOf"], plain["anyOf"])
        capability = signed["properties"]["include_terminal_references"]
        self.assertEqual(capability["type"], "boolean")
        self.assertIs(capability["default"], False)
        self.assertEqual({key: value for key, value in signed["properties"].items()
                          if key != "include_terminal_references"}, plain["properties"])
        for operation, definition in (("pull_events", "PullRequest"), ("pull_events_signed", "SignedPullRequest")):
            request = OPENAPI["paths"]["/v1/" + operation]["post"]["requestBody"]
            self.assertEqual(request["content"]["application/json"]["schema"],
                             {"$ref": "../realtime/message.schema.json#/$defs/" + definition})

    def test_source_references_and_operation_coverage(self):
        expected = {"/v1/" + name for name in contract.OPERATIONS}
        self.assertEqual(set(OPENAPI["paths"]), expected)
        self.assertEqual(OPENAPI["openapi"], "3.1.1")
        self.assertEqual(SCHEMA["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(OPENAPI["security"], [{"SyntheticDeviceBearer": []}])
        for path, document in ((SCHEMA_PATH, SCHEMA), (OPENAPI_PATH, OPENAPI)):
            pending = [document]
            while pending:
                item = pending.pop()
                if isinstance(item, list):
                    pending.extend(item)
                elif isinstance(item, dict):
                    if "$ref" in item:
                        file_name, fragment = item["$ref"].split("#", 1)
                        target = path if not file_name else (path.parent / file_name).resolve()
                        node = json.loads(target.read_text())
                        for piece in fragment.lstrip("/").split("/"):
                            node = node[piece.replace("~1", "/").replace("~0", "~")]
                        self.assertIsInstance(node, dict)
                    pending.extend(item.values())

    def test_message_availability_schema_preserves_explicit_terminal_and_target_contract(self):
        definition = SCHEMA["$defs"]["MessageAvailabilityEvent"]
        expected = {"type", "target_event_seq", "target_event_id", "acceptance_id", "attempt_id", "availability"}
        self.assertEqual(set(definition["properties"]), expected)
        self.assertEqual(set(definition["required"]), expected)
        self.assertFalse(definition["additionalProperties"])
        self.assertEqual(definition["properties"]["type"], {"const": "message_availability"})
        self.assertEqual(definition["properties"]["availability"]["enum"], ["deleted", "expired"])
        self.assertEqual(definition["properties"]["target_event_seq"], {"$ref": "#/$defs/U64", "not": {"const": "0"}})
        for name in ("target_event_id", "acceptance_id", "attempt_id"):
            self.assertEqual(definition["properties"][name], {"$ref": "#/$defs/Identifier"})
        self.assertIn({"$ref": "#/$defs/MessageAvailabilityEvent"}, SCHEMA["$defs"]["Event"]["oneOf"])

    def test_validators_do_not_mutate_requests(self):
        original = VECTORS["vectors"][0]["value"]
        value = copy.deepcopy(original)
        returned = contract.validate_request("submit_message", value)
        self.assertIs(returned, value)
        self.assertEqual(value, original)


if __name__ == "__main__":
    unittest.main()
