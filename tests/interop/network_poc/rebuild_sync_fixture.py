"""重建后继的真实 HTTP/Rust 联合装置；初始身份及锚信任仍为 synthetic_local。"""

import base64
import copy
import hashlib
import json
import secrets

from .anchor_fixture import private_json
from .fixture import NetworkLab, SERVICE, check
from .rebuild_fixture import RebuildLab


def page_value(page):
    return json.loads(base64.b64decode(page["page_bytes"]))


def statement(signed):
    return json.loads(base64.b64decode(signed["statement_bytes"]))


class RebuildSyncLab(RebuildLab):
    def __init__(self, *args):
        self.network_ready = False
        self.joined = False
        super().__init__(*args)
        self.registration = self.binding = self.link_result = None

    def start(self):
        # 父装置会在 G1 初始化尾部调用；必须等 G2 和新候选公开身份存在才启动 HTTP。
        if self.network_ready:
            NetworkLab.start(self)

    def initialize(self, **options):
        super().initialize()
        old_packet = self.rust("b1", "wire_send", logical_message_id="old_history", attempt_id="P1",
                               payload="synthetic-old-history")
        old_receipt = self.message_receipt(old_packet, "old_accepted")
        self.old_page = {"stream_id": "old_rebuild_stream", "next_after_seq": "1", "watermark": "1",
            "has_more": False, "events": [{"stream_id": "old_rebuild_stream", "event_seq": "1",
            "event_id": "old_event", "availability": "available", "event": {"type": "message",
            "acceptance_id": "old_accepted", "envelope": old_packet["envelope"],
            "acceptance_receipt": old_receipt}}]}
        NetworkLab.download(self, "a1", self.sign_test_page(self.old_page, device="a1"))
        self.rust("a1", "wire_process")
        check(self.rust("a1", "wire_inspect")["sync"]["processed_cursor"] == "1",
              "旧设备必须先实际解密并保存非零游标")
        self.unresolved(); self.offer(); self.approve()
        self.link_result = self.link()
        self.configure_successor()
        group = ("source", "source_twin", "source_peer")
        directory_devices = (*group, "successor", "a1")
        for alias in directory_devices:
            self.tokens.setdefault(alias, secrets.token_urlsafe(32))
        devices = [{**self.member(alias), "token": self.tokens[alias]} for alias in directory_devices]
        devices[3]["rebuild_trust"] = {"old_scope": self.plan["old_scope"],
                                        "anchor_public_key": self.plan["anchor_public_key"],
                                        "trust": self.plan["trust"]}
        checkpoint = copy.deepcopy(self.trust["checkpoint"])
        self.fixture = {"service_id": SERVICE, "controller_token": self.controller_token,
                        "devices": devices, "conversation": {
                            "conversation_id": "G2", "members": [self.identities[d] for d in group],
                            "authorization_version": checkpoint["authorization_version"],
                            "crypto_state_ref": checkpoint["crypto_state_ref"]},
                        "permission_checkpoint": checkpoint,
                        "relay_receipt_key": self.relay_receipt_key}
        self.fixture_path = self.directory / "rebuild-sync-fixture.json"
        private_json(self.fixture_path, self.fixture)
        self.network_ready = True
        self.start()
        self.evidence["fixture"] = "G2真实HTTP；新设备仅预置目录身份，群权限经真实Add/Welcome建立"

    def join_http(self, *, apply_welcome=True):
        check(not self.joined, "测试装置重复创建实际入群流程")
        self.rust("successor", "permission_device_join_anchor", checkpoint=self.trust["checkpoint"],
                  relay_receipt_key=self.relay_receipt_key)
        candidate = self.rust("source", "permission_prepare_device", change_id="rebuild_join",
                              member=self.member("successor"), key_package=self.public["successor"]["key_package"],
                              history_policy="from_join")
        accepted = self.http("source", "submit_permission_change", {"service_id": SERVICE,
            "conversation_id": "G2", "change": candidate["change"], "join": candidate["join"]})
        check(accepted["outcome"] == "accepted" and accepted.get("receipt"), "HTTP Add 缺少实际已接受签名")
        record = {"change": candidate["change"], "receipt": accepted["receipt"]}
        for alias in ("source", "source_twin", "source_peer"):
            self.rust(alias, "permission_recover", record=record)
        self.bundle = self.http("successor", "get_join_material", {"service_id": SERVICE,
            "conversation_id": "G2", "change_id": "rebuild_join"})
        check(self.bundle == {"record": record, "join": candidate["join"]}, "领取材料与HTTP原接受字节不同")
        if apply_welcome:
            self.rust("successor", "permission_join", **self.bundle)
            self.joined = True
        return self.bundle

    def registration_request(self, **options):
        result = self.rust("successor", "rebuild_stream_request", plan=self.plan, approval=self.approval,
                           anchor_request=self.link_result["anchor_request"],
                           anchor_response=self.link_result["anchor_response"], **options)
        if result is not None and options.get("expected_exit", 0) == 0:
            self.registration = result["registration"]
        return result

    def register_http(self, registration=None, *, device="successor", **options):
        result = self.http(device, "register_rebuild_stream", {"service_id": SERVICE,
                           "registration": registration or self.registration}, **options)
        if options.get("expected", 200) == 200:
            self.binding = result["binding"]
        return result

    def bind(self, binding=None, **options):
        return self.rust("successor", "rebuild_stream_bind", binding=binding or self.binding, **options)

    def ready(self):
        self.join_http(); self.registration_request(); self.register_http(); self.bind()

    def request_page(self, limit="3", **options):
        return self.rust("successor", "rebuild_stream_pull", limit=limit, **options)

    def http_page(self, request, *, device="successor", **options):
        return self.http(device, "pull_rebuild_events", {"service_id": SERVICE, "request": request}, **options)

    def next_page(self, limit="3"):
        return self.http_page(self.request_page(limit)["request"])

    def download(self, page, **options):
        return self.rust("successor", "rebuild_stream_download", **page, **options)

    def process_page(self, **options):
        return self.rust("successor", "wire_process", **options)

    def sign_statement(self, value):
        return self.relay_key("sign", statement=value,
                              expected_signature_key=self.relay_receipt_key)["receipt"]

    def signed_page(self, original, value):
        """用实验Service真钥签署恶意页，区分签名范围和消息原接受证明。"""
        raw = json.dumps(value, separators=(",", ":")).encode()
        claims = statement(original["receipt"])
        claims["page_sha256"] = hashlib.sha256(raw).hexdigest()
        return {"page_bytes": base64.b64encode(raw).decode(), "receipt": self.sign_statement(claims)}

    def publish(self, logical, *, device="source", payload=None):
        packet = self.rust(device, "wire_send", logical_message_id=logical, attempt_id="P1",
                           payload=payload or "synthetic-rebuild-sync-" + logical)
        accepted = self.http(device, "submit_message", {"envelope": packet["envelope"]})
        self.rust(device, "wire_accept", logical_message_id=logical, attempt_id="P1",
                  acceptance_receipt=accepted["acceptance_receipt"])
        return packet, accepted

    def sync(self, limit="3"):
        pages, results = [], []
        while True:
            check(len(pages) < 100, "测试同步超过100页，可能游标未前进")
            page = self.next_page(limit)
            value = page_value(page)
            self.download(page)
            results.append(self.process_page())
            pages.append(page)
            if not value["has_more"]:
                return pages, results

    def negative_baseline(self, name="negative", device="successor"):
        """仅隔离变异输入；同时恢复可信装置不是产品恢复能力。"""
        return {"device": device,
                "local": self.backup(name + "-local", self.directory / device),
                "authority": self.backup(name + "-authority", self.materials[device]["authority"])}

    def restore_negative_baseline(self, baseline):
        device = baseline["device"]
        self.restore(baseline["local"], self.directory / device)
        self.restore(baseline["authority"], self.materials[device]["authority"])
        self.evidence["negative_input_isolation"] = "完整可信fixture重置，仅隔离独立变异，不计生产双边回滚防护"
