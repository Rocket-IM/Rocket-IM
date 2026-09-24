"""Node桌面与选定移动运行端的限定配对；不改变历史五端75项矩阵。"""
from .cases import NEGATIVES, route
from .expectations import Case, CaseFailure, require

ENDPOINTS = ["node-macos", "swift-ios"]


def run_cases(client, peers=None):
    peers = ["swift-ios"] if peers is None else peers
    require(peers in (["swift-ios"], ["kotlin-android", "flutter-ios", "flutter-android"]), "node_peer_group")
    require(set(client.states) == {"node-macos", *peers}, "node_peer_endpoint_set")
    jobs = []
    for mobile in peers:
        for target, peer in (("node-macos", mobile), (mobile, "node-macos")):
            jobs.append((f"route.{target}_to_{peer}", route, (target, peer)))
            for name, function, variant in NEGATIVES:
                args = (target, peer) if variant is None else (target, peer, variant)
                # Node的每类拒绝都要分别使用三个对端的真实材料，不能用重复ID掩盖未测配对。
                suffix = "" if len(peers) == 1 else ".with_" + peer
                jobs.append((f"error.{target}{suffix}.{name}", function, args))
    require(len(jobs) == 24 * len(peers) and len({job[0] for job in jobs}) == len(jobs), "node_pair_case_count")
    results = []
    for case_id, function, args in jobs:
        case = Case(client, case_id)
        case.details["mode"] = "node_swift_pair_only" if len(peers) == 1 else "node_mobile_pairs_only"
        case.details["roles"] = dict(zip(
            ("creator", "joiner") if function is route else ("target", "material_source"), args[:2]))
        result = {"case_id": case_id, "status": "PASS", "details": case.details}
        try:
            function(case, *args)
        except CaseFailure as error:
            result.update(status="FAIL", failure=error.details)
        except Exception as error:
            result.update(status="FAIL", failure={"kind": "harness_exception", "exception_type": type(error).__name__})
        if case.cleanup():
            result["status"] = "FAIL"
            result.setdefault("failure", {"kind": "cleanup_failed"})
        results.append(result)
        client.on_case(result)
    return results
