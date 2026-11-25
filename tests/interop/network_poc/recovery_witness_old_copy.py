"""首次锚登记前建立旧副本分支；两个分支各持有独立锚，不重置已有锚。"""

import hashlib
import shutil

from .fixture import check
from .first_trust_evidence import state
from .recovery_watermark_cases import checkpoint
from .recovery_witness_fixture import WitnessLab


def old_call(lab, operation, **fields):
    branch = lab.old_copy_lab
    branch.binary = lab.binary
    if lab.target in lab.witness_configs:
        branch.witness_configs[lab.target] = lab.witness_configs[lab.target]
    return branch.rust(lab.target, operation, **fields)


def old_view(lab):
    raw = lab.old_copy_lab.snapshot(lab.target).read_bytes()
    branch = lab.old_copy_lab
    return {"snapshot": {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
            "group": old_call(lab, "inspect"),
            "permission": old_call(lab, "permission_inspect"),
            "recovery": old_call(lab, "join_recovery", command={"kind": "inspect"}),
            "wire": old_call(lab, "wire_inspect"),
            "packages": old_call(lab, "key_package_inspect")["packages"],
            "anchors": branch.anchor_views()}


def create_joined_copy(lab):
    check(lab.target not in lab.configs, "旧分支必须在目标首次锚登记前建立")
    before = state(lab)
    branch = WitnessLab(lab.binary, lab.directory / "independent-old-copy",
                        lab.permission_verifier, lab.receipt_signer, lab.helper)
    branch.public[lab.target] = lab.public[lab.target]
    lab.old_copy_lab = branch
    lab.old_copy = branch.directory / lab.target
    shutil.copytree(lab.directory / lab.target, lab.old_copy)
    lab.deferred_initial_anchors.discard(lab.target)
    if lab.helper is not None:
        branch.enable(lab.target)
        lab.enable(lab.target)
        main = lab.materials[lab.target]["config"]
        old = branch.materials[lab.target]["config"]
        check(main["scope"]["store_id"] != old["scope"]["store_id"]
              and main["anchor_public_key"] != old["anchor_public_key"]
              and main["anchor_directory"] != old["anchor_directory"],
              "两个旧新副本错误共用同一锚")
    joined = old_call(lab, "permission_join", **lab.original)
    rooted = old_call(lab, "join_recovery", command={"kind": "root", **lab.original})
    view = old_view(lab)
    admission = view["permission"]["admission"]
    current = checkpoint(lab, lab.actor)
    lab.case_evidence["real_old_join"] = {"joined": joined, "rooted": rooted,
        "old_copy": view, "main_before": before, "main_after": state(lab),
        "main_anchors_after_initial_binding": lab.anchor_views(),
        "branch_scope": "clone only before first target anchor binding; independently bootstrap both"}
    check(not joined["duplicate"] and view["group"]["active"]
          and view["permission"]["checkpoint"] == current
          and str(view["group"]["epoch"]) == admission["joined_epoch"]
          and admission["history_policy"] == "from_join"
          and sum(package["consumed"] for package in view["packages"].values()) == 1,
          "旧副本未真实普通加入")
    check(state(lab) == before and lab.rust(lab.target, "inspect")["group_id"] is None
          and all(not package["consumed"] for package in lab.pool(lab.target)["packages"].values()),
          "旧分支加入改写了主目标")
