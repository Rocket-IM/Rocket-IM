"""公开交换 83/84/85 受控退出，检查闸与原始材料一起持久化。"""

from .consistency_cases import assert_status, blocked, current_head, observe, send
from .exchange_cases import begin, branches, export, inspect, same_branch
from .fixture import check


BEFORE_COMMIT = (("before_save", 83), ("before_rename", 84))


def atomic_request_export_cancel(lab):
    same_branch(lab)
    path = lab.directory / "b1/state.enc"
    before = path.read_bytes()
    for point, code in BEFORE_COMMIT:
        begin(lab, failpoint=point, expected_exit=code)
        check(path.read_bytes() == before, "交换请求提交前退出改变了有效快照")
        check(inspect(lab)["active"] is None, "未持久请求提前变为活动交换")
    begin(lab, failpoint="after_save", expected_exit=85)
    check(inspect(lab)["active"] is not None, "请求保存后退出没有恢复活动交换")
    blocked(lab)
    request = begin(lab)["request"]
    source_path = lab.directory / "a2/state.enc"
    source_before = source_path.read_bytes()
    for point, code in BEFORE_COMMIT:
        export(lab, request, "exchange_same", failpoint=point, expected_exit=code)
        check(source_path.read_bytes() == source_before, "导出提交前退出留下半份记录")
        check(inspect(lab, "a2")["export_count"] == 0, "未提交导出占用了导出记录")
    export(lab, request, "exchange_same", failpoint="after_save", expected_exit=85)
    check(inspect(lab, "a2")["export_count"] == 1, "导出保存后退出丢掉原包")
    package = export(lab, request, "exchange_same")["package"]
    check(export(lab, request, "exchange_same")["package"] == package, "保存后原包重试发生变化")
    before_cancel = path.read_bytes()
    for point, code in BEFORE_COMMIT:
        lab.rust("b1", "consistency_exchange_cancel", failpoint=point, expected_exit=code)
        check(path.read_bytes() == before_cancel and inspect(lab)["active"] is not None,
              "取消提交前退出丢掉原活动请求")
        blocked(lab)
    lab.rust("b1", "consistency_exchange_cancel", failpoint="after_save", expected_exit=85)
    check(inspect(lab)["active"] is None, "取消保存后退出恢复出旧活动请求")
    blocked(lab)
    lab.restart()
    blocked(lab)
    observe(lab, current_head(lab))
    send(lab)


def atomic_import_fork(lab):
    branches(lab)
    request = begin(lab)["request"]
    package = export(lab, request, "exchange_right")["package"]
    path = lab.directory / "b1/state.enc"
    before = path.read_bytes()
    for point, code in BEFORE_COMMIT:
        lab.rust("b1", "consistency_exchange_import", package=package,
                 failpoint=point, expected_exit=code)
        check(path.read_bytes() == before and inspect(lab)["import_count"] == 0,
              "导入提交前退出留下部分证据或消耗了挑战")
        check(inspect(lab)["active"] is not None, "导入提交前退出丢掉活动交换")
        blocked(lab)
    lab.rust("b1", "consistency_exchange_import", package=package,
             failpoint="after_save", expected_exit=85)
    check(inspect(lab)["import_count"] == 1 and inspect(lab)["active"] is None,
          "有效冲突与交换完成状态没有一起保存")
    assert_status(lab, "fork_detected")
    blocked(lab)
    lab.restart()
    retry = lab.rust("b1", "consistency_exchange_import", package=package)
    check(retry["duplicate"] and retry["outcome"] == "fork_detected", "重启后原冲突包不幂等")
    begin(lab)
    retry = lab.rust("b1", "consistency_exchange_import", package=package)
    check(retry["duplicate"] and retry["consistency"]["checking"], "旧冲突包消耗了新的检查闸")
    blocked(lab)
