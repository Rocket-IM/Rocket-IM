#!/usr/bin/env python3
"""仅验收用：真实 t_check 之后阻塞提交，区分到期取样与 fsync 完成。"""
import argparse
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"poc/network-relay"));sys.path.insert(0,str(ROOT/"tests/interop"))
from network_poc.key_package_relay import main as original
import key_package_commit


def main():
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument("--recovery-check-directory",required=True)
    args,remaining=parser.parse_known_args();directory=Path(args.recovery_check_directory)
    checked=key_package_commit.before_commit
    def before_commit(value):
        checked(value)
        marker=directory/"after-check-until"
        if marker.is_file() and isinstance(value,key_package_commit.TimedResult):
            deadline=float(marker.read_text());marker.unlink()
            (directory/"checked-at").write_text(str(time.time()))
            while time.time()<deadline:time.sleep(.01)
            (directory/"released-at").write_text(str(time.time()))
    key_package_commit.before_commit=before_commit
    sys.argv=[sys.argv[0],*remaining];original()


if __name__=="__main__":main()
