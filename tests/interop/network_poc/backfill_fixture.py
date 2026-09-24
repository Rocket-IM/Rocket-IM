"""使用已归档的真实旧Relay建库，再启动当前实现；不伪造旧终态。"""

from contextlib import closing
from pathlib import Path
import sqlite3

from .deletion_observer import relay_records
from .fixture import check

ROOT = Path(__file__).resolve().parents[3]
LEGACY_ROOT = ROOT / 'dist/network-relay/m11-lifecycle/baseline'
INCREMENTAL_ROOT = ROOT / 'dist/network-relay/m11-backfill/baseline'
LEGACY_RELAY = LEGACY_ROOT / 'tests/interop/network_poc/expiration_relay.py'
INCREMENTAL_RELAY = INCREMENTAL_ROOT / 'tests/interop/network_poc/expiration_relay.py'
CURRENT_RELAY = ROOT / 'tests/interop/network_poc/expiration_relay.py'
VERSION = 'rim-lifecycle-backfill-1'


def ledger(lab):
    uri = (lab.directory / 'relay.sqlite').resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        try:
            metadata = dict(db.execute("SELECT key,value FROM meta WHERE key IN ('schema','lifecycle_backfill_version')"))
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE name='lifecycle_backfill' AND type='table'").fetchone()
            rows = [dict(row) for row in db.execute('SELECT * FROM lifecycle_backfill ORDER BY account,device,target_seq')] if exists else []
            for row in rows:
                row['target_seq'] = str(row['target_seq'])
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {'schema': metadata['schema'], 'version': metadata.get('lifecycle_backfill_version'), 'rows': rows}


def upgrade(lab):
    before, messages = ledger(lab), relay_records(lab)
    check(before['schema'] == 'rim-poc-storage-5' and before['version'] is None,
          '升级前必须是真实旧版本数据库')
    old_pid = lab.process.pid
    lab.stop()
    lab.relay_entrypoint = CURRENT_RELAY
    lab.start()
    after = ledger(lab)
    check(after['schema'] == 'rim-poc-storage-6' and after['version'] == VERSION
          and all(row['status'] == 'pending' for row in after['rows'])
          and relay_records(lab) == messages, '结构升级改变消息事实或提前发送通知')
    evidence = {'before': before, 'after': after, 'old_pid': old_pid, 'new_pid': lab.process.pid}
    lab.case_evidence['upgrade'] = evidence
    return evidence


def backfill(lab, **options):
    return lab.control('backfill_lifecycle', version=VERSION, **options)
