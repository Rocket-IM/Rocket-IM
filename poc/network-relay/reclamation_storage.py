"""显式回收的独立高水位、有限证明和计划账本；不清除去重事实。"""

from contract import ProtocolError

VERSION = "rim-reclamation-storage-1"
MAX_COMPACT_ATTEMPTS = 10000
MAX_COMPACT_EVENTS = 60000
MAX_PLANS = 128
MAX_PLAN_BYTES = 256 * 1024
MAX_PLAN_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PROOF_BYTES = 16 * 1024 * 1024
SCHEMA = """
CREATE TABLE stream_watermarks (account TEXT, device TEXT, high_watermark INTEGER NOT NULL,
    floor INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(account,device));
CREATE TABLE reclamation_plans (plan_id TEXT PRIMARY KEY, selection TEXT NOT NULL,
    messages TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','ready','complete')));
CREATE TABLE reclamation_participants (plan_id TEXT, account TEXT, device TEXT,
    request TEXT, receipt TEXT, finished INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(plan_id,account,device));
CREATE TABLE reclamation_selection (acceptance_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL);
"""


def install(db, previous_schema):
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    marker = db.execute("SELECT value FROM meta WHERE key='reclamation_schema'").fetchone()
    if marker is not None:
        if marker["value"] != VERSION:
            raise ValueError("不支持此回收存储版本")
        for table in ("stream_watermarks", "reclamation_plans", "reclamation_participants", "reclamation_selection"):
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                raise ValueError("回收持久账本缺失，禁止重新推断")
        if db.execute("SELECT 1 FROM devices d LEFT JOIN stream_watermarks w ON w.account=d.account AND w.device=d.device "
                      "WHERE w.account IS NULL OR typeof(w.floor)!='integer' OR typeof(w.high_watermark)!='integer' "
                      "OR w.floor<0 OR w.high_watermark<w.floor").fetchone():
            raise ValueError("设备流高水位账本缺失或边界无效")
        # H是已提交的唯一分配依据；只核对现存事件不能越界，不用MAX(seq)修补坏账本。
        if db.execute("SELECT 1 FROM events e JOIN stream_watermarks w ON w.account=e.account AND w.device=e.device "
                      "WHERE e.seq>w.high_watermark").fetchone():
            raise ValueError("设备流高水位低于已存事件，拒绝反推修补")
        return
    if previous_schema in {"rim-poc-storage-7", "rim-poc-storage-8"}:
        raise ValueError("回收版本标记缺失，禁止重新生成高水位")
    if db.execute("SELECT 1 FROM events e WHERE NOT EXISTS (SELECT 1 FROM devices d WHERE d.account=e.account AND d.device=e.device)").fetchone():
        raise ValueError("旧事件不属于任何已登记设备，拒绝迁移")
    if db.execute("SELECT 1 FROM events WHERE typeof(seq)!='integer' OR seq<1").fetchone():
        raise ValueError("旧事件序号类型或范围无效，拒绝迁移")
    if db.execute("SELECT 1 FROM events GROUP BY account,device HAVING MIN(seq)!=1 OR COUNT(*)!=MAX(seq)").fetchone():
        raise ValueError("旧设备流存在缺槽，拒绝推断高水位")
    for statement in SCHEMA.strip().split(";"):
        if statement.strip():
            db.execute(statement)
    db.execute("ALTER TABLE attempts ADD COLUMN compacted INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE attempts ADD COLUMN payload_sha256 TEXT")
    db.execute("ALTER TABLE attempts ADD COLUMN payload_size INTEGER")
    db.execute("ALTER TABLE events ADD COLUMN compacted INTEGER NOT NULL DEFAULT 0")
    db.execute("INSERT INTO stream_watermarks(account,device,high_watermark) "
               "SELECT d.account,d.device,COALESCE(MAX(e.seq),0) FROM devices d "
               "LEFT JOIN events e ON e.account=d.account AND e.device=d.device GROUP BY d.account,d.device")
    db.execute("INSERT INTO meta VALUES ('reclamation_schema',?)", (VERSION,))


def watermarks(db, pair):
    row = db.execute("SELECT high_watermark,floor FROM stream_watermarks WHERE account=? AND device=?", pair).fetchone()
    if row is None:
        raise ProtocolError("state_conflict", "设备流高水位缺失，禁止反推", status=409)
    return row


def capacity(db, attempts, events):
    compact_attempts = db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=1").fetchone()[0]
    compact_events = db.execute("SELECT COUNT(*) FROM events WHERE compacted=1").fetchone()[0]
    if compact_attempts + attempts > MAX_COMPACT_ATTEMPTS or compact_events + events > MAX_COMPACT_EVENTS:
        raise ProtocolError("resource_exhausted", "回收证明预算已满，保留原数据", status=429)


def pending_selection(db, acceptance_id):
    return db.execute("SELECT 1 FROM reclamation_selection WHERE acceptance_id=?", (acceptance_id,)).fetchone() is not None


def advance_floor(db, pair):
    marks = watermarks(db, pair)
    floor = marks["floor"]
    for row in db.execute("SELECT seq,compacted FROM events WHERE account=? AND device=? AND seq>? ORDER BY seq", (*pair, floor)):
        if row["seq"] != floor + 1 or not row["compacted"]:
            break
        floor = row["seq"]
    db.execute("UPDATE stream_watermarks SET floor=? WHERE account=? AND device=?", (floor, *pair))


def retained_stats(db):
    return {"live_attempts": str(db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=0").fetchone()[0]),
            "compact_attempts": str(db.execute("SELECT COUNT(*) FROM attempts WHERE compacted=1").fetchone()[0]),
            "live_events": str(db.execute("SELECT COUNT(*) FROM events WHERE compacted=0").fetchone()[0]),
            "compact_events": str(db.execute("SELECT COUNT(*) FROM events WHERE compacted=1").fetchone()[0]),
            "reclamation_plans": str(db.execute("SELECT COUNT(*) FROM reclamation_plans").fetchone()[0])}
