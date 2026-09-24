// 单进程 SQLite 预约寄存器；文件与可信配置仍受同机测试控制器控制。
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { AnchorError, PROTOCOL, scope, scopeKey, hex, head, revision, publicKey, parseRequest,
  verifyRequest, requestDigest, signResponse, requireValue } from "./anchor_wire.mjs";
import { createRebuildTables, validateRebuildTables, findLink } from "./rebuild_state.mjs";

const MAX_SCOPES = 128;
function decode(value) { try { return JSON.parse(value); } catch { throw new AnchorError("anchor_corrupt"); } }

export class AnchorState {
  constructor(directory, allowCreate = false) {
    this.seed = hex(decode(fs.readFileSync(path.join(directory, "authority.json"), "utf8")).seed);
    this.publicKey = publicKey(this.seed);
    const file = path.join(directory, "anchor.sqlite");
    const exists = fs.existsSync(file);
    requireValue(exists || allowCreate, "anchor_missing");
    this.db = new DatabaseSync(file, { timeout: 1000, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false, allowExtension: false });
    fs.chmodSync(file, 0o600);
    this.db.exec("PRAGMA journal_mode = DELETE; PRAGMA synchronous = FULL; PRAGMA trusted_schema = OFF;");
    this.tx(() => {
      const tables = this.db.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name").all().map(r => r.name);
      if (!exists && allowCreate) {
        requireValue(tables.length === 0, "anchor_corrupt");
        this.db.exec(`CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), format INTEGER NOT NULL, public_key TEXT NOT NULL);
          CREATE TABLE registry (scope_key TEXT PRIMARY KEY NOT NULL, scope_json TEXT NOT NULL, client_key TEXT NOT NULL,
          head TEXT NOT NULL, revision TEXT NOT NULL, pending_json TEXT, last_json TEXT);`);
        this.db.prepare("INSERT INTO meta VALUES (1, 1, ?)").run(this.publicKey);
      } else requireValue(["meta,registry", "meta,rebuild_approvers,rebuild_links,registry"].includes(tables.join(",")), "anchor_corrupt");
      const meta = this.db.prepare("SELECT singleton, format, public_key FROM meta").all();
      requireValue(meta.length === 1 && meta[0].singleton === 1 && [1, 2].includes(meta[0].format) && meta[0].public_key === this.publicKey, "anchor_corrupt");
      const rows = this.db.prepare("SELECT scope_key,scope_json,client_key,head,revision,pending_json,last_json FROM registry LIMIT 129").all();
      requireValue(rows.length <= MAX_SCOPES, "anchor_capacity"); rows.forEach(row => this.validate(row));
      if (meta[0].format === 1) {
        requireValue(!exists || tables.join(",") === "meta,registry", "anchor_corrupt");
        createRebuildTables(this.db); this.db.exec("UPDATE meta SET format=2 WHERE singleton=1");
      } else requireValue(tables.join(",") === "meta,rebuild_approvers,rebuild_links,registry", "anchor_corrupt");
      validateRebuildTables(this);
    });
  }
  tx(body, mode = "IMMEDIATE", failpoint = null) {
    this.db.exec("BEGIN " + mode);
    try {
      const value = body();
      if (failpoint === "before_commit") process.exit(91);
      this.db.exec("COMMIT");
      if (failpoint === "after_commit") process.exit(92);
      return value;
    } catch (error) {
      if (this.db.isTransaction) this.db.exec("ROLLBACK");
      throw error;
    }
  }
  validate(row) {
    const value = { scope: scope(decode(row.scope_json)), clientKey: hex(row.client_key), head: head(row.head),
      revision: revision(row.revision), pending: row.pending_json === null ? null : decode(row.pending_json),
      last: row.last_json === null ? null : decode(row.last_json) };
    requireValue(row.scope_key === scopeKey(value.scope), "anchor_corrupt");
    for (const item of [value.pending, value.last]) {
      if (item === null) continue;
      requireValue(typeof item === "object" && Object.keys(item).sort().join(",") === "base,reservedRevision,target,txn", "anchor_corrupt");
      hex(item.txn); head(item.base); head(item.target); revision(item.reservedRevision);
    }
    if (value.pending) requireValue(value.pending.base === value.head && value.pending.target === "absent"
      && BigInt(value.pending.reservedRevision) === value.revision && value.revision > 0n, "anchor_corrupt");
    if (value.last) requireValue(value.last.target !== "absent" && value.last.target === value.head
      && BigInt(value.last.reservedRevision) > 0n && BigInt(value.last.reservedRevision) < value.revision
      && value.pending?.txn !== value.last.txn, "anchor_corrupt");
    return value;
  }
  row(value) {
    const row = this.db.prepare("SELECT scope_key,scope_json,client_key,head,revision,pending_json,last_json FROM registry WHERE scope_key=?").get(scopeKey(value));
    requireValue(row, "anchor_scope"); return this.validate(row);
  }
  enroll(value) {
    const fixed = scope(value.scope); hex(value.clientPublicKey); head(value.head);
    const pin = value.rebuildApproverPublicKey;
    if (pin !== undefined) requireValue(hex(pin) !== value.clientPublicKey && pin !== fixed.identity_key && pin !== this.publicKey, "anchor_rebuild_denied");
    return this.tx(() => {
      requireValue(this.db.prepare("SELECT COUNT(*) AS count FROM registry").get().count < MAX_SCOPES, "anchor_capacity");
      requireValue(!this.db.prepare("SELECT scope_key FROM registry WHERE scope_key=?").get(scopeKey(fixed)), "anchor_exists");
      this.db.prepare("INSERT INTO registry VALUES (?, ?, ?, ?, '0', NULL, NULL)").run(scopeKey(fixed), JSON.stringify(fixed), value.clientPublicKey, value.head);
      if (pin !== undefined) this.db.prepare("INSERT INTO rebuild_approvers VALUES (?, ?)").run(scopeKey(fixed), pin);
      return { scope: fixed, anchorPublicKey: this.publicKey, revision: "0", head: value.head };
    });
  }
  request(signed, failpoint = null) {
    const untrusted = parseRequest(signed);
    const response = this.tx(() => {
      const current = this.row(untrusted.scope);
      const request = verifyRequest(signed, current.clientKey);
      requireValue(JSON.stringify(scope(request.scope)) === JSON.stringify(current.scope), "anchor_scope");
      const expected = revision(request.expected_revision);
      const closure = findLink(this, current.scope) ? "rebuilt" : null;
      let status = "conflict"; let changed = false;
      if (closure) { if (request.action === "inspect") status = "inspected"; }
      else if (request.action === "inspect") status = "inspected";
      else if (request.action === "reserve") {
        if (current.pending) {
          if (current.pending.txn === request.txn && current.pending.base === request.head
            && BigInt(current.pending.reservedRevision) - 1n === expected) status = "reserved_duplicate";
        } else if (current.head === request.head && current.revision === expected && current.last?.txn !== request.txn) {
          requireValue(current.revision <= 18446744073709551613n, "anchor_capacity");
          current.revision += 1n;
          current.pending = { txn: request.txn, base: request.head, target: "absent", reservedRevision: current.revision.toString() };
          status = "reserved"; changed = true;
        }
      } else {
        const matches = item => item && item.txn === request.txn && item.base === request.head && BigInt(item.reservedRevision) === expected;
        if (matches(current.last) && current.last.target === request.target) status = "finished_duplicate";
        else if (matches(current.pending)) {
          requireValue(current.revision < 18446744073709551615n, "anchor_capacity");
          current.last = { ...current.pending, target: request.target };
          current.pending = null; current.head = request.target; current.revision += 1n;
          status = "finished"; changed = true;
        }
      }
      if (changed) this.db.prepare("UPDATE registry SET head=?,revision=?,pending_json=?,last_json=? WHERE scope_key=?")
        .run(current.head, current.revision.toString(), current.pending && JSON.stringify(current.pending), current.last && JSON.stringify(current.last), scopeKey(current.scope));
      return { protocol_version: PROTOCOL, scope: current.scope, challenge: request.challenge, request_sha256: requestDigest(signed),
        action: request.action, status, head: current.head, active_txn: current.pending?.txn ?? null, revision: current.revision.toString(),
        ...(closure ? { closure } : {}) };
    }, "IMMEDIATE", failpoint);
    return { ok: true, response: signResponse(response, this.seed) };
  }
  inspect(value) {
    return this.tx(() => { const current = this.row(value); const link = findLink(this, value);
      const pin = this.db.prepare("SELECT public_key FROM rebuild_approvers WHERE scope_key=?").get(scopeKey(value));
      return { scope: current.scope, head: current.head, revision: current.revision.toString(), pending: current.pending, last: current.last,
        ...(link ? { closure: "rebuilt", successorScopeKey: link.successor_scope_key } : {}),
        ...(pin ? { rebuildApproverPublicKey: pin.public_key } : {}) }; }, "DEFERRED");
  }
  close() { this.db.close(); }
}
