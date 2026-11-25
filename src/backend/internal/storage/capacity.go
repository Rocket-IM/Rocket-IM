package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"strconv"
	"time"
)

func capacityBudget(name, unit string, used, limit int64) m.CapacityBudget {
	u, l, r := strconv.FormatInt(used, 10), strconv.FormatInt(limit, 10), strconv.FormatInt(max(0, limit-used), 10)
	return m.CapacityBudget{Enforcement: "hard_limit", Category: name, Unit: unit, State: "measured", Used: &u, Limit: l, HardRemaining: &r}
}
func capacityUnknown(name string, limit int64, reason string) m.CapacityBudget {
	return m.CapacityBudget{Enforcement: "hard_limit", Category: name, Unit: "bytes", State: "unavailable", Limit: strconv.FormatInt(limit, 10), Reason: &reason}
}
func capacityOperation(name, state string, blockers ...string) m.CapacityOperation {
	if blockers == nil {
		blockers = []string{}
	}
	if len(blockers) > 0 {
		state = "blocked"
	}
	return m.CapacityOperation{Operation: name, State: state, Blockers: blockers}
}

// CapacityDevice在同一个受控读事务内认证和计量；不接受宿主提供的设备索引。
func (s *Store) CapacityDevice(ctx context.Context, token string) (m.Capacity, error) {
	var out m.Capacity
	tx, e := s.beginRead(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	index, deadline, e := s.authenticateDevice(ctx, tx, token)
	if e != nil {
		return out, e
	}
	own, e := s.identity(ctx, tx, index)
	if e != nil {
		return out, e
	}
	out, e = s.capacityBase(ctx, tx)
	if e != nil {
		return m.Capacity{}, e
	}
	// 设备观察不得通过全局余量反推出业务主体账本；只给本设备已知控制数量。
	out.Reserve.Resources = []m.CapacityReservedResource{}
	if out.Schema == "6" {
		var controls int64
		e = tx.QueryRow(ctx, `SELECT count(*) FROM alpha_mailbox m JOIN alpha_devices d USING(device_index) WHERE d.device_index=$1 AND m.sequence>d.processed AND m.sequence < COALESCE((SELECT min(x.sequence) FROM alpha_mailbox x WHERE x.device_index=$1 AND x.sequence>d.processed AND x.event->>'kind' NOT IN ('delivered','unavailable')),d.tail+1)`, index).Scan(&controls)
		if e != nil {
			return m.Capacity{}, e
		}
		out.Reserve.Work = []m.CapacityReservedWork{{Kind: "known_control_report", Count: strconv.FormatInt(controls, 10)}}
	}
	out.Scope.Access = "device"
	out.Scope.Account = &own.Scope.Account
	out.Scope.Device = &own.Scope.Device
	var tail, processed, messages, control int64
	if e = tx.QueryRow(ctx, s.queries["mailbox_state"], index).Scan(&tail, &processed); e != nil {
		return m.Capacity{}, e
	}
	if e = tx.QueryRow(ctx, s.queries["capacity_backlog"], index, processed).Scan(&messages, &control); e != nil {
		return m.Capacity{}, e
	}
	out.Cursors = &m.CapacityCursors{Tail: strconv.FormatInt(tail, 10), Processed: strconv.FormatInt(processed, 10), PendingMessages: strconv.FormatInt(messages, 10), PendingControl: strconv.FormatInt(control, 10)}
	out.Operations = append(out.Operations, capacityOperation("download", "requires_input"), capacityOperation("process", "requires_input"), capacityOperation("report", "requires_input"))
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return m.Capacity{}, m.Fail("credential_expired")
	}
	if e = tx.Commit(ctx); e != nil {
		return m.Capacity{}, e
	}
	return out, nil
}

// CapacityBusiness仅允许配置中显式capacity_read主体读取全局计数，不返回其他主体原件。
func (s *Store) CapacityBusiness(ctx context.Context, token string) (m.Capacity, error) {
	var out m.Capacity
	tx, e := s.beginRead(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	p, ok := s.Config.AuthenticateBusiness(token, time.Now())
	if !ok {
		return out, m.Fail("unauthorized")
	}
	if !p.CapacityRead {
		return out, m.Fail("forbidden")
	}
	out, e = s.capacityBase(ctx, tx)
	if e != nil {
		return m.Capacity{}, e
	}
	out.Scope.Access = "service"
	out.Scope.Principal = &p.ID
	count, e := s.businessUsage(ctx, tx)
	if e != nil {
		return m.Capacity{}, e
	}
	rounds, size, e := s.recoveryUsage(ctx, tx)
	if e != nil {
		return m.Capacity{}, e
	}
	out.Budgets = append(out.Budgets, capacityBudget("business_requests", "items", count, businessRequestLimit), capacityBudget("recovery_rounds", "items", rounds, recoveryRoundLimit), capacityBudget("recovery_json_bytes", "bytes", size, recoveryJSONLimit))
	out.Budgets[len(out.Budgets)-1].Enforcement = "precheck"
	round, e := s.recoveryRound(ctx, tx, nil)
	if e != nil {
		return m.Capacity{}, e
	}
	roundBytes := 0
	if round != nil {
		raw, err := json.Marshal(round)
		if err != nil {
			return m.Capacity{}, err
		}
		roundBytes = len(raw)
	}
	out.Budgets = append(out.Budgets, capacityBudget("latest_round_bytes", "bytes", int64(roundBytes), m.MaxFrame-2048))
	if e = s.capacityMaintenance(ctx, tx, &out); e != nil {
		return m.Capacity{}, e
	}
	for _, op := range []string{"renew_credential", "revoke_credential"} {
		reasons := []string{}
		if count >= businessRequestLimit {
			reasons = append(reasons, "request_limit")
		}
		out.Operations = append(out.Operations, capacityOperation(op, "requires_input", reasons...))
	}
	reasons := []string{}
	if rounds >= recoveryRoundLimit || size > recoveryJSONLimit {
		reasons = append(reasons, "recovery_limit")
	}
	out.Operations = append(out.Operations, capacityOperation("new_recovery", "requires_input", reasons...))
	if _, ok = s.Config.BusinessPrincipal(p.ID, time.Now()); !ok {
		return m.Capacity{}, m.Fail("unauthorized")
	}
	if e = tx.Commit(ctx); e != nil {
		return m.Capacity{}, e
	}
	return out, nil
}
func (s *Store) capacityBase(ctx context.Context, tx pgx.Tx) (m.Capacity, error) {
	out := m.Capacity{Version: "service-capacity-alpha2", Owner: "service", Consistency: "single_pg_read", Scope: m.CapacityScope{Service: s.Config.Service, Conversation: s.Config.Conversation}, Reserve: m.CapacityReserve{State: "not_implemented"}, Physical: m.CapacityUnavailable{State: "unavailable"}, Remote: m.CapacityUnavailable{State: "unavailable"}}
	id, e := randomCheckpoint()
	if e != nil {
		return out, e
	}
	out.ObservationID = id
	var count, version int
	if e = tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return out, e
	}
	if count != 1 || (version != 4 && version != 5 && version != 6) {
		return out, m.Fail("schema_version_unsupported")
	}
	out.Schema = strconv.Itoa(version)
	var accepted int64
	if e = tx.QueryRow(ctx, s.queries["capacity_accepted"]).Scan(&accepted); e != nil {
		return out, e
	}
	out.Budgets = []m.CapacityBudget{capacityBudget("accepted", "items", accepted, messageLimit)}
	reasons := []string{}
	if accepted >= messageLimit {
		reasons = append(reasons, "message_limit")
	}
	round, e := s.recoveryRound(ctx, tx, nil)
	if e != nil {
		return out, e
	}
	out.Recovery = "none"
	if round != nil {
		out.Recovery = round.Status
		var current string
		if e = tx.QueryRow(ctx, s.queries["crypto_context"]).Scan(&current); e != nil {
			return out, e
		}
		if contextFrozen(current, round) {
			reasons = append(reasons, "context_not_accepted")
		}
	}
	out.Operations = []m.CapacityOperation{capacityOperation("new_send", "requires_input", reasons...), capacityOperation("retry_send", "requires_input")}
	if e = s.capacityReservation(ctx, tx, &out); e != nil {
		return out, e
	}
	return out, nil
}
func (s *Store) capacityMaintenance(ctx context.Context, tx pgx.Tx, out *m.Capacity) error {
	size, e := snapshotRowBytes(ctx, tx)
	if e != nil {
		return e
	}
	out.Budgets = append(out.Budgets, capacityBudget("reconciliation_row_bytes", "bytes", size, evidenceLimit), capacityBudget("export_row_bytes", "bytes", size, backupRowsLimit))
	if !s.evidenced {
		out.Budgets[len(out.Budgets)-2].Enforcement = "not_applied"
	}
	reasons := []string{"maintenance_seal_required"}
	out.Budgets[len(out.Budgets)-1].Enforcement = "precheck"
	if s.maintenance != nil && s.maintenance.state.Evidence != nil {
		out.Budgets[len(out.Budgets)-1].Enforcement = "not_applied"
	}
	if size > backupRowsLimit && (s.maintenance == nil || s.maintenance.state.Evidence == nil) {
		reasons = append(reasons, "export_row_limit")
	}
	if size > evidenceLimit {
		out.Budgets = append(out.Budgets, capacityUnknown("export_file_bytes", backupLimit, "reconciliation_size_limit"))
		reasons = append(reasons, "reconciliation_size_limit")
	} else if s.maintenance == nil {
		out.Budgets = append(out.Budgets, capacityUnknown("export_file_bytes", backupLimit, "maintenance_not_enrolled"))
		reasons = append(reasons, "maintenance_not_enrolled")
	} else {
		data, err := evidenceSnapshot(ctx, tx)
		if err != nil {
			return err
		}
		// 当前完整状态的精确编码大小，不伪称运行中的实例已经封存或产生备份文件。
		raw, err := json.Marshal(makeServiceBackup(data, s.maintenance.state))
		if err != nil {
			return err
		}
		out.Budgets = append(out.Budgets, capacityBudget("export_file_bytes", "bytes", int64(len(raw)), backupLimit))
		if len(raw) > backupLimit {
			reasons = append(reasons, "export_file_limit")
		}
	}
	out.Operations = append(out.Operations, capacityOperation("export", "not_reserved", reasons...), capacityOperation("import", "requires_input"))
	return nil
}
