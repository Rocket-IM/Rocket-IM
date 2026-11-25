"""固定双端容量观察器：公开SDK驱动，PG只读取证，计时包含控制器采样开销。"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import json
import math
import secrets
import subprocess
import time
from service_reconciliation_harness import ServiceReconciliationLab
from service_backup_harness import ServiceBackupLab, digest
from harness import require, wait, all_hashes


def summary(values):
    ordered = sorted(values)
    if not ordered:
        return {'n': 0}
    return {'n': len(ordered), 'p50_ms': ordered[math.ceil(len(ordered)*.50)-1],
            'p95_ms': ordered[math.ceil(len(ordered)*.95)-1], 'max_ms': ordered[-1]}


class CapacityLab(ServiceReconciliationLab):
    def __init__(self, *args):
        self.samples = []
        self.originals = {}
        self.clock_start = time.monotonic()
        self.credential_ttl = 4
        super().__init__(*args)

    def build(self, proxy=True):
        super().build(proxy)
        self.report['measurement_contract'] = {
            'clock': 'Python time.monotonic_ns; milliseconds; host round trips included',
            'text_bytes': 256, 'warmup_messages': 2, 'batch_messages': 2,
            'concurrency': 'one public SDK send per device, two independent Node processes',
            'poll_sleep_ms': 50, 'poll_resolution': 'actual intervals saved per sample, not internal timestamps',
            'send_deadline_seconds': 45, 'credential_ttl_seconds': self.credential_ttl,
            'slo': None, 'quantile': 'nearest rank, no interpolation',
            'acceptance': 'first read-only PG observation after actual Service commit',
            'processed': 'receiver public networkState.processed crosses original mailbox sequence',
            'reported': 'receiver public networkState.reported crosses original mailbox sequence',
            'local': 'public SDK command response after local persistence; includes IPC',
            'environment': 'isolated local PG/TLS, synthetic identity and dedicated keychains',
        }
        self.report['installed_trees'] = [
            {'directory': str(w.directory), 'files': all_hashes(w.directory/'node_modules/@rocket-im/desktop-dev')}
            for w in self.workers]
        for i, worker in enumerate(self.workers):
            self.instrument(worker, i)
        self.save()

    def instrument(self, worker, index):
        call = worker.call
        last_state = [None]
        def observed(op, expected=None, **fields):
            start = time.monotonic_ns()
            record = {'device': index, 'op': op, 'case': getattr(self, 'active_case', None)}
            try:
                result = call(op, expected=expected, **fields)
                record['result'] = expected or 'ok'
                if op == 'network':
                    state = (result['connection'], (result.get('error') or {}).get('code'))
                    if state != last_state[0]:
                        self.report.setdefault('observed_network_transitions', []).append({
                            'device': index, 'connection': state[0], 'error': state[1],
                            'case': getattr(self, 'active_case', None)})
                        last_state[0] = state
                return result
            except Exception as error:
                record['result'] = 'failed'; record['error'] = str(error)
                raise
            finally:
                if expected or record.get('result') == 'failed' or op in ('send','concurrentSend','autoConnect','concurrentConnect','disconnect','close','closeKeep','logoutKeep','cancel','cancelInFlight'):
                    record['elapsed_ms'] = (time.monotonic_ns()-start)/1e6
                    self.report.setdefault('public_command_results', []).append(record)
        worker.call = observed

    def restore(self, index):
        worker = super().restore(index); self.instrument(worker,index); return worker

    def restart_worker(self, index, kill=False):
        worker = super().restart_worker(index,kill); self.instrument(worker,index); self.track(); return worker

    def case(self, name, operation):
        self.active_case = name
        try:
            return super().case(name,operation)
        finally:
            self.active_case = None

    def maintenance(self, operation, *args, **kwargs):
        start = time.monotonic_ns()
        try:
            return super().maintenance(operation, *args, **kwargs)
        finally:
            self.report.setdefault('maintenance_timings', []).append({
                'operation': operation, 'expected_error': kwargs.get('expected'),
                'case': getattr(self, 'active_case', None),
                'elapsed_ms': (time.monotonic_ns()-start)/1e6})

    def controlled_restore(self, label, **kwargs):
        return ServiceBackupLab.cycle(self, label, **kwargs)

    def aligned(self):
        def settled():
            observed = self.observe()
            tails = [sum(e['device_index'] == i for e in observed['events']) for i in range(2)]
            states = [w.call('network') for w in self.workers]
            return all(int(s['downloaded']) == int(s['processed']) == int(s['reported']) == tails[i]
                       for i,s in enumerate(states)) and all(m['delivered'] or m['context_retired'] for m in observed['messages'])
        return wait(settled, 'both SDK cursors reach actual Service tails and all messages delivered')

    def send(self, index, id):
        text = ('CAPACITY_PRIVATE_'+secrets.token_hex(32)).ljust(getattr(self, 'payload_bytes', 256), 'x')
        self.texts.append(text)
        start = time.monotonic_ns()
        row = {'message_id': id, 'request_id': 'req-'+id, 'sender': index,
               'text_bytes': len(text.encode()), 'start_ns': start, 'outcome': 'started'}
        self.samples.append(row)
        try:
            result = self.workers[index].call('send', requestId='req-'+id, messageId=id, text=text)
        except Exception as error:
            row.update(outcome='command_failed', error=str(error))
            raise
        finally:
            row['local_ms'] = (time.monotonic_ns()-start)/1e6
        row['outcome'] = 'local_saved'
        row['ciphertext_sha256'] = hashlib.sha256(bytes.fromhex(result['value']['envelope']['ciphertext'])).hexdigest()
        self.originals[id] = (index, text, result)
        return text, result

    def observe(self):
        query = f"""BEGIN READ ONLY;
        SELECT json_build_object('messages',COALESCE((SELECT json_agg(json_build_object(
          'message_id',message_id,'accepted',accepted,'delivered',delivered,'context_retired',context_retired)) FROM {self.schema}.alpha_messages),'[]'),
          'events',COALESCE((SELECT json_agg(json_build_object('device_index',device_index,
          'sequence',sequence,'event',event)) FROM {self.schema}.alpha_mailbox),'[]'));
        COMMIT;"""
        rows = [json.loads(line) for line in self.sql(query).splitlines() if line.startswith('{')]
        require(len(rows) == 1, 'read-only observation complete')
        return rows[0]

    def drain(self, ids, phase, timeout=45):
        selected = [s for s in self.samples if s['message_id'] in ids]
        previous = {s['message_id']: s['start_ns'] for s in selected}
        deadline = time.monotonic()+timeout
        try:
            while time.monotonic() < deadline:
                observed = self.observe()
                states = [w.call('network') for w in self.workers]
                now = time.monotonic_ns()
                facts = {m['message_id']: m for m in observed['messages']}
                events = {(e['device_index'], e['event']['acceptance']['message_id']): e['sequence']
                          for e in observed['events'] if e['event']['kind'] == 'message'}
                for s in selected:
                    id = s['message_id']; receiver = 1-s['sender']; fact = facts.get(id)
                    s['phase'] = phase
                    seq = events.get((receiver, id))
                    flags = {'accepted': fact is not None,
                             'processed': seq is not None and int(states[receiver]['processed']) >= seq,
                             'reported': seq is not None and int(states[receiver]['reported']) >= seq,
                             'service_delivered': fact is not None and fact['delivered']}
                    for key, seen in flags.items():
                        if seen and key+'_ms' not in s:
                            s[key+'_ms'] = (now-s['start_ns'])/1e6
                            s[key+'_lower_ms'] = max(0, (previous[id]-s['start_ns'])/1e6)
                    s['max_observation_interval_ms'] = max(s.get('max_observation_interval_ms', 0), (now-previous[id])/1e6)
                    previous[id] = now
                    if all(flags.values()):
                        s['outcome'] = 'accepted_processed_reported'
                if all(s['outcome'] == 'accepted_processed_reported' for s in selected):
                    return
                time.sleep(.05)
            for s in selected:
                if s['outcome'] != 'accepted_processed_reported':
                    s.update(outcome='observation_timeout', deadline_seconds=timeout)
            raise AssertionError('capacity drain deadline '+phase)
        finally:
            self.save_samples()

    def save_samples(self):
        (self.run/'latency-samples.json').write_text(json.dumps(self.samples, indent=2))
        phases = sorted({s.get('phase', 'unobserved') for s in self.samples})
        self.report['latency_summary'] = {
            phase: {metric: summary([s[metric] for s in self.samples if s.get('phase', 'unobserved') == phase and metric in s])
                    for metric in ('local_ms', 'accepted_ms', 'processed_ms', 'reported_ms', 'service_delivered_ms')}
            for phase in phases}
        self.report['sample_outcomes'] = {status: sum(s['outcome'] == status for s in self.samples)
                                          for status in {s['outcome'] for s in self.samples}}
        self.save()

    def fill(self, target, phase):
        count = len(self.database_snapshot()['alpha_messages'])
        require(count <= target <= 256 and (target-count) % 2 == 0, 'bounded bilateral fill')
        with ThreadPoolExecutor(max_workers=2) as pool:
            while count < target:
                ids = ['load-'+str(count+i+1) for i in range(2)]
                calls = [pool.submit(self.send, i, id) for i, id in enumerate(ids)]
                for call in calls:
                    call.result()
                self.drain(ids, phase)
                count += 2
                if count % 16 == 0:
                    print(json.dumps({'stage': phase, 'accepted': count, 'run': self.run.name}), flush=True)
        self.aligned()
        self.checkpoint(phase)

    def checkpoint(self, label):
        data = self.database_snapshot(); networks = [w.call('network') for w in self.workers]
        messages = sorted(data['alpha_messages'], key=lambda m: m['accepted'])
        require([m['accepted'] for m in messages] == list(range(1, len(messages)+1)), 'contiguous accepted sequence')
        for index in range(2):
            events = sorted([e for e in data['alpha_mailbox'] if e['device_index'] == index], key=lambda e: e['sequence'])
            require([e['sequence'] for e in events] == list(range(1, len(events)+1)), 'contiguous device event sequence')
            n = networks[index]
            require(int(n['reported']) <= int(n['processed']) <= int(n['downloaded']) <= len(events), 'cursor ordering')
        for m in messages:
            if m['message_id'] in self.originals:
                _, _, sent = self.originals[m['message_id']]
                require(m['request_id'] == 'req-'+m['message_id'] and m['envelope'] == sent['value']['envelope'], 'all original accepted ciphertexts exact')
        pids = [self.service.pid, self.business_process.pid]+[w.pid for w in self.workers]
        rss = subprocess.check_output(['/bin/ps','-o','pid=,rss=,pcpu=','-p',','.join(map(str,pids))], text=True)
        size = self.sql(f"BEGIN READ ONLY; SELECT sum(pg_total_relation_size(quote_ident(schemaname)||'.'||quote_ident(tablename))) FROM pg_tables WHERE schemaname='{self.schema}'; COMMIT;")
        row = {'label': label, 'elapsed_seconds': time.monotonic()-self.clock_start,
               'tables': {t: {'count': len(rows), 'sha256': digest(rows)} for t,rows in data.items()},
               'network': networks, 'service_rows_bytes': len(json.dumps(data).encode()),
               'pg_relation_bytes': int(next(l for l in size.splitlines() if l.isdigit())),
               'external_record_bytes': self.head.stat().st_size,
               'client_file_bytes': [Path(w.options['path']).stat().st_size for w in self.workers],
               'process_rss_kib_cpu_percent': rss.strip(), 'credential_stats': [self.stats(i) for i in range(2)]}
        self.report.setdefault('load_checkpoints', []).append(row)
        self.save_samples()
        return data
