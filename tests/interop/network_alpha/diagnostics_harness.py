"""诊断验收复用容量装置；只有公开SDK/API读诊断，PG仅独立只读取证。"""
from pathlib import Path
import json
import shutil
import urllib.error
import urllib.request
from capacity_harness import CapacityLab
from harness import ROOT, require, sha, all_hashes

OLD_SERVICE = ROOT/'dist/platform-release/persistent/runs/a727bfee-5bd4-4862-bc87-16b235c55543/release-12/im-service'
OLD_SHA = 'c30b84cb1c5446247ab5fd9a181e834bf079bc701382dd020b71eba1090d499c'


class DiagnosticsLab(CapacityLab):
    def __init__(self, *args):
        super().__init__(*args)
        self.credential_ttl = 300
        self.operator = True
        self.old_service = False

    def command(self, args, cwd, label, env=None):
        if label == 'go-build' and self.old_service:
            source,digest=OLD_SERVICE,OLD_SHA
            if self.old_service == 'reserve':
                from reserve_upgrade import OLD_SERVICE as source, OLD_SHA as digest
            if self.old_service == 'workset':
                from workset_upgrade import OLD_SERVICE as source, OLD_SHA as digest
            version = {'reserve': 'alpha.6', 'workset': 'alpha.7'}.get(self.old_service, 'alpha.5')
            require(sha(source) == digest, 'unchanged actual '+version+' baseline')
            shutil.copy2(source, self.root/'im-service')
            self.report['upgrade_old_service'] = {'path': str(source), 'sha256': digest}
            log = self.run/'old-service-copy.log'
            log.write_text('Verified actual '+version+' executable copied into new isolated environment.\n')
            return log
        return super().command(args, cwd, label, env)

    def start_service(self):
        config = json.loads(self.config.read_text())
        if self.operator and 'recovery_state' not in config:
            config['business']['principals'][0]['capacity_read'] = True
            self.config.write_text(json.dumps(config))
            self.config.chmod(0o600)
        super().start_service()

    def diagnostic(self, token, business=False, status=200, code=None, suffix='', body=None):
        url = self.endpoint+('/v1/business/capacity' if business else '/v1/capacity')+suffix
        request = urllib.request.Request(url, data=body, method='GET', headers={'Authorization': 'Bearer '+token})
        try:
            response = urllib.request.urlopen(request, context=self.ssl, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            require(response.status == status, 'capacity HTTP status '+str(response.status))
            require(response.headers.get('Cache-Control') == 'no-store', 'capacity never cached')
            value = json.load(response)
        if code:
            require(value == {'error': {'code': code}}, 'error has no diagnostic data')
        else:
            require(value['scope']['access'] == ('service' if business else 'device'), 'exact authorized capacity scope')
        return value

    def install_new_service(self):
        report = json.loads((self.service_release/'report.json').read_text())
        require(report['status'] == 'PASS_SCOPED' and sha(self.service_release/'im-service') == report['service_sha256'], 'verified new Service')
        require(all_hashes(self.service_release/'source') == report['source_files'], 'new Service frozen source')
        shutil.copy2(self.service_release/'im-service', self.root/'im-service')
        self.old_service = False
        self.report['upgrade_new_service'] = {'version': report['service_version'], 'sha256': report['service_sha256']}


def old_client(task, new, key="dev10"):
    fingerprint = json.loads((new/'report.json').read_text())['signing']['certificate_sha1']
    matches = []
    for path in Path(task).glob('*-signer.json'):
        record = json.loads(path.read_text())
        if record.get('status') == 'PASS_SCOPED' and record.get('certificate_sha1') == fingerprint and record.get(key):
            matches.append(record[key])
    require(len(matches) == 1, 'one same-signer verified '+key+' baseline')
    release = Path(matches[0]['release'])
    report = json.loads((release/'report.json').read_text())
    require(report['archive_sha256'] == matches[0]['archive_sha256'] == sha(Path(report['archive'])), 'exact copied old package')
    require(all_hashes(release/'package') == report['package_files'], 'unchanged copied old package tree')
    return release
