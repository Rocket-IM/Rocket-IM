"""真实包副本负例、公开进程输入边界与数据库文件错误。"""
import json
import shutil
import subprocess
from desktop_package import NAME, node_binary, sha, command
from desktop_support import Host, SCOPE, peer, setup, send
from support import require


def package_cases(consumer, directory, report):
    cases = ['missing_binary','wrong_version','wrong_target','corrupt_binary','not_executable','unsupported_platform','wrong_handshake']
    expected = ['artifact_binary_missing','artifact_version_mismatch','artifact_platform_mismatch','artifact_hash_mismatch',
                'artifact_not_executable','unsupported_platform','ipc_protocol_error']
    outcomes = []
    for name, code in zip(cases,expected):
        dest = directory / name
        shutil.copytree(consumer,dest)
        package = dest/'node_modules'/NAME
        binary = package/'bin/darwin-arm64/desktop_storage'
        manifest_path = package/'artifact.json'
        manifest = json.loads(manifest_path.read_text())
        prelude = ''
        if name == 'missing_binary': binary.unlink()
        elif name == 'wrong_version': manifest['version'] = '999.0.0'
        elif name == 'wrong_target': manifest['target'] = 'win32-x64'
        elif name == 'corrupt_binary':
            with binary.open('ab') as stream: stream.write(b'corrupt')
        elif name == 'not_executable': binary.chmod(0o600)
        elif name == 'unsupported_platform': prelude = "Object.defineProperty(process, 'platform', {value:'win32'});\n"
        elif name == 'wrong_handshake':
            binary.write_text('#!/bin/sh\nprintf \'{"ready":true,"protocol":999,"version":"wrong"}\\n\'\n')
            binary.chmod(0o700); manifest['binarySha256'] = sha(binary)
        manifest_path.write_text(json.dumps(manifest))
        script = prelude + """
import { DesktopStorage } from '@rocket-im/stage0-desktop-storage';
try {
  const c = await DesktopStorage.open({ path: './unused.db', create: true, scope: {service:'s',account:'a',device:'d'} });
  await c.close(); console.log(JSON.stringify({code:'unexpected_success'}));
} catch (error) { console.log(JSON.stringify({code:error.code})); }
"""
        (dest/'negative.mjs').write_text(script)
        result = command([node_binary(),dest/'negative.mjs'],dest,dest/'result.log',timeout=20)
        actual = json.loads((dest/'result.log').read_text())
        require(actual['code'] == code, f'{name}: {actual}')
        require(not (dest/'unused.db').exists(),'包拒绝仍触及数据库')
        outcomes.append({'name':name,'status':'PASS_SCOPED','code':code,'process':result,
                         'scope':'simulated unsupported OS branch' if name == 'unsupported_platform' else 'actual package copy'})
    return outcomes


def input_cases(consumer,binary,directory,records):
    with peer(binary,directory,records) as other, Host(consumer,directory,records) as host:
        path = directory/'input.db'
        setup(host,other,path)
        before = host.ok('state')
        event_count = len(host.ok('events'))
        host.fail('send','request_too_large',requestId='large',attemptId='large',messageId='large',text='x'*270000)
        host.fail('send','invalid_text',requestId='oversize',attemptId='oversize',messageId='oversize',text='x'*4097)
        host.fail('received','invalid_sequence',sequence='9007199254740993x')
        host.fail('received','receive_not_found',sequence='9007199254740993')
        require(host.ok('state') == before and len(host.ok('events')) == event_count,'输入拒绝改变状态')
        host.fail('open','crypto_store_exists',name='exists',options={'path':str(path),'scope':SCOPE,'create':True})
        missing = directory/'missing.db'
        host.fail('open','crypto_store_missing',name='missing',options={'path':str(missing),'scope':SCOPE})
        corrupt = directory/'corrupt.db';corrupt.write_bytes(b'not a sqlite database'+b'\0'*128)
        host.fail('open','database_corrupt',name='corrupt',options={'path':str(corrupt),'scope':SCOPE})
        require(not missing.exists(),'缺库隐式创建')
        send(host)
    return {'input_rejections':4,'database_open_rejections':3,'normal_after_errors':True}


def public_gate(binary,directory):
    requests = [
        {'id':'fault','operation':{'op':'initialize','request_id':'init','fault':'refuse_commit'}},
        {'id':'peer','operation':{'op':'peer_identity'}},
        {'id':'sql','operation':{'op':'sql','sql':'SELECT 1'}},
        {'id':'state','operation':{'op':'state'}},
        {'id':'close','operation':{'op':'close'}},
    ]
    result = subprocess.run([str(binary),str(directory/'gate.db'),'s','a','d','create'],
                            input=''.join(json.dumps(r)+'\n' for r in requests),text=True,capture_output=True,timeout=10)
    lines = [json.loads(line) for line in result.stdout.splitlines()]
    require(result.returncode == 0 and len(lines) == 6,'公开进程异常')
    require(all(not x['ok'] and x['error']['code'] == 'invalid_request' and x['events'] == [] for x in lines[1:4]),'内部故障/peer/SQL命令泄露')
    require(lines[4]['result']['revision'] == '0','拒绝仍修改状态')
    require(not any(key in line for line in lines for key in ('trace','metrics')),'公开响应泄露诊断字段')
    (directory/'public-gate.json').write_text(json.dumps(lines,indent=2))
    return {'rejections':3,'trace_metrics_exposed':False}
