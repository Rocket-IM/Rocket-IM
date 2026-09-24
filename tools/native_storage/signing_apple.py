"""只读取公开证书，绑定用户选定身份与实际签名产物；不导出私钥。"""
import hashlib
import re
import ssl
from pathlib import Path

from support import require


def selected_identity(identity, directory, records, command):
    """私钥操作前匹配当前有效身份，并从精确证书OU读取团队。"""
    fingerprint = identity.upper()
    require(re.fullmatch(r'[0-9A-F]{40}', fingerprint) is not None, '签名身份必须为完整SHA-1指纹')
    inventory = command(['security', 'find-identity', '-v', '-p', 'codesigning'], records)['stdout']
    matches = re.findall(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$', inventory, re.M)
    names = {name for digest, name in matches if digest == fingerprint}
    require(len(names) == 1, '所选指纹不是当前唯一可用的签名身份')
    name = names.pop()
    kind = ('apple_development' if name.startswith('Apple Development: ') else
            'developer_id_application' if name.startswith('Developer ID Application: ') else None)
    require(kind is not None, '所选身份不是支持的Apple开发或Developer ID Application证书')
    certificates = command(['security', 'find-certificate', '-a', '-c', name, '-p'], records)['stdout']
    selected = None
    for pem in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', certificates, re.S):
        der = ssl.PEM_cert_to_DER_cert(pem)
        if hashlib.sha1(der).hexdigest().upper() == fingerprint:
            selected = pem
    require(selected is not None, '找不到与所选指纹精确匹配的公开证书')
    path = Path(directory) / 'selected-public-certificate.pem'
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(selected + '\n')
    details = command(['openssl', 'x509', '-in', path, '-noout', '-subject', '-issuer',
                       '-dates', '-nameopt', 'RFC2253'], records)['stdout']
    subject = next((line.split('=', 1)[1].strip() for line in details.splitlines()
                    if line.startswith('subject=')), '')
    teams = re.findall(r'(?:^|(?<!\\),)OU=([A-Z0-9]{10})(?=,|$)', subject)
    require(len(teams) == 1, '公开证书没有唯一有效的团队OU；不从名称括号猜测团队')
    return {'kind': kind, 'name': name, 'sha1': fingerprint, 'team_identifier': teams[0],
            'public_certificate': str(path), 'certificate_details': details}


def verify_signed(item, selected, records, command):
    """核对每份Apple程序的实际Authority、Team及嵌入叶证书。"""
    lines = item['signature'].splitlines()
    authorities = [line.removeprefix('Authority=') for line in lines if line.startswith('Authority=')]
    teams = [line.removeprefix('TeamIdentifier=') for line in lines if line.startswith('TeamIdentifier=')]
    require(item['static_valid'] and authorities and authorities[0] == selected['name'],
            '实际签名Authority与用户选定身份不一致或完整签名校验失败')
    require(teams == [selected['team_identifier']], '实际签名团队与所选公开证书OU不一致')
    path = Path(item['path'])
    prefix = path.parent / (path.name + '.public-cert-')
    command(['codesign', '--display', '--extract-certificates=' + str(prefix), path], records)
    leaf = Path(str(prefix) + '0')
    require(leaf.is_file(), '实际签名没有导出公开叶证书')
    digest = hashlib.sha1(leaf.read_bytes()).hexdigest().upper()
    require(digest == selected['sha1'], '实际嵌入的签名证书不是用户选定指纹')
    return {'path': str(path), 'kind': selected['kind'], 'team_identifier': teams[0],
            'leaf_sha1': digest, 'static_valid': True}
