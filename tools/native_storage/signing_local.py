"""仅供隔离自签实验的 macOS 签名 SPI；不属于正式发布或 SDK 接口。

Apple 公开源码 SecCodeSigner.h / CodeSigner.cpp / signerutils.cpp 描述此调用链。
本机 SDK 只导出 SPI 符号，没有对应公开头文件；系统升级后必须重新实测。
直接传入本轮 SecIdentity，避免 codesign 命令的受信身份搜索；不修改系统信任。
"""

import ctypes as C
import json
from pathlib import Path
import re

from signing_keychain import CF, P, S, api, release, string
from support import ROOT


_dictionary = api(CF, 'CFDictionaryCreate', P, [P, P, P, C.c_long, P, P])
_file_url = api(CF, 'CFURLCreateFromFileSystemRepresentation', P,
                [P, C.c_char_p, C.c_long, C.c_ubyte])
_error_code = api(CF, 'CFErrorGetCode', C.c_long, [P])
_error_domain = api(CF, 'CFErrorGetDomain', P, [P])
_error_description = api(CF, 'CFErrorCopyDescription', P, [P])
_error_info = api(CF, 'CFErrorCopyUserInfo', P, [P])
_error_type = api(CF, 'CFErrorGetTypeID', C.c_ulong, [])
_dictionary_value = api(CF, 'CFDictionaryGetValue', P, [P, P])
_string_utf8 = api(CF, 'CFStringGetCString', C.c_ubyte,
                   [P, P, C.c_long, C.c_uint32])
_type_id = api(CF, 'CFGetTypeID', C.c_ulong, [P])
_identity_type = api(S, 'SecIdentityGetTypeID', C.c_ulong, [])
_static_code = api(S, 'SecStaticCodeCreateWithPath', C.c_int32,
                   [P, C.c_uint32, C.POINTER(P)])
_signer_create = api(S, 'SecCodeSignerCreate', C.c_int32,
                     [P, C.c_uint32, C.POINTER(P)])
_add_signature = api(S, 'SecCodeSignerAddSignatureWithErrors', C.c_int32,
                     [P, P, C.c_uint32, C.POINTER(P)])


class LocalSigningError(RuntimeError):
    """记录有界错误链；不枚举 userInfo、证书、身份或密钥对象。"""

    def __init__(self, stage, status, error=None):
        self.stage = stage
        self.status = status
        self.cferror_code = _error_code(error) if error else None
        self.cferror = _public_error(error) if error else None
        super().__init__(f'{stage}: OSStatus={status}, '
                         f'CFError={json.dumps(self.cferror, ensure_ascii=False)}')


def _public_text(value):
    if not value:
        return None
    buffer = C.create_string_buffer(8192)
    if not _string_utf8(value, buffer, len(buffer), 0x08000100):
        return '[错误文本超出记录上限]'
    text = buffer.value.decode('utf-8')
    # 本入口只收到实验身份和公开参数，仍不保留错误中偶然嵌入的秘密/二进制。
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*', '[REDACTED]', text,
                  flags=re.DOTALL)
    text = re.sub(r'(?i)(password|passphrase|seed|secret|token|keydata)\s*[:=]\s*\S+',
                  r'\1=[REDACTED]', text)
    text = re.sub(r'[A-Za-z0-9+/=_-]{80,}', '[REDACTED_LONG_VALUE]', text)
    return text[:2048]


def _public_error(error, depth=0, seen=()):
    address = error.value if isinstance(error, P) else error
    if depth >= 3 or address in seen:
        return {'truncated': True}
    result = {'domain': _public_text(_error_domain(error)), 'code': _error_code(error)}
    description, info = _error_description(error), _error_info(error)
    try:
        result['description'] = _public_text(description)
        if info:
            underlying = _dictionary_value(info, _constant(CF, 'kCFErrorUnderlyingErrorKey'))
            if underlying and _type_id(underlying) == _error_type():
                result['underlying'] = _public_error(underlying, depth + 1, (*seen, address))
        return result
    finally:
        for ref in (description, info):
            if ref:
                release(ref)


def _constant(library, name):
    return P.in_dll(library, name).value


def _owned(refs, value, stage):
    if not value:
        raise RuntimeError(f'{stage}: CoreFoundation 返回空对象')
    refs.append(value)
    return value


def sign_local(path, identifier, identity_ref, requirement):
    """使用本轮有效 SecIdentity 引用签隔离副本，返回可记录的非秘密结果。

    identity_ref 必须由当前进程导入并保持存活；调用方拥有它并负责释放。
    本函数同步调用系统 SPI；调用方应提供进程级超时，不能中途释放身份。
    失败显式抛出并保留目标供排查；成功只代表签名写入，不代表 Keychain、
    系统启动、Developer ID 或公证验收。后续必须独立验证签名与业务行为。
    """
    target = Path(path).resolve(strict=True)
    output = (ROOT / 'dist/native-storage/signing').resolve()
    if not target.is_relative_to(output) or not target.is_file():
        raise ValueError('直接签名仅允许 dist/native-storage/signing 内的实验副本')
    if target.stat().st_nlink != 1:
        raise ValueError('直接签名不接受硬链接，必须先复制已验收程序')
    for name, value in (('identifier', identifier), ('requirement', requirement)):
        if not isinstance(value, str) or not value or '\0' in value:
            raise ValueError(f'{name} 必须是非空且不含 NUL 的字符串')
    if not identity_ref or _type_id(identity_ref) != _identity_type():
        raise ValueError('必须传入本轮有效的 SecIdentity 引用')

    refs = []
    code, signer, error = P(), P(), P()
    try:
        identity_key = _constant(S, 'kSecCodeSignerIdentity')
        identifier_key = _constant(S, 'kSecCodeSignerIdentifier')
        requirement_key = _constant(S, 'kSecCodeSignerRequirements')
        timestamp_key = _constant(S, 'kSecCodeSignerRequireTimestamp')
        signing_identifier = _owned(
            refs, string(None, identifier.encode(), 0x08000100), 'identifier')
        signing_requirement = _owned(
            refs, string(None, requirement.encode(), 0x08000100), 'requirement')
        keys = (P * 4)(identity_key, identifier_key, requirement_key, timestamp_key)
        identity_value = identity_ref.value if isinstance(identity_ref, P) else identity_ref
        values = (P * 4)(identity_value, signing_identifier, signing_requirement,
                         _constant(CF, 'kCFBooleanFalse'))
        # CFType 回调保留键和值；不能把 Python 临时引用的寿命当作 CF 所有权。
        key_callbacks = C.addressof(C.c_byte.in_dll(CF, 'kCFTypeDictionaryKeyCallBacks'))
        value_callbacks = C.addressof(C.c_byte.in_dll(CF, 'kCFTypeDictionaryValueCallBacks'))
        parameters = _owned(refs, _dictionary(None, keys, values, 4,
                                            key_callbacks, value_callbacks), 'parameters')
        encoded_path = bytes(target)
        url = _owned(refs, _file_url(None, encoded_path, len(encoded_path), 0), 'file_url')
        status = _static_code(url, 0, C.byref(code))
        if status != 0:
            raise LocalSigningError('static_code', status)
        status = _signer_create(parameters, 0, C.byref(signer))
        if status != 0:
            raise LocalSigningError('signer_create', status)
        # 显式关闭时间戳网络请求；不设置伪造 Team ID，也不改变信任或钥匙串 ACL。
        status = _add_signature(signer, code, 0, C.byref(error))
        if status != 0:
            raise LocalSigningError('add_signature', status, error)
        return {'path': str(target), 'identifier': identifier,
                'method': 'SecCodeSigner_private_SPI', 'os_status': status,
                'timestamp_requested': False, 'formal_release_validation': 'not_tested'}
    finally:
        for ref in (error, signer, code):
            if ref.value:
                release(ref)
        for ref in reversed(refs):
            release(ref)
