"""仅向本轮专用钥匙串导入新生成实验身份；秘密不进入 argv 或日志。"""
import ctypes as C
import hashlib
import os
from pathlib import Path
import secrets
import subprocess

from support import require

P = C.c_void_p
S = C.CDLL('/System/Library/Frameworks/Security.framework/Security')
CF = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')


class ImportParameters(C.Structure):
    _fields_ = [('version', C.c_uint32), ('flags', C.c_uint32),
                ('passphrase', P), ('title', P), ('prompt', P),
                ('access', P), ('usage', P), ('attributes', P)]


def api(library, name, result, arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, arguments
    return function


string = api(CF, 'CFStringCreateWithCString', P, [P, C.c_char_p, C.c_uint32])
data = api(CF, 'CFDataCreate', P, [P, P, C.c_long])
array = api(CF, 'CFArrayCreate', P, [P, P, C.c_long, P])
array_count = api(CF, 'CFArrayGetCount', C.c_long, [P])
array_value = api(CF, 'CFArrayGetValueAtIndex', P, [P, C.c_long])
retain = api(CF, 'CFRetain', P, [P])
type_id = api(CF, 'CFGetTypeID', C.c_ulong, [P])
identity_type = api(S, 'SecIdentityGetTypeID', C.c_ulong, [])
release = api(CF, 'CFRelease', None, [P])
interaction = api(S, 'SecKeychainSetUserInteractionAllowed', C.c_int32, [C.c_ubyte])
create = api(S, 'SecKeychainCreate', C.c_int32, [C.c_char_p, C.c_uint32, P, C.c_ubyte, P, C.POINTER(P)])
lock = api(S, 'SecKeychainLock', C.c_int32, [P])
trusted_app = api(S, 'SecTrustedApplicationCreateFromPath', C.c_int32, [C.c_char_p, C.POINTER(P)])
access_create = api(S, 'SecAccessCreate', C.c_int32, [P, P, C.POINTER(P)])
item_import = api(S, 'SecItemImport', C.c_int32,
                  [P, P, C.POINTER(C.c_uint32), C.POINTER(C.c_uint32), C.c_uint32,
                   C.POINTER(ImportParameters), P, C.POINTER(P)])


def checked(status, operation):
    require(status == 0, f'{operation}: OSStatus={status}')


class LabIdentity:
    """只生成新的自签代码签名证书；不导出任何已有系统身份。"""
    def __init__(self, directory, label):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.path = self.directory / f'lab-signing-{label}.keychain-db'
        self.keychain = P()
        self.identity = P()
        self.label = label
        checked(interaction(0), 'disable_interaction')
        password = secrets.token_hex(32).encode()
        checked(create(str(self.path).encode(), len(password), password, 0, None,
                       C.byref(self.keychain)), 'create_lab_signing_keychain')
        try:
            self.fingerprint = self.generate_and_import()
        except BaseException:
            self.close()
            raise

    def generate_and_import(self):
        cert = self.directory / 'certificate.pem'
        # 全新实验私钥只经子进程 stdout 与导入 API，磁盘仅保存公开证书。
        result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                                 '-noenc', '-days', '2', '-subj',
                                 f'/CN=Rockets-IM isolated signing {self.label}',
                                 '-addext', 'basicConstraints=critical,CA:FALSE',
                                 '-addext', 'keyUsage=critical,digitalSignature',
                                 '-addext', 'extendedKeyUsage=critical,codeSigning',
                                 '-keyout', '/dev/stdout', '-out', str(cert)],
                                capture_output=True, timeout=20)
        require(result.returncode == 0, '实验密钥生成失败')
        private = bytearray(result.stdout)
        # PKCS12在内存中打包完整身份；密码由独立管道输入，不经过argv。
        password = secrets.token_hex(32)
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, (password + '\n').encode())
            os.close(write_fd); write_fd = None
            packed = subprocess.run(['openssl', 'pkcs12', '-export', '-inkey', '/dev/stdin',
                                     '-in', str(cert), '-keypbe', 'PBE-SHA1-3DES',
                                     '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1',
                                     '-passout', f'fd:{read_fd}'],
                                    input=private, capture_output=True, pass_fds=(read_fd,), timeout=20)
            require(packed.returncode == 0, '实验身份内存打包失败')
            imported = bytearray(packed.stdout)
        finally:
            os.close(read_fd)
            if write_fd is not None: os.close(write_fd)
        refs = []
        try:
            app = P(); checked(trusted_app(b'/usr/bin/codesign', C.byref(app)), 'codesign_app')
            refs.append(app)
            runner = P()
            # NULL表示当前进程的真实代码身份；Framework Python的sys.executable可能是启动器。
            # 这里仅控制新实验签名私钥，不影响业务key/trust四程序ACL。
            checked(trusted_app(None, C.byref(runner)), 'lab_runner_app')
            refs.append(runner)
            app_values = (P * 2)(app.value, runner.value)
            apps = array(None, app_values, 2, None); refs.append(apps)
            title = string(None, b'Rockets-IM isolated codesign key', 0x08000100); refs.append(title)
            access = P(); checked(access_create(title, apps, C.byref(access)), 'codesign_access')
            refs.append(access)
            view = (C.c_ubyte * len(imported)).from_buffer(imported)
            blob = data(None, view, len(imported)); refs.append(blob)
            phrase = string(None, password.encode(), 0x08000100); refs.append(phrase)
            params = ImportParameters(); params.access = access.value; params.passphrase = phrase
            # 本机SecImportExport.h：kSecFormatPKCS12=12、kSecItemTypeAggregate=5。
            fmt, kind, items = C.c_uint32(12), C.c_uint32(5), P()
            checked(item_import(blob, None, C.byref(fmt), C.byref(kind), 0,
                                C.byref(params), self.keychain, C.byref(items)), 'import_new_lab_identity')
            if items.value: refs.append(items)
            require(items.value is not None and array_count(items) > 0,
                    f'实验身份导入未返回条目（packed_bytes={len(imported)}）')
            identities = [array_value(items, i) for i in range(array_count(items))
                          if type_id(array_value(items, i)) == identity_type()]
            require(len(identities) == 1, '实验导入没有唯一签名身份')
            self.identity = P(retain(identities[0]))
        finally:
            for ref in reversed(refs):
                if ref: release(ref)
            for buffer in (private, imported): buffer[:] = b'\0' * len(buffer)
        der = subprocess.run(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'],
                             capture_output=True, timeout=10)
        require(der.returncode == 0, '实验公开证书解析失败')
        return hashlib.sha1(der.stdout).hexdigest()

    def close(self):
        if self.identity.value:
            release(self.identity)
            self.identity = P()
        if self.keychain.value:
            status = lock(self.keychain)
            release(self.keychain)
            self.keychain = P()
            checked(status, 'lock_lab_signing_keychain')
