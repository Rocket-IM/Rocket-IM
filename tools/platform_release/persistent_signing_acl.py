"""本轮只读公开 ACL 观察器；不读取秘密、不更新访问列表。"""
import ctypes as c
from persistent_keychain import S, C, P, U, api, no_ui, open_keychain, find, release, binding, PURPOSE

copy_access = api(S, 'SecKeychainItemCopyAccess', [P, c.POINTER(P)])
copy_list = api(S, 'SecAccessCopyACLList', [P, c.POINTER(P)])
copy_contents = api(S, 'SecACLCopyContents', [P, c.POINTER(P), c.POINTER(P), c.POINTER(U)])
copy_auth = api(S, 'SecACLCopyAuthorizations', [P], P)
copy_data = api(S, 'SecTrustedApplicationCopyData', [P, c.POINTER(P)])
count = api(C, 'CFArrayGetCount', [P], c.c_long)
value = api(C, 'CFArrayGetValueAtIndex', [P, c.c_long], P)
get_text = api(C, 'CFStringGetCString', [P, P, c.c_long, U], c.c_ubyte)
data_len = api(C, 'CFDataGetLength', [P], c.c_long)
data_bytes = api(C, 'CFDataGetBytePtr', [P], P)

def checked(status):
    assert status == 0, f'public ACL read OSStatus={status}'

def items(array):
    if not array:
        return []
    n = count(array)
    assert 0 <= n <= 64, 'ACL array overflow'
    return [value(array, i) for i in range(n)]

def text(ref):
    if not ref:
        return None
    buffer = c.create_string_buffer(65536)
    assert get_text(ref, buffer, len(buffer), 0x08000100), 'ACL text overflow'
    return buffer.value.decode()

def inspect(keychain, database, account=None, *, scope=None):
    assert str(keychain).startswith('/private/tmp/Rocket IM ') and keychain.name.startswith('lab-')
    checked(no_ui(0)); refs = []
    try:
        kc = P(); checked(open_keychain(bytes(keychain), c.byref(kc))); refs.append(kc)
        actual_scope = scope if scope is not None else {'service': 'test', 'account': account, 'device': 'one'}
        name = binding({'database': str(database), 'scope': actual_scope}).encode()
        service = PURPOSE.encode(); item = P()
        checked(find(kc, len(service), service, len(name), name, None, None, c.byref(item))); refs.append(item)
        access = P(); checked(copy_access(item, c.byref(access))); refs.append(access)
        listing = P(); checked(copy_list(access, c.byref(listing))); refs.append(listing)
        result = []
        for acl in items(listing):
            apps, description, prompt = P(), P(), U()
            checked(copy_contents(acl, c.byref(apps), c.byref(description), c.byref(prompt)))
            refs.extend(x for x in (apps, description) if x.value)
            auth = copy_auth(acl); assert auth; refs.append(auth)
            paths = []
            for app in items(apps):
                data = P(); checked(copy_data(app, c.byref(data))); refs.append(data)
                n = data_len(data); assert 0 <= n <= 65536
                paths.append(c.string_at(data_bytes(data), n).hex())
            result.append({'authorizations': sorted(text(x) for x in items(auth)),
                'description': text(description), 'prompt': prompt.value,
                'applications_present': bool(apps.value), 'applications': paths})
        decrypt = [row for row in result if 'ACLAuthorizationDecrypt' in row['authorizations']]
        assert decrypt and all(row['applications_present'] and len(row['applications']) == 1 for row in decrypt)
        return result
    finally:
        for ref in reversed(refs):
            release(ref)
