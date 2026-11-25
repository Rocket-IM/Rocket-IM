"""验收专用 macOS Security.framework 装置；仅明确 lab-*.keychain-db，秘密只经 stdin。"""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys

S = c.CDLL('/System/Library/Frameworks/Security.framework/Security')
C = c.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
P = c.c_void_p
U = c.c_uint32
def api(lib, name, args, result=c.c_int32):
    f = getattr(lib, name); f.argtypes = args; f.restype = result; return f
release = api(C, 'CFRelease', [P], None)
no_ui = api(S, 'SecKeychainSetUserInteractionAllowed', [c.c_ubyte])
create = api(S, 'SecKeychainCreate', [c.c_char_p,U,P,c.c_ubyte,P,c.POINTER(P)])
open_keychain = api(S, 'SecKeychainOpen', [c.c_char_p,c.POINTER(P)])
lock = api(S, 'SecKeychainLock', [P])
unlock = api(S, 'SecKeychainUnlock', [P,U,P,c.c_ubyte])
status = api(S, 'SecKeychainGetStatus', [P,c.POINTER(U)])
find = api(S, 'SecKeychainFindGenericPassword', [P,U,c.c_char_p,U,c.c_char_p,c.POINTER(U),c.POINTER(P),c.POINTER(P)])
free = api(S, 'SecKeychainItemFreeContent', [P,P])
remove = api(S, 'SecKeychainItemDelete', [P])
trusted = api(S, 'SecTrustedApplicationCreateFromPath', [c.c_char_p,c.POINTER(P)])
array = api(C, 'CFArrayCreate', [P,c.POINTER(P),c.c_long,P], P)
string = api(C, 'CFStringCreateWithCString', [P,c.c_char_p,U], P)
access = api(S, 'SecAccessCreate', [P,P,c.POINTER(P)])
class Attribute(c.Structure):
    _fields_=[('tag',U),('length',U),('data',P)]
class Attributes(c.Structure):
    _fields_=[('count',U),('attributes',c.POINTER(Attribute))]
add = api(S, 'SecKeychainItemCreateFromContent', [U,c.POINTER(Attributes),U,P,P,P,c.POINTER(P)])
PURPOSE = 'org.rocket-im.sdk.sqlcipher.v1'
def binding(request):
    scope=request['scope']; path=request['database']
    # 对应 Rust 的字段顺序和 UTF-8 JSON；测试路径包含中文。
    scope={k:scope[k] for k in ('service','account','device')}
    return hashlib.sha256(json.dumps([PURPOSE,scope,path],separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def run(request):
    path=Path(request['keychain'])
    assert path.is_absolute() and path.name.startswith('lab-') and path.name.endswith('.keychain-db')
    assert str(path).startswith('/private/tmp/Rocket IM ')
    assert no_ui(0)==0
    refs=[]
    try:
        handle=P()
        if request['op']=='create':
            assert not path.exists()
            password=request['password'].encode()
            result=create(str(path).encode(),len(password),password,0,None,c.byref(handle))
        else: result=open_keychain(str(path).encode(),c.byref(handle))
        if result: return {'status':result}
        refs.append(handle)
        op=request['op']
        if op=='create': return {'status':result}
        if op=='lock': return {'status':lock(handle)}
        if op=='unlock':
            password=request['password'].encode()
            return {'status':unlock(handle,len(password),password,1)}
        if op=='status':
            bits=U(); result=status(handle,c.byref(bits))
            return {'status':result,'unlocked':bool(bits.value&1)}
        service=PURPOSE.encode(); account=binding(request).encode(); item=P()
        if op=='read':
            size=U(); data=P()
            result=find(handle,len(service),service,len(account),account,c.byref(size),c.byref(data),None)
            digest=None
            if result==0:
                digest=hashlib.sha256(c.string_at(data,size.value)).hexdigest()
                free(None,data)
            return {'status':result,'sha256':digest}
        result=find(handle,len(service),service,len(account),account,None,None,c.byref(item))
        if result: return {'status':result}
        refs.append(item)
        if op=='remove': return {'status':remove(item)}
        if op in ('deny','replace'):
            record={'version':1,'purpose':PURPOSE,'scope':request.get('record_scope',request['scope']),
                'path':request['database'],'key':request.get('key')}
            raw=json.dumps(record,separators=(',',':'),ensure_ascii=False).encode()
            apps=[]
            for name in (['/usr/bin/false'] if op=='deny' else request['binaries']):
                binary=Path(name); assert binary.is_file()
                app=P(); result=trusted(str(binary).encode(),c.byref(app))
                if result: return {'status':result}
                refs.append(app); apps.append(app.value)
            values=(P*len(apps))(*apps); arr=array(None,values,len(apps),None);refs.append(arr)
            label=string(None,b'Rocket-IM SDK test fixture ACL',0x08000100);refs.append(label)
            acl=P(); result=access(label,arr,c.byref(acl))
            if result: return {'status':result}
            refs.append(acl)
            result=remove(item)
            if result: return {'status':result}
            attributes=(Attribute*2)(Attribute(int.from_bytes(b'svce','big'),len(service),c.cast(c.c_char_p(service),P)),
                Attribute(int.from_bytes(b'acct','big'),len(account),c.cast(c.c_char_p(account),P)))
            values=Attributes(2,attributes)
            return {'status':add(int.from_bytes(b'genp','big'),c.byref(values),len(raw),raw,handle,acl,None)}
        raise ValueError('unknown fixture operation')
    finally:
        for ref in reversed(refs): release(ref)

if __name__=='__main__':
    print(json.dumps(run(json.load(sys.stdin))))
