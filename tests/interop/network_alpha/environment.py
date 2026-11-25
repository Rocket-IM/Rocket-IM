"""本机Alpha验收环境：独立原生PostgreSQL、临时TLS CA；秘密不进日志。"""
from pathlib import Path
import json
import os
import secrets
import socket
import subprocess
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[3]
PG = ROOT / 'dist/toolchains/postgres/bin'
GO = ROOT / 'dist/toolchains/go/bin/go'

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def command(args, directory, log):
    with open(log, 'wb') as out:
        subprocess.run([str(a) for a in args], cwd=directory, stdout=out, stderr=subprocess.STDOUT, check=True, timeout=120)

def prepare(directory):
    directory = Path(directory); directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    pgdata = directory / 'postgres'; sockets = directory / 'socket'; sockets.mkdir(exist_ok=True)
    password = directory / 'postgres-password'; password.write_text(secrets.token_hex(24)); password.chmod(0o600)
    command([PG/'initdb', '-D', pgdata, '-U', 'alpha', '--pwfile', password, '--auth-local=trust', '--auth-host=scram-sha-256', '--encoding=UTF8', '--no-locale'], directory, directory/'initdb.log')
    # 仅私有Unix socket；此本机数据库没有TCP监听或真实账号。
    with (pgdata/'postgresql.conf').open('a') as f:
        f.write("\nlisten_addresses = ''\nunix_socket_directories = '" + str(sockets) + "'\nunix_socket_permissions = 0700\nmax_connections = 20\n")
    command([PG/'pg_ctl','-D',pgdata,'-l',directory/'postgres.log','-w','start'],directory,directory/'postgres-start.log')
    command([PG/'createdb','-h',sockets,'-U','alpha','alpha'],directory,directory/'createdb.log')
    openssl='/opt/homebrew/opt/openssl@3/bin/openssl'
    command([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','3','-subj','/CN=Rocket IM Alpha Test CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],directory,directory/'ca.log')
    command([openssl,'req','-new','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN=127.0.0.1'],directory,directory/'csr.log')
    (directory/'tls.ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    command([openssl,'x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','3','-extfile','tls.ext'],directory,directory/'cert.log')
    command([openssl,'x509','-in','ca.pem','-outform','DER','-out','ca.der'],directory,directory/'der.log')
    for p in directory.glob('*.key'): p.chmod(0o600)
    result={'directory':str(directory),'database_url':f'postgresql://alpha@/alpha?host={quote(str(sockets), safe="")}', 'port':port(), 'ca_certificate':(directory/'ca.der').read_bytes().hex()}
    (directory/'environment.json').write_text(json.dumps(result,indent=2));return result

def stop(directory):
    directory=Path(directory)
    subprocess.run([str(PG/'pg_ctl'),'-D',str(directory/'postgres'),'-m','fast','-w','stop'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=True)

if __name__=='__main__':
    import sys
    if sys.argv[1]=='prepare':
        result=prepare(sys.argv[2]);print(json.dumps({'environment':str(Path(sys.argv[2])/'environment.json'),'status':'READY'}))
    elif sys.argv[1]=='stop':stop(sys.argv[2])
