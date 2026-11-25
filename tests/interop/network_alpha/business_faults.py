"""测试专用HTTPS响应丢失/延迟代理，仅记录请求摘要，不存凭证或响应正文。"""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


class FaultProxy:
    def __init__(self,lab,mode,delay_seconds=.25):
        self.hashes=[];self.lock=threading.Lock();self.count=0
        proxy=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']))
                with proxy.lock:
                    proxy.count+=1;number=proxy.count;proxy.hashes.append(hashlib.sha256(raw).hexdigest())
                req=urllib.request.Request(lab.endpoint+self.path,data=raw,headers={'Authorization':self.headers['Authorization'],'Content-Type':'application/json'})
                try:
                    with urllib.request.urlopen(req,context=lab.ssl,timeout=10) as response:status=response.status;data=response.read()
                except urllib.error.HTTPError as e:status=e.code;data=e.read()
                if mode=='drop' and number==1:
                    self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                if (mode=='delay' and number==1) or mode=='timeout':time.sleep(delay_seconds)
                try:self.send_response(status);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
                except (BrokenPipeError,ssl.SSLEOFError,ConnectionResetError):pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_3
        root=Path(lab.env['directory']);tls.load_cert_chain(root/'server.pem',root/'server.key')
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.endpoint=f'https://127.0.0.1:{self.server.server_port}'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)
