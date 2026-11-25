"""仅独立test-hooks程序制造精确提交中断；恢复使用正常安装的实际TGZ。"""
import json
import os
import queue
import subprocess
import threading
import time
from harness import Worker, require, wait

class FaultRuntime:
    def __init__(self,lab,index,phase,refuse=False,connect=True):
        self.queue=queue.Queue();self.sequence=0;self.events=[]
        w=lab.workers[index];self.options=w.options;w.close()
        env={k:v for k,v in os.environ.items() if not k.startswith('ROCKET_IM_TEST_')}
        if refuse:env['ROCKET_IM_TEST_COMMIT_FAILURE']='1'
        else:env['ROCKET_IM_TEST_EXIT_PHASE']=phase
        scope=self.options['scope'];args=[lab.release/'fault-runtime',self.options['path'],scope['service'],scope['account'],scope['device'],'open',self.options['keychain']]
        self.log=(lab.run/('fault-'+phase+'.log')).open('wb')
        self.process=subprocess.Popen(args,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1)
        def read():
            for line in self.process.stdout:
                self.queue.put(json.loads(line))
            self.queue.put(None)
        threading.Thread(target=read,daemon=True).start()
        ready=self.queue.get(timeout=10);require(ready and ready.get('ready') and ready.get('test_hooks'),'fault runtime handshake')
        if connect:self.call({'op':'connect','options':lab.connect_options[index]})
    def next(self,timeout=15):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=self.queue.get(timeout=max(.1,deadline-time.monotonic()))
            if value and 'event' in value:self.events.append(value['event']);continue
            return value
        raise AssertionError('fault runtime deadline')
    def call(self,operation,timeout=15):
        self.sequence+=1;self.process.stdin.write(json.dumps({'id':str(self.sequence),'operation':operation})+'\n');self.process.stdin.flush()
        reply=self.next(timeout);require(reply and reply.get('ok'),'fault call');return reply['result']
    def exited(self):
        require(self.next() is None,'expected exact interruption');require(self.process.wait(timeout=5)==86,'test hook exit code');self.close()
    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.log.close()

def run(lab):
    def restore(index):
        old=lab.workers[index];lab.workers[index]=Worker(old.directory,old.options)
    def after_accept():
        lab.workers[0].call('disconnect');text,result=lab.send(0,'commit-accept')
        fault=FaultRuntime(lab,0,'network_after_accept')
        try:fault.exited()
        finally:fault.close()
        restore(0);require(lab.status(0,'commit-accept','local_saved'),'Service acceptance not falsely reported before local commit')
        recovered=lab.workers[0].call('send',requestId='req-commit-accept',messageId='commit-accept',text=text)
        require(recovered['value']==result['value'],'accept interruption preserves original ciphertext')
        lab.connect(0);wait(lambda:lab.status(0,'commit-accept','delivered'),'recover service accepted local unknown')
        require(len([x for x in lab.history(1) if x['message']['message_id']=='commit-accept'])==1,'single accept interruption message')
    lab.case('network_accept_interruption_before_local_ack_commit',after_accept)
    for phase in ('network_after_download','after_candidate','before_commit','after_commit','refuse_commit'):
        def receive_fault(phase=phase):
            b=lab.workers[1];b.call('disconnect');before=b.call('state')['received_count']
            id='fault-'+phase.replace('_','-');text,result=lab.send(0,id);wait(lambda:lab.status(0,id,'accepted'),'message accepted before receiver failure')
            fault=FaultRuntime(lab,1,phase,refuse=phase=='refuse_commit')
            try:
                if phase=='refuse_commit':
                    state=wait(lambda:(s if (s:=fault.call({'op':'network_state'}))['connection']=='blocked' else False),'refused commit explicit blocked')
                    require(state['error']['code']=='commit_unknown','unknown commit reason');fault.close()
                else:fault.exited()
                require(not lab.status(0,id,'delivered'),'no device delivery before processed report')
                restore(1);current=lab.workers[1].call('state')
                require(current['received_count']==str(int(before)+(1 if phase=='after_commit' else 0)),'only committed receive exposed')
                network=lab.workers[1].call('network');require(int(network['downloaded'])>=int(network['processed']),'persistent cursor order')
                lab.connect(1);wait(lambda:lab.status(0,id,'delivered'),'normal package resumes '+phase)
                found=[x for x in lab.history(1) if x['message']['message_id']==id]
                require(len(found)==1 and found[0]['message']['text']==text,'one recovered receive '+phase)
            finally:fault.close()
        lab.case('network_receive_'+phase,receive_fault)
