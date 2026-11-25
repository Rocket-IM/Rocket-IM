"""联网后继恢复装置：只故障程序制造中断，正常材料由真实Release自动交换。"""
import hashlib
import json
import secrets
from renewal_harness import RenewalLab
from harness import Worker,require,wait
from commit_faults import FaultRuntime

class RecoveryLab(RenewalLab):
    def build(self,proxy=False):
        super().build(proxy=proxy)
        if proxy:
            for i in range(2):self.connect_options[i]['url']=self.auto_options[i]['url']
    def restore(self,index):
        old=self.workers[index];self.workers[index]=Worker(old.directory,old.options);self.setup(index)
        return self.workers[index]
    def initial(self):
        self.auto(0);self.auto(1);self.online(0);self.online(1)
        for i in range(2):
            _,sent=self.send(i,'original-'+str(i));wait(lambda:self.status(i,'original-'+str(i),'delivered'),'original history')
        self.original_identities=[w.call('state')['identity'] for w in self.workers]
        self.original_history=[self.history(i) for i in range(2)]
    def unknown(self,index,label,connect=False):
        # 真正退出密码执行后、完整候选持久化前；既有正常Release负责后继恢复。
        text='SUCCESSOR_PRIVATE_'+secrets.token_hex(16);self.texts.append(text)
        action={'kind':'send','message_id':label,'text':text};request='req-'+label
        fault=FaultRuntime(self,index,'after_crypto',connect=connect)
        try:
            fault.sequence+=1;fault.process.stdin.write(json.dumps({'id':str(fault.sequence),'operation':{'op':'execute','request_id':request,'action':action}})+'\n');fault.process.stdin.flush();fault.exited()
        finally:fault.close()
        self.restore(index)
        self.workers[index].call('recoverRequest',expected='successor_required',requestId=request,action=action)
        self.report.setdefault('real_exit_faults',[]).append({'phase':'after_crypto','exit':86,'index':index,'request_id':request})
        return request,action
    def begin(self,index,request,action):
        return self.workers[index].call('networkRecovery',command={'kind':'begin','request_id':request,'action':action})
    def recovery(self,index):return self.workers[index].call('networkRecovery',command={'kind':'status'})
    def phase(self,index,phase):
        r=self.recovery(index);return r if r and r['phase']==phase else False
    def approve(self,index,round_id):return self.workers[index].call('networkRecovery',command={'kind':'approve','round_id':round_id})
    def complete(self):
        for i in range(2):wait(lambda:self.phase(i,'complete'),'both installed '+str(i),75)
        for i in range(2):self.online(i)
        states=[w.call('state') for w in self.workers]
        require(states[0]['context']==states[1]['context'] and states[0]['context']!='initial','same successor context')
        require([s['identity'] for s in states]==self.original_identities,'original public identity continuous')
        for i in range(2):
            history=self.history(i);require(history[:len(self.original_history[i])]==self.original_history[i],'original history exact prefix')
        return states[0]['context']
    def communicate(self,label):
        for i in range(2):
            _,sent=self.send(i,label+'-'+str(i));wait(lambda:self.status(i,label+'-'+str(i),'delivered'),'new bidirectional delivery',60)
            fact=self.fact(label+'-'+str(i));require(fact and fact['envelope']==sent['value']['envelope'] and fact['delivered'],'real new context accepted and delivered')
    def save_round_proof(self):
        reply=self.rpc(0,'recovery_query',{'id':None});require(reply['ok'],'public round query');r=reply['result']
        self.report.setdefault('rounds',[]).append({'round_id':r['reservation']['id'],'context':r['context'],'status':r['status'],
            'material_sha256':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in r['materials'].items()}})
        return r
