const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const script=fs.readFileSync(path.join(__dirname,'../static/app.js'),'utf8');
const start=script.indexOf('function sshAccessState(');
const end=script.indexOf('function renderSshAccess(',start);
const access=vm.runInNewContext(script.slice(start,end)+';sshAccessState');
function state(values){
  return {capabilities:{groups:{dropbear_lan:{status:'read',parameters:Object.fromEntries(
    Object.entries(values).map(([key,value])=>['uci.dropbear.dropbear.@lan.'+key,{value}]))}}}};
}

test('CLI permission alone never implies the SSH service is enabled',()=>{
  const result=access({values:{'1.Enable':'1','1.Access':'LAN'}});
  assert.equal(result.service,'Henüz okunmadı');
  assert.equal(result.root,'Doğrulanmadı');
});
test('An inaccessible ACS group is unknown, not disabled or enabled',()=>{
  const result=access({capabilities:{groups:{dropbear_lan:{status:'fault',fault_code:'9005'}}}});
  assert.equal(result.service,'Bilinmiyor');
  assert.equal(result.root,'Doğrulanmadı');
});
test('Enabling the service does not imply root authentication is permitted',()=>{
  const result=access(state({enable:'1',RootPasswordAuth:'on',PasswordAuth:'on'}));
  assert.equal(result.service,'Ayar açık');
  assert.equal(result.root,'Doğrulanmadı');
});
test('Known root configuration still requires testing a real SSH connection',()=>{
  const result=access(state({enable:'1',RootLogin:'1',RootPasswordAuth:'on',PasswordAuth:'true',Port:'2222'}));
  assert.equal(result.root,'İzinli (ayar)');
  assert.equal(result.port,'2222');
  assert.match(result.detail,/SSH ile doğrula/);
});
test('Any disabled root-auth flag is reported as blocked',()=>{
  for(const field of ['RootLogin','RootPasswordAuth','PasswordAuth']){
    const result=access(state({enable:'1',RootLogin:'1',RootPasswordAuth:'on',PasswordAuth:'on',[field]:'off'}));
    assert.equal(result.root,'İzin kapalı');
    assert.equal(result.tone,'warn');
  }
  assert.equal(access(state({enable:'0'})).detail,'Önce SSH hizmetini aç.');
});
test('Missing or invalid ports are not shown as verified metadata',()=>{
  for(const port of ['0','65536','22;id','not-a-port'])assert.equal(access(state({Port:port})).port,null);
});

const progressStart=script.indexOf('function operationProgress(');
const progressEnd=script.indexOf('function renderProgress(',progressStart);
const progress=vm.runInNewContext(script.slice(progressStart,progressEnd)+';operationProgress');
test('Successful log transfer is complete and has no write-test restore stage',()=>{
  const result=progress({settings:{mode:'log_upload'},outcome:'success',steps:{link:'done',inform:'done',methods:'done',read:'done'}});
  assert.equal(result.successTitle,'Standart log aktarımı başarılı');
  assert.equal(result.done,result.order.length);
  assert.equal(result.order.length,5);
  assert(!result.order.includes('restore'));
  assert(!result.order.includes('names'));
});
test('Progress includes only stages belonging to the selected operation',()=>{
  assert.equal(progress({settings:{mode:'root_password'}}).order.length,4);
  assert.equal(progress({settings:{mode:'configure'}}).order.length,6);
  assert.equal(progress({settings:{mode:'write'}}).order.length,7);
  assert.equal(progress({settings:{mode:'readonly'}}).order.length,5);
});
test('Requesting LAN root SSH is not shown as verified service availability',()=>{
  const result=access({settings:{mode:'root_password',root_enable_lan_ssh:true},rootPasswordTransfer:{status:'transfer_reported'}});
  assert.equal(result.service,'Açma isteği gönderildi');
  assert.equal(result.root,'SSH ile doğrula');
  assert.notEqual(result.service,'Ayar açık');
});
