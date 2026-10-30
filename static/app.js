const $=id=>document.getElementById(id);
let token='',cursor=0,polling=false,lastState=null,booted=false,lastRun=null,discovering=false,discoveryResults=[],lastDiscoveryResult=null;
const labels={idle:'HAZIR',running:'ÇALIŞIYOR',success:'DOĞRULANDI',incomplete:'TAMAMLANMADI',failed:'HATA',stopped:'DURDURULDU',needs_restore:'GERİ ALMA GEREKLİ',restored_only:'GERİ ALINDI',password_check_required:'SSH İLE DOĞRULA'};
function error(message){$('error').textContent=message;$('error').hidden=!message;}
function eventLine(event){const row=document.createElement('div');row.className='log-entry '+event.kind;const time=document.createElement('time');time.textContent=event.time;const text=document.createElement('span');text.textContent=event.message;row.append(time,text);$('log').append(row);while($('log').children.length>1500)$('log').firstChild.remove();}
function sshAccessState(state){
  if(state.settings?.mode==='root_password' && state.settings.root_enable_lan_ssh && state.rootPasswordTransfer?.status==='transfer_reported')return {service:'Açma isteği gönderildi',root:'SSH ile doğrula',tone:'neutral',detail:'Yeni parolayla LAN / Wi-Fi üzerinden giriş yap. Hizmetin açıldığı henüz doğrulanmadı.',port:null};
  const group=state.capabilities?.groups?.dropbear_lan;
  const parameters=group?.parameters||{};
  const value=key=>parameters['uci.dropbear.dropbear.@lan.'+key]?.value;
  const flag=raw=>['1','true','on','yes'].includes(String(raw).toLowerCase())?true:['0','false','off','no'].includes(String(raw).toLowerCase())?false:null;
  const enabled=flag(value('enable'));
  const rootFlags=['RootLogin','RootPasswordAuth','PasswordAuth'].map(key=>flag(value(key)));
  const rootAllowed=rootFlags.includes(false)?false:rootFlags.every(item=>item===true)?true:null;
  const port=value('Port');
  return {
    service:enabled===true?'Ayar açık':enabled===false?'Ayar kapalı':group?'Bilinmiyor':'Henüz okunmadı',
    root:rootAllowed===true?'İzinli (ayar)':rootAllowed===false?'İzin kapalı':'Doğrulanmadı',
    tone:enabled===false||rootAllowed===false?'warn':'neutral',
    detail:enabled===false?'Önce SSH hizmetini aç.':rootAllowed===false?'Root parola giriş izni kapalı.':enabled===true?'Hizmetin çalıştığını SSH ile doğrula.':group?'ACS bu ayarı doğrulayamadı.':'Durum için önce salt okunur keşif yap.',
    port:typeof port==='string'&&/^\d{1,5}$/.test(port)&&Number(port)>0&&Number(port)<=65535?port:null,
  };
}
function renderSshAccess(state){
  const access=sshAccessState(state);
  $('root-ssh-service').textContent=access.service;
  $('root-ssh-login').textContent=access.root;
  $('root-ssh-status').dataset.tone=access.tone;
  $('root-ssh-status-note').textContent=access.detail;
  $('lan-ssh-state').textContent=access.service;
  $('lan-ssh-detail').textContent=(access.port?'Port '+access.port+'. ':'')+access.detail;
}
function render(state){
  lastState=state;
  if(state.runId && state.runId!==lastRun && state.settings){
    const saved=state.settings;const active=document.querySelector('input[name=mode][value="'+saved.mode+'"]');if(active)active.checked=true;
    const fields={iface:'iface',mac:'mac',vlan:'vlan',duration:'duration',management_ip:'management-ip',local_ip:'local-ip',peer_ip:'peer-ip',acs_ip:'acs-ip'};
    for(const [key,id] of Object.entries(fields)){if(saved[key]!==undefined && (key!=='iface'||Array.from($(id).options).some(o=>o.value===saved[key])))$(id).value=String(saved[key]);}
    $('root-enable-lan-ssh').checked=saved.root_enable_lan_ssh===true;
    topology();
  }
  renderDiscovery(state.discovery);
  renderProgress(state);
  if(state.runId && state.runId!==lastRun){$('log').replaceChildren();lastRun=state.runId;}
  const badge=$('badge');badge.textContent=state.finishing?'AĞ KAPATILIYOR':labels[state.outcome]||state.outcome;
  badge.className='badge '+(state.outcome==='success'?'success':state.running?'running':['failed','needs_restore','incomplete'].includes(state.outcome)?'warn':'');
  const busy=state.running||discovering;
  $('settings').querySelectorAll('input,select,button').forEach(node=>{if(node.id!=='stop-discovery')node.disabled=busy;});
  $('discover').disabled=state.running||discovering||state.readiness.length>0||!$('iface').value;
  $('start').disabled=state.running||discovering||state.readiness.length>0;
  $('start').firstChild.textContent=state.pending&&!state.running?'Geri almayı tamamla ':document.querySelector('input[name=mode]:checked').value==='configure'?'Seçilen ayarları uygula ':document.querySelector('input[name=mode]:checked').value==='root_password'?'Root parolasını değiştir ':document.querySelector('input[name=mode]:checked').value==='readonly'?'Salt okunur keşfi başlat ':document.querySelector('input[name=mode]:checked').value==='sts_probe'?'STS testini başlat ':document.querySelector('input[name=mode]:checked').value==='log_upload'?'Log aktarımını başlat ':'Yazma / geri alma testini başlat ';
  if(state.pending&&!state.running)document.querySelector('input[name=mode][value=write]').checked=true;
  $('stop').disabled=!state.canStop;
  $('report').disabled=!state.runId;
  $('connection').textContent=state.finishing?'KAPATILIYOR':state.running?'CANLI':state.runId?'OTURUM SONUCU':'BEKLENİYOR';
  $('run-id').textContent=state.runId?`OTURUM ${state.runId} · ${{write:'YAZMA / GERİ ALMA',configure:'YAPILANDIRMA',root_password:'ROOT PAROLASI',readonly:'SALT OKUNUR',log_upload:'LOG AKTARIMI',sts_probe:'STS TESTİ'}[state.settings.mode]}`:'Henüz oturum yok';
  $('router-confirmed').textContent=state.routerConfirmed?'WAN bağlantısı doğrulandı.':'Hedef router: PPPoE bağlantısı bekleniyor.';
  const seconds=state.elapsed||0;$('elapsed').textContent=`${Math.floor(seconds/60).toString().padStart(2,'0')}:${(seconds%60).toString().padStart(2,'0')}`;
  const phase=operationProgress(state,document.querySelector('input[name=mode]:checked').value);document.querySelectorAll('[data-step]').forEach(node=>{const key=node.dataset.step;node.hidden=!phase.order.includes(key);const status=state.outcome==='success'?'done':state.steps[key];node.className=status;node.querySelector('i').textContent=status==='done'?'✓':String(phase.order.indexOf(key)+1);node.querySelector('span').textContent=phase.names[key];});
  $('readiness').hidden=!state.readiness.length;$('readiness').textContent=state.readiness.join(' ');
  $('network-recover').hidden=!state.networkRecovery;$('network-recover').disabled=state.running||discovering;
  const result=$('result');result.hidden=!!state.finishing||!['success','incomplete','failed','needs_restore','restored_only','stopped','password_check_required'].includes(state.outcome);
  result.classList.toggle('warning',state.outcome!=='success');$('result-symbol').textContent=state.outcome==='success'?'✓':'!';
  if(state.outcome==='success'){
    $('result-title').textContent=state.settings?.mode==='sts_probe'?'STS testi doğrulandı, eski değer geri yüklendi.':state.settings?.mode==='write'?'Yazma doğrulandı, eski değer geri yüklendi.':state.settings?.mode==='configure'?'Seçilen ayarlar yazıldı ve tekrar okunarak doğrulandı.':state.settings?.mode==='log_upload'?'Standart log dosyası alındı ve transfer doğrulandı.':'Salt okunur ACS sorguları tamamlandı.';
    $('result-detail').textContent=state.settings?.mode==='sts_probe'?'SSH kalıcılık ayarı: 1 → STS ile 0 → ACS ile 1; iki değer okundu.':state.settings?.mode==='write'?'SSH kalıcılık ayarı: 1 → 0 → okundu: 0 → 1 → okundu: 1':state.settings?.mode==='configure'?'Değişiklikler cihazda bırakıldı. Sonuçlar aşağıdaki kartlarda.':state.settings?.mode==='log_upload'?`${state.uploadProbe?.bytes||0} bayt · SHA-256: ${state.uploadProbe?.sha256||'-'}`:'Okunan değerler ve erişilemeyen alanlar raporda.';
  }else{$('result-title').textContent=state.outcome==='password_check_required'&&state.settings?.mode==='root_password'?'ACS aktarımı tamamlandı; SSH ile doğrulama bekleniyor.':labels[state.outcome]||'';$('result-detail').textContent=state.outcome==='password_check_required'&&state.settings?.mode==='root_password'?'Dosya aktarıldı. Yeni root parolasını SSH ile doğrula.':state.outcome==='password_check_required'?'Parola isteği kabul edildi. Yeni parolayı SSH ile doğrula.':state.outcome==='needs_restore'?'Eski değer henüz doğrulanmadı. Aşağıdaki kurtarma adımlarını kullan.':state.outcome==='restored_only'?'Eski değer geri alındı; ilk yazma sonucu kanıtlanamadı.':'Başarı ölçütleri karşılanmadı. Son işlem günlüğünü incele.';}
  if(state.outcome==='failed' && state.settings?.mode==='root_password'){
    $('result-title').textContent='Root ayarları uygulanamadı';
    $('result-detail').textContent=state.rootPasswordTransfer?.error||state.error||'Cihaz aktarımı tamamlayamadı. Aktarım hata kodunu ve günlüğü kontrol et.';
  }
  $('recovery').hidden=!state.pending;$('rollback').textContent=state.rollback;
  function user(i){const v=state.values;return v[i+'.Username']?`${v[i+'.Username']} · SSH izni ${v[i+'.Enable']==='1'?'açık':v[i+'.Enable']==='0'?'kapalı':'bilinmiyor'} · ${v[i+'.Access']||'-'} · kalıcılık: ${v[i+'.RebootPersistent']==='1'?'açık':v[i+'.RebootPersistent']==='0'?'kapalı':'bilinmiyor'}`:'Henüz okunmadı';}
  let web=state.configuration?.webAdmin;
  if(!web){const parameters=state.capabilities?.groups?.web_users?.parameters||{};const admin=Object.keys(parameters).filter(path=>path.endsWith('.Username')&&parameters[path].value==='admin');if(admin.length===1){const role=parameters[admin[0].slice(0,-8)+'X_000E50_Role']?.value;if(role)web={verifiedRole:role};}}
  $('web-admin-role').textContent=web?`admin · ${web.verifiedRole?'doğrulanan rol: '+web.verifiedRole:'başlangıç rolü: '+web.originalRole+' · hedef: '+web.desiredRole}`:'Henüz okunmadı';
  $('engineer').textContent=user('1');$('superuser').textContent=user('2');
  renderSshAccess(state);
  $('readback').textContent=`${state.values.writeReadback||'-'} / ${state.values.restoreReadback||'-'}`;
  for(const event of state.events)eventLine(event);
  cursor=state.cursor;
  if($('autoscroll').checked)$('log').scrollTop=$('log').scrollHeight;
  error(state.error||'');
  updateMode();
  renderNextActions(state);
}
async function api(path,data){const response=await fetch(path,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-Local-Token':token},...(data===undefined?{}:{body:JSON.stringify(data)})});const body=await response.json();if(!response.ok)throw Error(body.error||'Yerel sunucu isteği başarısız.');return body;}
function updateMode(){const mode=document.querySelector('input[name=mode]:checked').value;const config=mode==='configure';const rootPassword=mode==='root_password';$('configuration-fields').hidden=!config;$('root-password-fields').hidden=!rootPassword;$('mode-note').textContent=rootPassword?'Parola değişikliği otomatik geri alınmaz.':mode==='readonly'?'Okuma bitince veya süre dolunca otomatik durur.':mode==='sts_probe'?'Geri alma bitene kadar bağlantıyı koru.':mode==='log_upload'?'Yalnızca sistem günlüğü alınır.':mode==='write'?'Geri alma doğrulanana kadar router’ı yeniden başlatma.':config?'Yalnızca seçilen ayarlar yazılır ve kontrol edilir.':'Cihaz yapılandırmasına yazma isteği gönderilmez.';
  const busy=!!lastState?.running||discovering;
  const ssh=config&&$('set-ssh').checked;
  const sshExtras=ssh&&$('ssh-action').value==='enable';
  $('ssh-settings-fields').hidden=!ssh;$('ssh-extra-fields').hidden=!sshExtras;
  $('set-admin-role').disabled=!config||busy;$('set-ssh').disabled=!config||busy;
  for(const id of ['ssh-action','target'])$(id).disabled=!ssh||busy;
  for(const id of ['set-persistence','set-password'])$(id).disabled=!sshExtras||busy;
  $('persistence').disabled=!sshExtras||!$('set-persistence').checked||busy;
  document.querySelector('input[value=configure]').setAttribute('aria-expanded',String(config));
  document.querySelector('input[value=root_password]').setAttribute('aria-expanded',String(rootPassword));
  $('set-ssh').setAttribute('aria-expanded',String(ssh));
  const password=sshExtras&&$('set-password').checked;$('cli-password-fields').hidden=!password;
  $('set-password').setAttribute('aria-expanded',String(password));
  for(const id of ['cli-password','cli-confirm']){$(id).required=password;$(id).disabled=!password||!!lastState?.running||discovering;}
  for(const id of ['root-password','root-password-confirm']){$(id).required=rootPassword;$(id).disabled=!rootPassword||!!lastState?.running||discovering;}
  $('root-enable-lan-ssh').disabled=!rootPassword||busy;
  $('root-password-ack').required=rootPassword;$('root-password-ack').disabled=!rootPassword||!!lastState?.running||discovering;
  if(!lastState?.running)$('start').firstChild.textContent=lastState?.pending?'Geri almayı tamamla ':config?'Seçilen ayarları uygula ':rootPassword?'Root parolasını değiştir ':document.querySelector('input[name=mode]:checked').value==='readonly'?'Salt okunur keşfi başlat ':document.querySelector('input[name=mode]:checked').value==='sts_probe'?'STS testini başlat ':document.querySelector('input[name=mode]:checked').value==='log_upload'?'Log aktarımını başlat ':'Yazma / geri alma testini başlat ';
  updateSelectionSummary();
  if(!lastState?.runId){$('steps').querySelector('[data-step=write]').classList.toggle('skipped',['readonly','log_upload'].includes(mode));$('steps').querySelector('[data-step=restore]').classList.toggle('skipped',!['write','sts_probe'].includes(mode));}
}
document.querySelectorAll('input[name=mode]').forEach(node=>node.addEventListener('change',updateMode));
$('form').addEventListener('submit',async event=>{event.preventDefault();error('');$('start').disabled=true;try{const settings={mode:document.querySelector('input[name=mode]:checked').value,iface:$('iface').value,mac:$('mac').value.trim(),vlan:Number($('vlan').value),duration:Number($('duration').value),management_ip:$('management-ip').value.trim(),local_ip:$('local-ip').value.trim(),peer_ip:$('peer-ip').value.trim(),acs_ip:$('acs-ip').value.trim()};
  if(settings.mode==='configure'){const ssh=$('set-ssh').checked;const sshExtras=ssh&&$('ssh-action').value==='enable';settings.web_admin_role=$('set-admin-role').checked?'engineer':'keep';settings.target=Number($('target').value);settings.ssh_action=ssh?$('ssh-action').value:'keep';settings.persistence=sshExtras&&$('set-persistence').checked?$('persistence').value:'keep';if(sshExtras&&$('set-password').checked){if($('cli-password').value!==$('cli-confirm').value)throw Error('CLI parolaları eşleşmiyor.');settings.cli_password=$('cli-password').value;}}
  if(settings.mode==='root_password'){if($('root-password').value!==$('root-password-confirm').value)throw Error('Root parolaları eşleşmiyor.');settings.root_password=$('root-password').value;settings.root_password_confirm=$('root-password-confirm').value;settings.root_password_ack=$('root-password-ack').checked;settings.root_enable_lan_ssh=$('root-enable-lan-ssh').checked;}
  render(await api('/api/start',settings));}catch(e){error(e.message);$('start').disabled=!!lastState?.readiness.length;}finally{$('root-password').value='';$('root-password-confirm').value='';$('cli-password').value='';$('cli-confirm').value='';}});
$('network-recover').addEventListener('click',async()=>{error('');$('network-recover').disabled=true;try{render(await api('/api/network/recover',{}));}catch(e){error(e.message);$('network-recover').disabled=false;}});
$('stop').addEventListener('click',async()=>{error('');try{render(await api('/api/stop',{}));}catch(e){error(e.message);}});
$('report').addEventListener('click',async()=>{try{const r=await fetch('/api/report',{headers:{'X-Local-Token':token}});if(!r.ok)throw Error('Rapor alınamadı.');const url=URL.createObjectURL(await r.blob());const a=document.createElement('a');a.href=url;a.download='acs-test-report.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){error(e.message);}});
async function poll(){if(polling||!booted)return;polling=true;try{render(await api('/api/events?after='+cursor));}catch(e){error('Sunucuya ulaşılamadı. Terminal açık olsun.');}finally{polling=false;}}
async function boot(){try{const r=await fetch('/api/bootstrap');if(!r.ok)throw Error();const b=await r.json();token=b.token;$('host-system').textContent=b.host?b.host.name+(b.host.liveTestPending?' · deneysel':''):'macOS / Linux / Windows';$('iface').replaceChildren();if(b.interfaces.length){for(const entry of b.interfaces){const option=document.createElement('option');option.value=entry.id;option.textContent=entry.displayName||`${entry.id} · ${entry.name}`;$('iface').append(option);}if(b.interfaces.some(i=>i.id==='en11'))$('iface').value='en11';}else{const option=document.createElement('option');option.value='';option.textContent='Fiziksel Ethernet adaptörü bulunamadı';$('iface').append(option);}booted=true;render(b.state);setInterval(poll,1000);}catch(e){error('Sunucu bağlantısı kurulamadı. Sayfayı yenile.');$('start').disabled=true;}}
for(const id of ['set-admin-role','set-ssh','set-persistence','set-password','target','ssh-action','persistence','root-password-ack','root-enable-lan-ssh'])$(id).addEventListener('change',updateMode);
function topology(){const text=$('topology-addresses');text.replaceChildren(document.createTextNode('SSH yönetimi: Wi-Fi / LAN · '+$('management-ip').value),document.createElement('br'),document.createTextNode('Test PPP ağı: '+$('local-ip').value+' ↔ '+$('peer-ip').value));}
for(const id of ['management-ip','local-ip','peer-ip'])$(id).addEventListener('input',topology);
$('iface').addEventListener('change',()=>{discoveryResults=[];$('discovery-results').hidden=true;$('discovery-status').textContent='Yeni adaptör için keşfi tekrar çalıştır.';$('interface-result').textContent='Yeni adaptör seçildi. Bağlantı durumunu kontrol et.';});
$('check-interface').addEventListener('click',async()=>{error('');$('check-interface').disabled=true;try{const data=await api('/api/interface?name='+encodeURIComponent($('iface').value));$('interface-result').textContent=`${data.label||data.iface} · ${data.active?'Fiziksel bağlantı aktif':'Fiziksel bağlantı pasif'} · ${data.mac}. ${data.note}`;}catch(e){error(e.message);}finally{$('check-interface').disabled=false;}});
updateMode();boot();

function operationProgress(state,selectedMode='readonly'){
  const mode=state.settings?.mode||selectedMode;
  const orders={readonly:['link','inform','methods','names','read'],log_upload:['link','inform','methods','read','write'],root_password:['link','inform','methods','write'],configure:['link','inform','methods','names','read','write']};
  const order=orders[mode]||['link','inform','methods','names','read','write','restore'];
  const names={link:'PPPoE / IP',inform:'Cihaz bildirimi',methods:'Desteklenen işlemler',names:'Alanlar',read:'Okuma',write:mode==='log_upload'?'Log aktarımı':mode==='root_password'?'Parola aktarımı':'Yazma',restore:'Geri alma'};
  const done=state.outcome==='success'?order.length:order.filter(step=>state.steps?.[step]==='done').length;
  const titles={readonly:'Salt okunur keşif tamamlandı',log_upload:'Standart log aktarımı başarılı',write:'Yazma ve geri alma başarılı',sts_probe:'STS testi ve geri alma başarılı',configure:'Seçilen ayarlar doğrulandı'};
  return {mode,order,names,done,successTitle:titles[mode]||'İşlem tamamlandı'};
}
function renderProgress(state){
  const {mode,order,names,done,successTitle}=operationProgress(state,document.querySelector('input[name=mode]:checked').value);
  $('progress').max=order.length;$('progress').value=done;
  if(state.finishing){$('progress-title').textContent='Ağ oturumu kapatılıyor';$('progress-detail').textContent='İşlem sona erdi. Geçici ağ ayarı geri alınıyor; ardından yeni bir test başlatabilirsin.';return;}
  if(!state.runId){$('progress-title').textContent='Hazır';$('progress-detail').textContent='Test başlayınca ilerleme ve mevcut aşama burada görünür.';return;}
  if(state.outcome==='success'){$('progress-title').textContent=successTitle;$('progress-detail').textContent=mode==='log_upload'?`Dosya alındı (${state.uploadProbe?.bytes||0} bayt), aktarım doğrulandı ve ağ oturumu kapatıldı.`:'İşlem doğrulandı, ağ oturumu kapatıldı. Sonraki işlemi seçebilirsin.';return;}
  if(mode==='readonly'&&state.outcome==='incomplete'){$('progress-title').textContent='Bekleme süresi doldu';$('progress-detail').textContent='Okuma tamamlanamadı. Bağlantıyı kontrol et.';return;}
  if(!state.running){$('progress-title').textContent=state.outcome==='failed'?'İşlem başarısız':state.outcome==='password_check_required'?'ACS aktarımı tamamlandı; SSH ile doğrula':'İşlem sona erdi';$('progress-detail').textContent=state.outcome==='password_check_required'?'Aktarım tamamlandı ve ağ oturumu kapatıldı. Yeni parolayla giriş yaparak doğrula.':`Tamamlanan aşamalar: ${done} / ${order.length}. Sonucu ve işlem günlüğünü kontrol et.`;return;}
  const active=order.find(step=>state.steps?.[step]==='active')||order.find(step=>state.steps?.[step]==='waiting');
  const number=active?order.indexOf(active)+1:done;
  $('progress-title').textContent=active?`Aşama ${number} / ${order.length} · ${names[active]}`:'İşlem sürüyor';
  $('progress-detail').textContent=active==='link'?'PPPoE/IP bağlantısı kurulması bekleniyor.':active==='inform'?'Router’ın ACS bildirimi bekleniyor.':active==='methods'?'Router’ın desteklediği ACS işlemleri okunuyor.':active==='names'?'Router’dan sunulan alanlar isteniyor.':active==='read'?'Salt okunur değerler alınıyor.':active==='write'?(mode==='log_upload'?'Sistem günlüğü aktarılıyor.':'Seçilen işlem router’a gönderiliyor.'):active==='restore'?'Önceki değer geri yükleniyor ve kontrol ediliyor.':'Yanıt bekleniyor.';
}

function renderDiscovery(data){
  if(!data)return;
  discovering=data.running;
  $('stop-discovery').hidden=!discovering;
  $('stop-discovery').disabled=!discovering;
  if(discovering){
    $('discovery-results').hidden=true;
    $('discovery-status').textContent='PPPoE isteği bekleniyor. Süre sınırı yok; gerekirse WAN kablosunu çıkarıp takın.';
    return;
  }
  if(!data.id||data.id===lastDiscoveryResult)return;
  lastDiscoveryResult=data.id;discoveryResults=data.candidates;
  $('discovered-device').replaceChildren();
  for(const [index,item] of discoveryResults.entries()){
    const option=document.createElement('option');option.value=index;
    const vlan=item.vlans.length?'VLAN '+item.vlans.join(' / '):'VLAN etiketi görünmedi';
    option.textContent=`${item.mac} · ${vlan}${item.selectable?'':' · desteklenmiyor'}`;
    option.disabled=!item.selectable;$('discovered-device').append(option);
  }
  const first=discoveryResults.findIndex(item=>item.selectable);
  $('discovered-device').selectedIndex=first;$('use-discovered').disabled=first<0;
  $('discovery-results').hidden=!discoveryResults.length;
  $('discovery-status').textContent=data.error||
    (discoveryResults.length?'WAN isteği bulundu. Seçilen cihazı kullan.':data.cancelled?'Keşif durduruldu. MAC ve VLAN elle de girilebilir.':'Keşif tamamlandı; PADI görülmedi.');
}
$('discover').addEventListener('click',async()=>{
  error('');$('discover').disabled=true;
  try{
    const data=await api('/api/discover',{iface:$('iface').value});
    render({...lastState,discovery:data,events:[]});
  }catch(e){error(e.message);if(lastState)render({...lastState,events:[]});}
});
$('stop-discovery').addEventListener('click',async()=>{
  $('stop-discovery').disabled=true;
  try{render(await api('/api/discovery/stop',{}));}catch(e){error(e.message);$('stop-discovery').disabled=false;}
});
$('use-discovered').addEventListener('click',()=>{
  const item=discoveryResults[Number($('discovered-device').value)];if(!item?.selectable)return;
  $('mac').value=item.mac;
  if(item.vlan!==null)$('vlan').value=item.vlan;
  $('discovery-status').textContent=item.vlan===null?`Seçilen cihaz: ${item.mac}. VLAN etiketi görünmedi; VLAN ${$('vlan').value} korunuyor, doğrulanmış sayılmaz.`:`Seçilen cihaz: ${item.mac} · gözlenen VLAN ${item.vlan}.`;
});

function updateSelectionSummary(){
  const user=$('target').value==='1'?'engineer':'superuser';
  $('account-name').textContent=user+' hesabı';
  $('account-description').textContent=`SSH kullanıcı adı: ${user}. Mevcut hesap düzenlenir.`;
  const mode=document.querySelector('input[name=mode]:checked').value;
  if(mode==='sts_probe'){$('selection-text').textContent='Geçici ayar değiştirilip geri alınacak.';return;}
  if(mode==='log_upload'){$('selection-text').textContent='Sistem günlüğü bu bilgisayara aktarılacak.';return;}
  if(mode==='readonly'){$('selection-text').textContent='Web rolü, SSH ayarları ve ACS desteği okunacak.';return;}
  if(mode==='write'){$('selection-text').textContent='engineer kalıcılık ayarı 1 → 0 → 1 olarak sınanacak.';return;}
  if(mode==='root_password'){$('selection-text').textContent=$('root-enable-lan-ssh').checked?'Root parolası değiştirilecek; root terminal erişimi ve LAN SSH açılacak. SSH hizmeti yeniden başlatılacak.':'Yalnızca root parolası değiştirilecek. SSH hizmeti açılmayacak.';return;}
  const actions=[];
  const webAction=$('set-admin-role').checked?'Web admin: rol engineer yapılacak. ':'';
  if($('set-ssh').checked)actions.push($('ssh-action').value==='enable'?'LAN SSH hesap izni açılacak':'SSH hesap izni kapatılacak');
  const sshExtras=$('set-ssh').checked&&$('ssh-action').value==='enable';
  if(sshExtras&&$('set-persistence').checked)actions.push($('persistence').value==='1'?'SSH izni yeniden başlatma sonrasında korunacak':'SSH izni yeniden başlatma sonrasında korunmayacak');
  if(sshExtras&&$('set-password').checked)actions.push('bu hesabın parolası değiştirilecek');
  $('selection-text').textContent=webAction||actions.length?webAction+(actions.length?`SSH ${user}: ${actions.join('; ')}. `:'SSH hesapları değişmez. ')+'Router yeniden başlatılmaz.':'En az bir ayar seç.';
}
function renderNextActions(state){
  const mode=state.settings?.mode;
  const show=['success','password_check_required','failed','incomplete','stopped','needs_restore','restored_only'].includes(state.outcome);
  $('next-actions').hidden=!show;
  $('ssh-command').hidden=true;$('ssh-guidance').hidden=true;
  if(!show)return;
  if(state.outcome==='needs_restore'){$('next-instructions').textContent='Geri alma doğrulanmadı. Aşağıdaki adımları izle.';return;}
  if(!['success','password_check_required','restored_only'].includes(state.outcome)){$('next-instructions').textContent='İşlem tamamlanmadı. Yeniden denemeden önce günlük ve mevcut ayarları kontrol et.';return;}
  if(mode==='sts_probe'){$('next-instructions').textContent='STS testi ve geri alma doğrulandı.';return;}
  if(mode==='log_upload'){$('next-instructions').textContent='Log alındı. Boyut ve dosya özeti raporda.';return;}
  if(mode==='readonly'){$('next-instructions').textContent='Sonuçları aşağıda incele. İstersen ayarları uygulama moduna geç.';return;}
  if(mode==='write'){$('next-instructions').textContent='Eski değer geri yüklendi. Artık istediğin işlemi seçebilirsin.';return;}
  if(mode==='root_password'){$('next-instructions').textContent=state.settings.root_enable_lan_ssh?'Root parolası ve LAN SSH açma isteği gönderildi. LAN veya Wi-Fi üzerinden yeni parolayla giriş yaparak doğrula.':'Yalnızca root parolası için istek gönderildi. SSH kapalıysa bu moddaki LAN SSH seçeneğini işaretleyerek yeniden uygula.';$('ssh-command').hidden=false;$('ssh-command').textContent=`ssh root@${state.settings.management_ip||'192.168.1.1'}`;$('ssh-guidance').hidden=false;$('ssh-guidance').textContent='Başarılı girişe kadar mevcut oturumu açık tut.';return;}
  const settings=state.settings;
  const user=settings.target===1?'engineer':'superuser';
  const webChanged=settings.web_admin_role==='engineer';
  const cliChanged=settings.ssh_action!=='keep'||settings.persistence!=='keep'||settings.passwordRequested;
  const webMessage=webChanged?'Web rolü doğrulandı. admin ile web arayüzüne yeniden giriş yap. ':'';
  $('next-instructions').textContent=webMessage+(cliChanged?`${user} için hesap ayarları uygulandı. Parola değiştiyse SSH ile doğrula.`:'SSH hesabı değişmedi.');
  if(!cliChanged)return;
  if(settings.ssh_action==='disable'){
    $('ssh-guidance').hidden=false;$('ssh-guidance').textContent=`${user} hesabının SSH izni kapatıldı.`;
  }else{
    $('ssh-command').hidden=false;$('ssh-command').textContent=`ssh ${user}@${settings.management_ip||'192.168.1.131'}`;
    $('ssh-guidance').hidden=false;$('ssh-guidance').textContent='LAN veya Wi-Fi ağına bağlanıp bu komutu çalıştır. SSH hizmeti açık olmalı; bu hesap root değildir.';
  }
}
