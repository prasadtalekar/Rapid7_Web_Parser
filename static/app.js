const $ = id => document.getElementById(id);
let data = {status:'idle',rows:[],warnings:[]};
let busy = false;
function visibleRows(){return data.rows.filter(r => !$('since').value || (r.date && r.date >= $('since').value));}
function render(){
 const rows=visibleRows(), running=data.status==='running';
 $('scan').disabled=running; $('scan').textContent=running?'Scanning…':'Scan Rapid7';
 $('download').disabled=!rows.length || !['ready','partial'].includes(data.status);
 $('status').textContent=({idle:'Ready to scan',running:`Scanning articles · ${data.completed} / ${data.total || '…'}`,ready:'Scan complete',partial:'Scan complete with warnings',error:'Scan failed'})[data.status];
 $('updated').textContent=data.updated?'Last result: '+new Date(data.updated).toLocaleString():'No completed scan yet';
 $('progress').hidden=!running; $('progress').max=data.total || 1; $('progress').value=data.completed || 0;
 $('count').textContent=rows.length;
 $('summary').textContent=$('since').value?'Filtered by original publication date; undated articles are excluded.':'Only articles containing a CVE identifier appear here.';
 $('warnings').hidden=!data.warnings.length;
 const warnings=$('warnings').querySelector('ul'); warnings.replaceChildren();
 data.warnings.forEach(w=>{const li=document.createElement('li');li.textContent=w;warnings.append(li);});
 $('rows').replaceChildren();
 if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.className='empty';td.textContent=running?'Reading article content…':data.status==='idle'?'Run a scan to collect the latest CVE articles.':'No CVE articles available for this selection.';tr.append(td);$('rows').append(tr);}
 rows.forEach(r=>{const tr=document.createElement('tr');const dt=document.createElement('td');dt.textContent=r.date || 'Date unavailable';const title=document.createElement('td'),a=document.createElement('a');a.textContent=r.title;a.href=r.url;a.target='_blank';a.rel='noopener noreferrer';title.append(a);const cv=document.createElement('td');r.cves.forEach(c=>{const span=document.createElement('span');span.className='cve';span.textContent=c;cv.append(span);});const scores=document.createElement('td'),technologies=document.createElement('td');r.cves.forEach(c=>{const detail=(r.nvd||{})[c]||{},score=document.createElement('div'),technology=document.createElement('div');score.className='nvd-item';technology.className='nvd-item';const scoreId=document.createElement('strong'),technologyId=document.createElement('strong');scoreId.textContent=c+': ';technologyId.textContent=c+': ';score.append(scoreId,document.createTextNode(detail.score||'NVD data unavailable'));technology.append(technologyId,document.createTextNode(detail.technology||'NVD data unavailable'));scores.append(score);technologies.append(technology);});tr.append(dt,title,cv,scores,technologies);$('rows').append(tr);});
}
async function refresh(){if(busy)return;busy=true;try{const r=await fetch('/api/results');if(!r.ok)throw Error('Unable to load results.');data=await r.json();render();}catch(e){$('message').textContent='Connection lost. Retrying automatically…';}finally{busy=false;}}
$('scan').addEventListener('click',async()=>{ $('message').textContent='';$('scan').disabled=true;try{const r=await fetch('/api/scan',{method:'POST',headers:{'X-Requested-With':'Rapid7Reader'}});const j=await r.json();if(!r.ok)throw Error(j.error || 'Unable to start scan.');await refresh();}catch(e){$('message').textContent=e.message;$('scan').disabled=false;}});
$('since').addEventListener('change',render);
$('download').addEventListener('click',async()=>{const d=new Date(),p=x=>String(x).padStart(2,'0');const stamp=p(d.getDate())+p(d.getMonth()+1)+String(d.getFullYear()).slice(-2)+'_'+p(d.getHours())+'_'+p(d.getMinutes());const q=new URLSearchParams({since:$('since').value,stamp});try{const r=await fetch('/download?'+q);if(!r.ok)throw Error(await r.text());const url=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=url;a.download='Rapid7Parser_'+stamp+'.xls';a.click();setTimeout(()=>URL.revokeObjectURL(url),10000);}catch(e){$('message').textContent=e.message;}});
refresh();setInterval(refresh,2500);
