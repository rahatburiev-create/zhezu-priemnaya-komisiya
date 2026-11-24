'use strict';
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'OPEN_SITE.html'),'utf8');
const scripts=[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]);
let count=0;function check(value,message){assert.ok(value,message);count++;}
const context={location:{protocol:'file:'},console};context.window=context;vm.createContext(context);
vm.runInContext(scripts.find(s=>s.includes('window.INITIAL_PROGRAMS =')),context);
vm.runInContext(scripts.find(s=>s.includes('window.ZhezU=')),context);
(async()=>{
 const data=await context.ZhezU.api('/api/programs');check(data.programs.length===21,'offline catalog');check(data.programs.filter(p=>p.level==='master').length===3,'offline master programs');
 check((await context.ZhezU.api('/api/auth/me')).user===null,'offline no fabricated identity');
 let denied=false;try{await context.ZhezU.api('/api/inquiries',{method:'POST',body:{}});}catch(e){denied=/START\.bat/.test(e.message);}check(denied,'offline no fabricated saved data');
 check(!/<link[^>]+rel="stylesheet"/i.test(html),'single file contains styles');check(!/<script[^>]+src=/i.test(html),'single file contains JavaScript');
 for(const src of [...html.matchAll(/<img[^>]+src="([^"]+)"/gi)].map(m=>m[1]))check(src.startsWith('data:image/'),'images embedded in preview');
 const admin=fs.readFileSync(path.join(root,'public/admin.html'),'utf8');const adminScript=[...admin.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]).find(s=>s.includes('admin-app'));
 const app={innerHTML:''};const ctx={location:{protocol:'file:'},document:{getElementById:()=>app},console};vm.createContext(ctx);vm.runInContext(adminScript,ctx);check(app.innerHTML.includes('START.bat'),'offline admin gives launch instructions');
 for(const filename of ['index.html','login.html','account.html','admin.html']){
  const text=fs.readFileSync(path.join(root,'public',filename),'utf8');
  for(const match of text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi))new vm.Script(match[1]);
  check(!/<script[^>]+src=/i.test(text),'inline page '+filename);
 }
 console.log('PASS:',count,'standalone HTML and inline code checks');
})().catch(e=>{console.error(e);process.exitCode=1;});
