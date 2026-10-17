import {test,expect} from '@playwright/test';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('owner manages optional modules and local Master while Supervisor is unavailable',async({page})=>{
  const dir=await mkdtemp(join(tmpdir(),'lattice-modules-ui-')); const socket=join(dir,'node.sock');
  const mutations=[];let relay=false;
  const ipc=net.createServer(client=>{let data='';client.on('data',chunk=>{data+=chunk;if(!data.includes('\n'))return;
    const r=JSON.parse(data);let reply;
    if(r.method==='get_participation')reply={type:'participation',data:{accepted:true,text:'Fixture terms',version:'1',sha256:'test',master_choice:{control_id:null,revision:0}}};
    else if(r.method==='get_modules'||r.method==='enable_module'||r.method==='disable_module'){
      if(r.method!=='get_modules'){mutations.push(r);relay=r.method==='enable_module';}
      reply={type:'modules',data:[{kind:'master',enabled:true,state:'active',process_id:100,certificate_id:'master-certificate',error_code:null},{kind:'relay',enabled:relay,state:relay?'active':'disabled',process_id:null,certificate_id:'relay-certificate',error_code:null},{kind:'supervisor',enabled:false,state:'disabled',process_id:null,certificate_id:null,error_code:null}]};
    }else if(r.method==='sync_authority')reply={type:'error',data:{message:'Supervisor unavailable'}};
    else if(r.method==='get_network_manager')reply={type:'network_manager',data:{owner_process_id:99,desired_revision:7,applied_revision:7,interface_name:'lattice0',error_code:null}};
    else if(r.method==='local_master'){mutations.push(r);reply={type:'local_master',data:{status:200,content_type:'application/json',body_base64:Buffer.from('{"nodes":[]}').toString('base64')}};}
    else reply={type:'error',data:{message:'Unavailable in fixture'}};
    client.end(JSON.stringify(reply)+'\n');
  });});
  await new Promise(r=>ipc.listen(socket,r));
  const child=spawn(process.execPath,['web/node/server.mjs'],{cwd:new URL('../..',import.meta.url),env:{...process.env,LATTICE_SOCKET:socket,LATTICE_CONSOLE_TEST_MODE:'1',LATTICE_CONSOLE_TOKEN:'a'.repeat(64),LATTICE_NODE_WEB_PORT:'18746'},stdio:'ignore'});
  try{
    for(let i=0;i<50;i++){try{await fetch('http://127.0.0.1:18746/');break;}catch{await new Promise(r=>setTimeout(r,50));}}
    await page.context().addCookies([{name:'lattice_owner',value:'b'.repeat(64),url:'http://127.0.0.1:18746/',httpOnly:true,sameSite:'Strict'}]);
    await page.goto(`http://127.0.0.1:18746/#access=${'a'.repeat(64)}`);await page.locator('[data-tab=tab-enrollment]').click();
    await expect(page.locator('#module-master-state')).toContainText('active');
    await page.reload();await page.locator('[data-tab=tab-enrollment]').click();
    await expect(page.locator('#module-master-state')).toContainText('active');
    await page.locator('#authority-sync').click();
    await expect(page.locator('#module-feedback')).toContainText('Supervisor unavailable');
    await expect(page.locator('#module-master-state')).toContainText('active');
    await page.locator('#relay-consent').check();await page.locator('#relay-budget').fill('1000000');await page.locator('#module-relay-enable').click();
    await expect(page.locator('#module-relay-state')).toContainText('active');
    expect(mutations.at(-1).params.activation.forwarding_limit_bps).toBe(1000000);
    await page.locator('#module-relay-disable').click();await expect(page.locator('#module-relay-state')).toContainText('disabled');
    await page.getByText('Local Master administration',{exact:true}).click();
    await page.locator('#local-master-send').click();await expect(page.locator('#local-master-result')).toContainText('nodes');
    expect(mutations.at(-1).params.request.operation).toBe('fleet_inventory');
    await page.setViewportSize({width:1280,height:900});await page.screenshot({path:'test-results/modules-wide.png',fullPage:true});
    await page.setViewportSize({width:390,height:844});await page.screenshot({path:'test-results/modules-narrow.png',fullPage:true});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  }finally{child.kill();await new Promise(r=>child.once('exit',r));await new Promise(r=>ipc.close(r));await rm(dir,{recursive:true,force:true});}
});
