import {test,expect} from '@playwright/test';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('device owner explicitly accepts terms and selects one master',async({page})=>{
  const dir=await mkdtemp(join(tmpdir(),'lattice-owner-'));const socket=join(dir,'node.sock');
  let accepted=false,choice=null;const mutations=[];
  const ipc=net.createServer(client=>{let input='';client.on('data',chunk=>{input+=chunk;if(!input.includes('\n'))return;const r=JSON.parse(input);let reply;
    if(r.method==='get_participation'||r.method==='accept_participation'||r.method==='select_master'){
      if(r.method==='accept_participation'){accepted=true;mutations.push(r);}
      if(r.method==='select_master'){choice=r.params.control_id;mutations.push(r);}
      reply={type:'participation',data:{version:'fixture-terms',sha256:'fixture-digest',text:'Participation notice: public network, local policy and selected master.',accepted,master_choice:{control_id:choice,revision:choice?1:0}}};
    }else if(r.method==='get_master_catalog')reply={type:'master_catalog',data:['master-a','master-b'].map((id,i)=>({control_id:id,overlay_ipv4:`10.77.0.${i+4}`}))};
    else if(r.method==='get_setup_status')reply={type:'setup_status',data:{stage:'waiting_for_master',network_ready:true,workload_ready:false,error_code:'master_selection_required'}};
    else reply={type:'error',data:{message:'Not available in fixture'}};
    client.end(JSON.stringify(reply)+'\n');
  });});
  await new Promise(resolve=>ipc.listen(socket,resolve));
  const child=spawn(process.execPath,['web/node/server.mjs'],{cwd:new URL('../..',import.meta.url),env:{...process.env,LATTICE_SOCKET:socket,LATTICE_CONSOLE_TEST_MODE:'1',LATTICE_CONSOLE_TOKEN:'a'.repeat(64),LATTICE_NODE_WEB_PORT:'18745'},stdio:'ignore'});
  try{
    for(let i=0;i<50;i++){try{await fetch('http://127.0.0.1:18745/');break;}catch{await new Promise(r=>setTimeout(r,50));}}
    await page.goto(`http://127.0.0.1:18745/#access=${'a'.repeat(64)}`);
    await page.locator('[data-tab=tab-enrollment]').click();
    await expect(page.locator('#participation-accept')).toHaveCount(1);
    await page.locator('#participation-accept').scrollIntoViewIfNeeded();
    await expect(page.locator('#participation-accept')).toBeDisabled();
    await expect(page.locator('#statSharing')).toHaveText('CONSENT REQUIRED');
    await page.locator('#participation-check').check();await page.locator('#participation-accept').click();
    await expect(page.locator('#participation-status')).toContainText('Accepted');
    await page.locator('#owner-masters-refresh').click();
    await expect(page.locator('#owner-master')).toHaveValue('');
    await page.locator('#owner-master').selectOption('master-b');await page.locator('#owner-master-save').click();
    await expect(page.locator('#owner-master-status')).toContainText('master-b');
    expect(mutations.map(r=>r.method)).toEqual(['accept_participation','select_master']);
    expect(mutations[1].params.control_id).toBe('master-b');
    await page.screenshot({path:'test-results/node-owner.png',fullPage:true});
  }finally{child.kill();await new Promise(r=>child.once('exit',r));await new Promise(r=>ipc.close(r));await rm(dir,{recursive:true,force:true});}
});
