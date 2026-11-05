import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import {requestImage, type ImageReference} from '../src/image.js';
import type {GatewayClient} from '../src/index.js';
import type {Frame} from '../src/frames.js';

// These are post-verification transport fixtures, never hardware acceptance fixtures.
const data='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC';
const digest=createHash('sha256').update(Buffer.from(data,'base64')).digest('hex');
const request='a'.repeat(32);
function fixture(change: (result: any)=>void=()=>{}, offset=0) {
  const calls: string[]=[];
  const client={retain:()=>()=>{},upload:async()=>{calls.push('upload');return String(calls.length);},rpc:async(payload:any,frame?:(value:Frame)=>void,options?:{requestId?:string})=>{
    calls.push(payload.op);if(payload.op!=='image') return {};
    frame?.({protocol:'axiom-gateway-v2',request_id:options!.requestId!,sequence:0,kind:'image_chunk',data:{offset,data}});
    // Exact GeneratedImage serde field names, including RequestUsage's binding.
    const result={upstream_response_verified:true,image_data_length:data.length,image:{requestId:request,mimeType:'image/png',width:1,height:1,sha256:digest,sourceImageIds:payload.references.map((r:any)=>r.id),evidence:{state:'verified'},usage:{responseVerified:true,requestId:request}}};
    change(result);return result;
  }} as unknown as GatewayClient;
  return {client,calls};
}
const reference=(id:string):ImageReference=>({id,bytes:Uint8Array.from(Buffer.from(data,'base64')),mimeType:'image/png'});
test('five ordered references reach one request and the returned image matches its content digest',async()=>{
  const {client,calls}=fixture();const refs=['fifth','fourth','third','second','first'].map(reference);
  const image=await requestImage(client,{model:'direct:qwen3.8-27b',prompt:'synthetic',references:refs});
  assert.deepEqual(image.source_image_ids,refs.map(r=>r.id));assert.equal(image.data,data);
  assert.deepEqual(calls,['upload','upload','upload','upload','upload','image']);
});
test('six references are rejected before network work',async()=>{
  const {client,calls}=fixture();await assert.rejects(requestImage(client,{model:'model',prompt:'synthetic',references:Array.from({length:6},(_,i)=>reference(String(i)))}));assert.deepEqual(calls,[]);
});
test('wrong chunk offset, digest or source order cannot produce an accepted image',async()=>{
  for(const {client} of [fixture(()=>{},1),fixture(r=>r.image.sha256='0'.repeat(64)),fixture(r=>r.image.sourceImageIds.reverse()),fixture(r=>r.image.usage.requestId='b'.repeat(32)),fixture(r=>r.image.usage.responseVerified=false)]) {
    await assert.rejects(requestImage(client,{model:'model',prompt:'synthetic',references:[reference('one'),reference('two')]}));
  }
});
test('provisional image chunks are withheld until the RPC authenticates completion',async()=>{
  const original=fixture().client;let finish!:()=>void;let received!:()=>void;let returned=false;
  const ready=new Promise<void>(r=>{received=r;}),gate=new Promise<void>(r=>{finish=r;});
  const client={retain:()=>()=>{},rpc:async(...args:Parameters<GatewayClient['rpc']>)=>{const value=await original.rpc(...args);received();await gate;return value;}} as unknown as GatewayClient;
  const result=requestImage(client,{model:'model',prompt:'synthetic'}).then(value=>{returned=true;return value;});
  await ready;assert.equal(returned,false);finish();assert.equal((await result).sha256,digest);
});
