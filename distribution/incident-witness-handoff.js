'use strict';
// Read-only v4.7 handoff integrity and recipient receipt verification.
// Neither signature is release authority or proof of independent custody.
const {createHash,createPublicKey,verify}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.incident-witness-handoff.v1';
const RECEIPT='palaco.distribution.incident-witness-receipt.v1';
const MAX_AGE=86400000;
function handoffPayload(h){
 if(!h||typeof h!=='object'||Array.isArray(h)||
   h.schemaVersion!==VERSION||!NS.test(h.namespace||'')||
   !ID.test(h.senderId||'')||!ID.test(h.recipientId||'')||
   h.senderId===h.recipientId||!ID.test(h.nonce||'')||
   !Number.isSafeInteger(h.previousSequence)||h.previousSequence<1||
   !Number.isSafeInteger(h.nextSequence)||h.nextSequence!==h.previousSequence+1||
   !HEX.test(h.previousDigest||'')||!HEX.test(h.nextDigest||'')||
   h.previousDigest===h.nextDigest||
   !Number.isSafeInteger(h.issuedAtMs)||h.issuedAtMs<0||
   !Number.isSafeInteger(h.expiresAtMs)||h.expiresAtMs<=h.issuedAtMs||
   h.authorization!=='DENY'||h.go13!=='HOLD'||
   h.purpose!=='EVIDENCE_ONLY_NO_RELEASE')return null;
 return Buffer.from([
  'PALACO-INDUSTRIE-INCIDENT-WITNESS-HANDOFF-V1',VERSION,h.namespace,
  h.senderId,h.recipientId,h.nonce,String(h.previousSequence),
  h.previousDigest,String(h.nextSequence),h.nextDigest,
  String(h.issuedAtMs),String(h.expiresAtMs),
  h.authorization,h.go13,h.purpose,''
 ].join('\n'),'utf8');
}
function handoffDigest(h){
 const payload=handoffPayload(h);
 return payload?createHash('sha256').update(payload).digest('hex'):null;
}
function receiptPayload(receipt){
 if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)||
   receipt.schemaVersion!==RECEIPT||
   !NS.test(receipt.namespace||'')||!ID.test(receipt.recipientId||'')||
   !ID.test(receipt.nonce||'')||!HEX.test(receipt.handoffDigest||'')||
   !Number.isSafeInteger(receipt.acceptedAtMs)||receipt.acceptedAtMs<0||
   receipt.acknowledgement!=='EVIDENCE_RECEIVED_NO_AUTHORITY')
  return null;
 return Buffer.from([
  'PALACO-INDUSTRIE-INCIDENT-WITNESS-RECEIPT-V1',RECEIPT,
  receipt.namespace,receipt.recipientId,receipt.nonce,
  receipt.handoffDigest,String(receipt.acceptedAtMs),
  receipt.acknowledgement,''
 ].join('\n'),'utf8');
}
function denied(reason){
 return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
  mayAdvance:false,mayRestore:false,mayPublish:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,findings:Object.freeze([reason])});
}
function verifySignature(payload,signature,root){
 if(!payload||!signature||signature.algorithm!=='Ed25519'||
   !ID.test(signature.keyId||'')||signature.keyId!==root?.keyId||
   !SIG.test(signature.signature||'')||
   Buffer.from(signature.signature,'base64').toString('base64')!==signature.signature||
   !root||root.enabled!==true||root.revoked!==false||
   typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096)return false;
 try{
  const publicKey=createPublicKey(root.publicKeyPem);
  return publicKey.asymmetricKeyType==='ed25519'&&
   verify(null,payload,publicKey,Buffer.from(signature.signature,'base64'));
 }catch(_){return false;}
}
/**
 * External trusted anchor, sender and recipient identity roots MUST be
 * provisioned out of band. Signatures demonstrate possession, not custody.
 */
function verifyIncidentWitnessHandoff(handoff,senderSignature,receipt,receiptSignature,{
 namespace,previousSequence,previousDigest,nowMs,
 senderRoot,recipientRoot,maximumLifetimeMs=MAX_AGE
}={}){
 const payload=handoffPayload(handoff),ack=receiptPayload(receipt);
 if(!payload||!ack||handoff.namespace!==namespace||
   receipt.namespace!==namespace||receipt.recipientId!==handoff.recipientId||
   receipt.nonce!==handoff.nonce||receipt.handoffDigest!==handoffDigest(handoff))
  return denied('WITNESS_HANDOFF_FORMAT_OR_BINDING_INVALID');
 if(!Number.isSafeInteger(previousSequence)||previousSequence<1||
   !HEX.test(previousDigest||'')||!Number.isSafeInteger(nowMs)||nowMs<0||
   !Number.isSafeInteger(maximumLifetimeMs)||maximumLifetimeMs<1||
   maximumLifetimeMs>MAX_AGE)
  return denied('WITNESS_HANDOFF_ANCHOR_UNAVAILABLE');
 if(handoff.previousSequence!==previousSequence||
   handoff.previousDigest!==previousDigest)
  return denied('WITNESS_HANDOFF_REPLAY_OR_CHAIN_MISMATCH');
 if(nowMs<handoff.issuedAtMs||nowMs>=handoff.expiresAtMs||
    receipt.acceptedAtMs<handoff.issuedAtMs||
    receipt.acceptedAtMs>=handoff.expiresAtMs||
    receipt.acceptedAtMs>nowMs||
    handoff.expiresAtMs-handoff.issuedAtMs>maximumLifetimeMs)
  return denied('WITNESS_HANDOFF_EXPIRED');
 if(!senderRoot||senderRoot.identityId!==handoff.senderId||
   !recipientRoot||recipientRoot.identityId!==handoff.recipientId||
   senderRoot.identityId===recipientRoot.identityId||
   senderRoot.keyId===recipientRoot.keyId||
   senderRoot.publicKeyPem===recipientRoot.publicKeyPem)
  return denied('WITNESS_HANDOFF_ROOT_UNTRUSTED');
 if(!verifySignature(payload,senderSignature,senderRoot))
  return denied('WITNESS_HANDOFF_SENDER_SIGNATURE_INVALID');
 if(!verifySignature(ack,receiptSignature,recipientRoot))
  return denied('WITNESS_HANDOFF_RECEIPT_SIGNATURE_INVALID');
 return Object.freeze({
  readiness:'WITNESS_HANDOFF_RECEIPT_VERIFIED_NON_AUTHORIZING',
  authorization:'DENY',go13:'HOLD',
  handoffDigest:handoffDigest(handoff),nonce:handoff.nonce,
  sequence:handoff.nextSequence,digest:handoff.nextDigest,
  mayAdvance:false,mayRestore:false,mayPublish:false,mayReconcile:false,
  maySynchronize:false,mayInstall:false,findings:Object.freeze([])
 });
}
module.exports={VERSION,RECEIPT,handoffPayload,handoffDigest,
 receiptPayload,verifyIncidentWitnessHandoff};
