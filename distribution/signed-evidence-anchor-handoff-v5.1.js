'use strict';
// v5.1 Signed transfer of a FULL v5.0 evidence-chain head.
// This is a non-authorizing independent custody *claim*, never release proof.
const {createHash,createPublicKey,verify}=require('node:crypto');
const NS=/^[a-z][a-z0-9._-]{2,79}$/;
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const HEX=/^[0-9a-f]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const VERSION='palaco.distribution.signed-evidence-anchor-handoff.v1';
const RECEIPT='palaco.distribution.signed-evidence-anchor-receipt.v1';
function valid(h){
 return h&&typeof h==='object'&&!Array.isArray(h)&&
 h.schemaVersion===VERSION&&NS.test(h.namespace||'')&&
 ID.test(h.senderId||'')&&ID.test(h.recipientId||'')&&
 h.senderId!==h.recipientId&&ID.test(h.nonce||'')&&
 Number.isSafeInteger(h.previousSequence)&&h.previousSequence>=2&&
 Number.isSafeInteger(h.nextSequence)&&h.nextSequence===h.previousSequence+1&&
 HEX.test(h.previousDigest||'')&&HEX.test(h.nextDigest||'')&&
 h.previousDigest!==h.nextDigest&&
 Number.isSafeInteger(h.issuedAtMs)&&h.issuedAtMs>=0&&
 Number.isSafeInteger(h.expiresAtMs)&&h.expiresAtMs>h.issuedAtMs&&
 h.authorization==='DENY'&&h.go13==='HOLD'&&
 h.purpose==='SIGNED_EVIDENCE_ANCHOR_ONLY';
}
function handoffBytes(h){
 return valid(h)?Buffer.from([
 'PALACO-INDUSTRIE-SIGNED-EVIDENCE-ANCHOR-HANDOFF-V1',
 VERSION,h.namespace,h.senderId,h.recipientId,h.nonce,
 String(h.previousSequence),h.previousDigest,String(h.nextSequence),
 h.nextDigest,String(h.issuedAtMs),String(h.expiresAtMs),
 h.authorization,h.go13,h.purpose,''
 ].join('\n')):null;
}
function handoffDigest(h){
 const p=handoffBytes(h);
 return p?createHash('sha256').update(p).digest('hex'):null;
}
function receiptBytes(r){
 if(!r||typeof r!=='object'||Array.isArray(r)||
 r.schemaVersion!==RECEIPT||!NS.test(r.namespace||'')||
 !ID.test(r.recipientId||'')||!ID.test(r.nonce||'')||
 !HEX.test(r.handoffDigest||'')||
 !Number.isSafeInteger(r.acceptedAtMs)||r.acceptedAtMs<0||
 r.acknowledgement!=='ANCHOR_RECEIVED_NO_AUTHORITY')return null;
 return Buffer.from(['PALACO-INDUSTRIE-SIGNED-EVIDENCE-ANCHOR-RECEIPT-V1',
 RECEIPT,r.namespace,r.recipientId,r.nonce,r.handoffDigest,
 String(r.acceptedAtMs),r.acknowledgement,''].join('\n'));
}
function denied(reason){return Object.freeze({
 readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([reason])
});}
function signed(bytes,signature,root){
 if(!bytes||!root||!signature||root.enabled!==true||
 root.revoked!==false||root.keyId!==signature.keyId||
 typeof root.publicKeyPem!=='string'||root.publicKeyPem.length>4096||
 signature.algorithm!=='Ed25519'||!SIG.test(signature.signature||'')||
 Buffer.from(signature.signature,'base64').toString('base64')!==signature.signature)
 return false;
 try{
  const key=createPublicKey(root.publicKeyPem);
  return key.asymmetricKeyType==='ed25519'&&
   verify(null,bytes,key,Buffer.from(signature.signature,'base64'));
 }catch(_){return false;}
}
function verifySignedEvidenceAnchorTransfer(h,sig,r,ack,{
 namespace,previousSequence,previousDigest,nowMs,senderRoot,recipientRoot,
 maxAgeMs=86400000
}={}){
 if(!handoffBytes(h)||!receiptBytes(r)||
 h.namespace!==namespace||r.namespace!==namespace||
 r.recipientId!==h.recipientId||r.nonce!==h.nonce||
 r.handoffDigest!==handoffDigest(h))
 return denied('EVIDENCE_ANCHOR_TRANSFER_BINDING_INVALID');
 if(!Number.isSafeInteger(previousSequence)||previousSequence<2||
 !HEX.test(previousDigest||'')||
 !Number.isSafeInteger(nowMs)||nowMs<0||
 !Number.isSafeInteger(maxAgeMs)||maxAgeMs<1||maxAgeMs>86400000)
 return denied('EVIDENCE_ANCHOR_TRUST_UNAVAILABLE');
 if(h.previousSequence!==previousSequence||h.previousDigest!==previousDigest)
 return denied('EVIDENCE_ANCHOR_REPLAY_OR_ROLLBACK');
 if(nowMs<h.issuedAtMs||nowMs>=h.expiresAtMs||
 h.expiresAtMs-h.issuedAtMs>maxAgeMs||
 r.acceptedAtMs<h.issuedAtMs||r.acceptedAtMs>nowMs||
 r.acceptedAtMs>=h.expiresAtMs)
 return denied('EVIDENCE_ANCHOR_TRANSFER_EXPIRED');
 if(!senderRoot||!recipientRoot||
 senderRoot.identityId!==h.senderId||
 recipientRoot.identityId!==h.recipientId||
 senderRoot.keyId===recipientRoot.keyId||
 senderRoot.publicKeyPem===recipientRoot.publicKeyPem)
 return denied('EVIDENCE_ANCHOR_ROOTS_INVALID');
 if(!signed(handoffBytes(h),sig,senderRoot))
 return denied('EVIDENCE_ANCHOR_SENDER_SIGNATURE_INVALID');
 if(!signed(receiptBytes(r),ack,recipientRoot))
 return denied('EVIDENCE_ANCHOR_RECEIPT_SIGNATURE_INVALID');
 return Object.freeze({
 readiness:'EVIDENCE_ANCHOR_TRANSFER_VERIFIED_NON_AUTHORIZING',
 authorization:'DENY',go13:'HOLD',sequence:h.nextSequence,
 digest:h.nextDigest,nonce:h.nonce,handoffDigest:handoffDigest(h),
 mayAdvance:false,mayRestore:false,mayReconcile:false,
 maySynchronize:false,mayInstall:false,mayPublish:false,
 findings:Object.freeze([])
 });
}
module.exports={VERSION,RECEIPT,handoffBytes,handoffDigest,receiptBytes,
 verifySignedEvidenceAnchorTransfer};
