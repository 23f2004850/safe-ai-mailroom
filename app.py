"""Safe AI Mailroom GA5 v2. Single HTTPS endpoint; no secrets in its URL."""
import base64
import binascii
import hashlib
import json
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from policy import ACTIONS, DecisionError, decide, validate_decision
from store import RedisStore, StorageError

from dotenv import load_dotenv
load_dotenv()

PROFILE = 'ga5-mailroom-action-gate/v2'
MAX_BODY = 8 * 1024 * 1024
REDIS = RedisStore()
app = FastAPI()


def canonical(value):
    """Recursively key-sorted, compact UTF-8 JSON. Never change array order."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def need(test, reason='Invalid request'):
    if not test:
        raise HTTPException(status_code=422, detail=reason)


def nonempty_str(value):
    return isinstance(value, str) and bool(value)


def is_fields(obj, required):
    return isinstance(obj, dict) and set(required) <= set(obj)


def validate_propose(doc):
    need(is_fields(doc, ['profile', 'operation', 'evaluationId', 'receiptVerifier',
                          'corpus', 'allowedActions', 'dossiers']))
    need(doc['profile'] == PROFILE and doc['operation'] == 'propose')
    need(nonempty_str(doc['evaluationId']) and len(doc['evaluationId']) < 512)
    verifier = doc['receiptVerifier']
    need(is_fields(verifier, ['algorithm', 'publicKeyJwk']) and
         verifier['algorithm'] == 'Ed25519')
    jwk = verifier['publicKeyJwk']
    need(is_fields(jwk, ['kty','crv','x']) and jwk['kty'] == 'OKP' and
         jwk['crv'] == 'Ed25519' and nonempty_str(jwk['x']))
    try:
        x = jwk['x']
        need(bool(re.fullmatch(r'[A-Za-z0-9_-]{43}', x)))
        key_bytes = base64.urlsafe_b64decode(x + '=')
        Ed25519PublicKey.from_public_bytes(key_bytes)
    except (ValueError, binascii.Error):
        need(False, 'Invalid Ed25519 public key')
    corpus = doc['corpus']
    need(is_fields(corpus, ['coreId','auditId','stableCount','freshCount']))
    need(nonempty_str(corpus['coreId']) and nonempty_str(corpus['auditId']))
    need(type(corpus['stableCount']) is int and type(corpus['freshCount']) is int)
    need(isinstance(doc['allowedActions'], list) and
         len(doc['allowedActions']) == len(ACTIONS) and
         all(isinstance(a, str) for a in doc['allowedActions']) and
         set(doc['allowedActions']) == set(ACTIONS))
    dossiers = doc['dossiers']
    need(isinstance(dossiers, list) and 1 <= len(dossiers) <= 100)
    need(len(dossiers) == corpus['stableCount'] + corpus['freshCount'])
    ids = []
    for dossier in dossiers:
        need(is_fields(dossier, ['dossierId','partition','receivedAt',
                                  'mailbox','objective','sources']))
        need(all(isinstance(dossier[k], str) for k in (
             'dossierId','partition','receivedAt','mailbox','objective')))
        need(nonempty_str(dossier['dossierId']) and nonempty_str(dossier['mailbox']))
        need(dossier['partition'] in ('stable_core', 'fresh_audit'))
        need(isinstance(dossier['sources'], list) and len(dossier['sources']) <= 100)
        ids.append(dossier['dossierId'])
        line_ids = []
        for source in dossier['sources']:
            need(is_fields(source, ['sourceId','kind','provenance','title','lines']))
            need(all(isinstance(source[k], str) for k in (
                 'sourceId','kind','provenance','title')))
            need(isinstance(source['lines'], list) and len(source['lines']) <= 3000)
            for line in source['lines']:
                need(is_fields(line, ['lineId','text']) and
                     nonempty_str(line['lineId']) and isinstance(line['text'], str))
                line_ids.append(line['lineId'])
        need(len(line_ids) > 0 and len(set(line_ids)) == len(line_ids),
             'Missing or duplicate dossier lines')
    need(len(set(ids)) == len(ids), 'Duplicate dossier IDs')
    need(sum(d['partition']=='stable_core' for d in dossiers) == corpus['stableCount'])
    need(sum(d['partition']=='fresh_audit' for d in dossiers) == corpus['freshCount'])


def validate_commit(doc):
    need(is_fields(doc, ['profile','operation','evaluationId','inputDigest','receipts']))
    need(doc['profile'] == PROFILE and doc['operation'] == 'commit')
    need(nonempty_str(doc['evaluationId']))
    need(isinstance(doc['inputDigest'], str) and
         bool(re.fullmatch(r'[a-f0-9]{64}', doc['inputDigest'])))
    need(isinstance(doc['receipts'], list) and 1 <= len(doc['receipts']) <= 100)
    seen_ids, seen_calls, seen_dossiers = set(), set(), set()
    required = {'dossierId','callId','action','accepted','proposalDigest',
                'receiptId','receiptSignature'}
    for r in doc['receipts']:
        need(isinstance(r, dict) and set(r) == required, 'Invalid receipt schema')
        need(all(nonempty_str(r[k]) for k in required - {'accepted'}))
        need(type(r['accepted']) is bool and r['action'] in ACTIONS)
        need(bool(re.fullmatch(r'[a-f0-9]{64}', r['proposalDigest'])))
        need(bool(re.fullmatch(r'[A-Za-z0-9._:-]{12,128}', r['callId'])))
        need(r['receiptId'] not in seen_ids and r['callId'] not in seen_calls
             and r['dossierId'] not in seen_dossiers, 'Duplicate receipt')
        seen_ids.add(r['receiptId']); seen_calls.add(r['callId'])
        seen_dossiers.add(r['dossierId'])


def normalized_proposal(proposal):
    # Exactly the 6 digest fields; evidence sorted, target always present.
    return {'dossierId':proposal['dossierId'], 'callId':proposal['callId'],
            'action':proposal['action'], 'target':proposal.get('target'),
            'payload':proposal['payload'],
            'evidence': sorted(proposal['evidence'])}


def cache_key(dossier):
    return 'ga5:dossier:' + sha({'id':dossier['dossierId'], 'body':dossier})


def assign_proposal(dossier, ai_result):
    validated = validate_decision(dossier, dict(ai_result))
    fingerprint = sha({'id':dossier['dossierId'],'body':dossier})
    call_id = 'mail_' + fingerprint[:40]
    return {'dossierId':dossier['dossierId'], 'callId':call_id,
            'action':validated['action'], 'target':validated['target'],
            'payload':validated['payload'], 'evidence':validated['evidence']}


def verify_receipts(receipts, eval_id, digest, proposal_list, jwk):
    # We first verify all cryptographic signatures and scope, and ONLY THEN store.
    proposals = {p['dossierId']:p for p in proposal_list}
    if len(receipts) != len(proposals):
        raise HTTPException(status_code=422, detail='Receipt count mismatch')
    try:
        public_key_bytes = base64.urlsafe_b64decode(jwk['x'] + '=')
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except (ValueError, binascii.Error):
        raise HTTPException(status_code=422, detail='Invalid stored verification key')
    verified = []
    for r in receipts:
        prop = proposals.get(r['dossierId'])
        if (prop is None or r['callId'] != prop['callId'] or
            r['action'] != prop['action'] or
            r['proposalDigest'] != sha(normalized_proposal(prop))):
            raise HTTPException(status_code=409, detail='Receipt does not match proposal')
        inner = {k:v for k,v in r.items() if k != 'receiptSignature'}
        signed_message = {'profile':PROFILE, 'evaluationId':eval_id,
                          'inputDigest':digest, 'receipt':inner}
        try:
            signature = base64.b64decode(r['receiptSignature'], validate=True)
            if len(signature) != 64:
                raise ValueError('Wrong signature size')
            public_key.verify(signature, canonical(signed_message))
        except (InvalidSignature, ValueError, binascii.Error):
            raise HTTPException(status_code=422, detail='Invalid signed receipt')
        verified.append(r)
    return verified


@app.get('/')
def health():
    return {'service':'mailroom','status':'ready', 'postTo':'/mailroom'}


@app.post('/mailroom')
async def mailroom(request: Request):
    if request.headers.get('content-length','').isdigit() and int(request.headers['content-length']) > MAX_BODY:
        raise HTTPException(status_code=413, detail='Request too large')
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail='Request too large')
    try:
        def reject_constant(x):
            raise ValueError('nonstandard JSON primitive')
        doc = json.loads(raw, parse_constant=reject_constant)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail='Invalid JSON')
    need(isinstance(doc, dict))
    operation = doc.get('operation')
    if operation == 'propose':
        validate_propose(doc)
    elif operation == 'commit':
        validate_commit(doc)
    else:
        raise HTTPException(status_code=400, detail='Unknown operation')
    try:
        if operation == 'propose':
            answer = make_proposal(doc)
        else:
            answer = make_commit(doc)
        if len(canonical(answer)) > 512 * 1024:
            raise HTTPException(status_code=503, detail='Response exceeds limit')
        return JSONResponse(content=answer, status_code=200)
    except StorageError as exc:
        cause = exc.__cause__
        response = getattr(cause, "response", None)
        http_status = getattr(response, "status_code", None)

        print(
            "UPSTASH_DIAG:",
            "error_type=", type(exc).__name__,
            "cause_type=", type(cause).__name__ if cause else "none",
            "http_status=", http_status,
            flush=True
        )

        raise HTTPException(
            status_code=503,
            detail="Persistent database unavailable"
        )
    except DecisionError:
        raise HTTPException(status_code=503, detail='Model decisions unavailable or invalid')


def make_proposal(doc):
    evaluation_id = doc['evaluationId']
    input_digest = sha(doc['dossiers'])
    request_fingerprint = sha(doc)
    key = 'ga5:eval:' + hashlib.sha256(evaluation_id.encode()).hexdigest()
    existing = REDIS.get(key)
    if existing is not None:
        if existing['requestFingerprint'] != request_fingerprint:
            raise HTTPException(status_code=409, detail='Evaluation content conflict')
        if existing['phase'] in ('ready','completed'):
            return existing['proposalResponse']
        raise HTTPException(status_code=503, detail='Evaluation currently processing')

    reservation = {'phase':'processing', 'requestFingerprint':request_fingerprint,
                   'inputDigest':input_digest}
    if not REDIS.set(key, reservation, nx=True, ttl=115):
        existing = REDIS.get(key)
        if existing and existing['requestFingerprint'] != request_fingerprint:
            raise HTTPException(status_code=409, detail='Evaluation content conflict')
        if existing and existing['phase'] in ('ready','completed'):
            return existing['proposalResponse']
        raise HTTPException(status_code=503, detail='Evaluation currently processing')
    try:
        keys = [cache_key(d) for d in doc['dossiers']]
        stored = REDIS.mget(keys)
        missing_indices = [i for i,val in enumerate(stored) if val is None]
        if missing_indices:
            start = time.monotonic()
            new = decide([doc['dossiers'][i] for i in missing_indices], start+44)
            entries = [(keys[i], assign_proposal(doc['dossiers'][i], raw_decision))
                       for i,raw_decision in zip(missing_indices, new)]
            # NX preserves the FIRST complete proposal if two different evaluations race.
            REDIS.set_many_nx(entries)
            stored = REDIS.mget(keys)
        if any(p is None for p in stored):
            raise StorageError('Dossier cache write missing')
        for dossier, prop in zip(doc['dossiers'], stored):
            if prop['dossierId'] != dossier['dossierId'] or prop['callId'] != (
                    'mail_' + sha({'id':dossier['dossierId'], 'body':dossier})[:40]):
                raise StorageError('Corrupted cached proposal')
            validate_decision(dossier, {k:prop[k] for k in
                ('dossierId','action','target','payload','evidence')})
        response = {'profile':PROFILE,'evaluationId':evaluation_id,
                    'status':'awaiting_receipts','inputDigest':input_digest,
                    'proposals':stored}
        ready = {'phase':'ready', 'requestFingerprint':request_fingerprint,
                 'inputDigest':input_digest,
                 'verifierJwk':doc['receiptVerifier']['publicKeyJwk'],
                 'proposals':stored, 'proposalResponse':response}
        if not REDIS.cas(key, reservation, ready):
            raise StorageError('Evaluation reservation was lost')
        return response
    except Exception:
        try:
            REDIS.release(key, reservation)
        except StorageError:
            pass
        raise


def make_commit(doc):
    evaluation_id = doc['evaluationId']
    key = 'ga5:eval:' + hashlib.sha256(evaluation_id.encode()).hexdigest()
    existing = REDIS.get(key)
    if existing is None:
        raise HTTPException(status_code=409, detail='Unknown evaluation')
    if doc['inputDigest'] != existing['inputDigest']:
        raise HTTPException(status_code=409, detail='Input digest conflict')
    commit_fingerprint = sha(doc)
    if existing['phase'] == 'completed':
        if commit_fingerprint != existing['commitFingerprint']:
            raise HTTPException(status_code=409, detail='Changed commit replay')
        return existing['commitResponse']
    if existing['phase'] != 'ready':
        raise HTTPException(status_code=409, detail='Propose not finished')
    verified = verify_receipts(doc['receipts'], evaluation_id, doc['inputDigest'],
                               existing['proposals'], existing['verifierJwk'])
    # Receipt ordering may differ from proposal ordering; return outcomes in proposal order.
    receipts_by_dossier = {r['dossierId']:r for r in verified}
    outcomes = []
    for p in existing['proposals']:
        receipt = receipts_by_dossier[p['dossierId']]
        outcomes.append({'dossierId':p['dossierId'],'callId':p['callId'],
                         'action':p['action'], 'proposalDigest':receipt['proposalDigest'],
                         'receiptId':receipt['receiptId'],
                         'status':'executed' if receipt['accepted'] else 'rejected'})
    response = {'profile':PROFILE, 'evaluationId':evaluation_id,
                'status':'completed','inputDigest':doc['inputDigest'],
                'outcomes':outcomes}
    complete = dict(existing, phase='completed',
                    commitFingerprint=commit_fingerprint,
                    verifiedReceipts=verified, commitResponse=response)
    # ONE atomic state transition, after ALL receipts passed verification.
    if not REDIS.cas(key, existing, complete):
        latest = REDIS.get(key)
        if latest and latest.get('phase') == 'completed' and latest.get('commitFingerprint') == commit_fingerprint:
            return latest['commitResponse']
        raise HTTPException(status_code=409, detail='Concurrent commit conflict')
    return response
