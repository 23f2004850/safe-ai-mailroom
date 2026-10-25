import base64
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import app


class FakeRedis:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return copy.deepcopy(self.data.get(key))

    def mget(self, keys):
        return [self.get(k) for k in keys]

    def set(self, key, value, nx=False, ttl=None):
        if nx and key in self.data:
            return False
        self.data[key] = copy.deepcopy(value)
        return True

    def set_many_nx(self, entries):
        for k,v in entries:
            self.set(k,v,nx=True)

    def cas(self, key, old, new):
        if self.data.get(key) != old:
            return False
        self.data[key] = copy.deepcopy(new)
        return True

    def release(self, key, reservation):
        if self.data.get(key) == reservation:
            del self.data[key]


@pytest.fixture
def env(monkeypatch):
    storage = FakeRedis()
    monkeypatch.setattr(app, 'REDIS', storage)
    calls = []

    def fake_ai(dossiers, deadline):
        calls.extend(d['dossierId'] for d in dossiers)
        return [
            {'dossierId':d['dossierId'], 'action':'no_action', 'target':None,
             'payload':{'reasonCode':'INFORMATIONAL','referenceId':'ref-007'},
             'evidence':['L1']}
            for d in dossiers
        ]

    monkeypatch.setattr(app, 'decide', fake_ai)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    jwk = {'kty':'OKP', 'crv':'Ed25519',
           'x':base64.urlsafe_b64encode(public).decode().rstrip('=')}
    request = {
        'profile': app.PROFILE, 'operation':'propose', 'evaluationId':'evaluation-one',
        'receiptVerifier':{'algorithm':'Ed25519','publicKeyJwk':jwk},
        'corpus':{'coreId':'core','auditId':'audit-1',
                  'stableCount':1, 'freshCount':0},
        'allowedActions':list(app.ACTIONS),
        'dossiers':[{
          'dossierId':'d-1','partition':'stable_core','receivedAt':'2026-10-25T12:00:00Z',
          'mailbox':'support', 'objective':'Process an informational note',
          'sources':[{'sourceId':'s-1','kind':'internal','provenance':'system',
                      'title':'status notice', 'lines':[{'lineId':'L1',
                            'text':'Reference ref-007; informational only.'}]}]
        }]
    }
    return TestClient(app.app), request, private, calls, storage


def make_receipt(private, propose_body, accepted=True):
    p = propose_body['proposals'][0]
    receipt = {'dossierId':p['dossierId'],'callId':p['callId'],'action':p['action'],
               'accepted':accepted,'proposalDigest':app.sha(app.normalized_proposal(p)),
               'receiptId':'random-nonce-123'}
    signed = {'profile':app.PROFILE,
              'evaluationId':propose_body['evaluationId'],
              'inputDigest':propose_body['inputDigest'], 'receipt':receipt}
    receipt['receiptSignature'] = base64.b64encode(
        private.sign(app.canonical(signed))).decode()
    return {'profile':app.PROFILE, 'operation':'commit',
            'evaluationId':propose_body['evaluationId'],
            'inputDigest':propose_body['inputDigest'], 'receipts':[receipt]}


def test_full_acceptance_and_replay(env):
    client, req, private, calls, _ = env
    result = client.post('/mailroom',json=req)
    assert result.status_code == 200, result.text
    proposal = result.json()
    assert proposal['status'] == 'awaiting_receipts'
    assert proposal['inputDigest'] == app.sha(req['dossiers'])
    assert len(calls) == 1
    assert client.post('/mailroom',json=req).json() == proposal
    assert len(calls) == 1, 'Exact propose replay must never re-run AI'
    commit = make_receipt(private,proposal)
    receipt_response = client.post('/mailroom',json=commit)
    assert receipt_response.status_code == 200, receipt_response.text
    terminal = receipt_response.json()
    assert terminal['status'] == 'completed'
    assert terminal['outcomes'][0]['status'] == 'executed'
    assert client.post('/mailroom',json=commit).json() == terminal
    assert client.post('/mailroom',json=req).json() == proposal
    assert len(calls) == 1


def test_rejected_receipt(env):
    client, req, private, _, _ = env
    proposal = client.post('/mailroom',json=req).json()
    commit = make_receipt(private, proposal, accepted=False)
    result = client.post('/mailroom',json=commit)
    assert result.status_code == 200
    assert result.json()['outcomes'][0]['status'] == 'rejected'


def test_tampered_signature_is_atomic(env):
    client, req, private, _, _ = env
    proposal = client.post('/mailroom',json=req).json()
    commit = make_receipt(private, proposal)
    commit['receipts'][0]['accepted'] = False   # signature MUST now fail
    invalid = client.post('/mailroom',json=commit)
    assert invalid.status_code in (400,422), invalid.text
    # Failure cannot make the evaluation completed.
    valid = make_receipt(private, proposal)
    assert client.post('/mailroom',json=valid).status_code == 200
    invalid_replay = client.post('/mailroom',json=commit)
    assert invalid_replay.status_code == 409


def test_changed_propose_conflict_and_core_cache(env):
    client, req, private, calls, _ = env
    first = client.post('/mailroom',json=req)
    assert first.status_code == 200
    modified = copy.deepcopy(req)
    modified['dossiers'][0]['objective'] = 'DIFFERENT CONTENT'
    assert client.post('/mailroom',json=modified).status_code == 409
    next_eval = copy.deepcopy(req)
    next_eval['evaluationId'] = 'evaluation-two'
    next_eval['corpus']['auditId'] = 'audit-2'
    second = client.post('/mailroom',json=next_eval)
    assert second.status_code == 200
    assert second.json()['proposals'] == first.json()['proposals']
    assert len(calls) == 1, 'Same dossier across evals must use durable cache'


def test_invalid_requests_no_model_work(env):
    client, req, _, calls, _ = env
    assert client.post('/mailroom',json={'operation':'erase_all'}).status_code == 400
    bad = copy.deepcopy(req)
    bad['dossiers'].append(copy.deepcopy(bad['dossiers'][0]))
    bad['corpus']['stableCount'] = 2
    assert client.post('/mailroom',json=bad).status_code == 422
    assert calls == []


def test_unknown_commit_and_changed_valid_commit(env):
    client, req, private, _, _ = env
    prop = client.post('/mailroom',json=req).json()
    commit = make_receipt(private, prop)
    bad = copy.deepcopy(commit)
    bad['evaluationId'] = 'other-eval'
    assert client.post('/mailroom',json=bad).status_code == 409
    assert client.post('/mailroom',json=commit).status_code == 200
    different = copy.deepcopy(commit)
    different['receipts'][0]['receiptId'] = 'another-nonce'
    assert client.post('/mailroom',json=different).status_code == 409


def test_canonical_digest():
    a = {'b':[{'z':2,'a':True}], 'a':'Hello'}
    b = {'a':'Hello','b':[{'a':True,'z':2}]}
    assert app.sha(a) == app.sha(b)
    assert app.canonical(b) == b'{"a":"Hello","b":[{"a":true,"z":2}]}'


def test_two_receipts_are_all_or_nothing(env):
    client, req, private, _, storage = env
    req['dossiers'].append(copy.deepcopy(req['dossiers'][0]))
    req['dossiers'][1]['dossierId'] = 'd-2'
    req['dossiers'][1]['partition'] = 'fresh_audit'
    req['corpus']['freshCount'] = 1
    proposed_response = client.post('/mailroom',json=req)
    assert proposed_response.status_code == 200, proposed_response.text
    proposed = proposed_response.json()
    receipts = []
    for i, p in enumerate(proposed['proposals']):
        r = {'dossierId':p['dossierId'], 'callId':p['callId'],
             'action':p['action'], 'accepted':i == 0,
             'proposalDigest':app.sha(app.normalized_proposal(p)),
             'receiptId':f'nonce-{i}'}
        body = {'profile':app.PROFILE,'evaluationId':proposed['evaluationId'],
                'inputDigest':proposed['inputDigest'],'receipt':r}
        r['receiptSignature'] = base64.b64encode(private.sign(app.canonical(body))).decode()
        receipts.append(r)
    commit = {'profile':app.PROFILE, 'operation':'commit',
              'evaluationId':proposed['evaluationId'],
              'inputDigest':proposed['inputDigest'], 'receipts':receipts}
    invalid = copy.deepcopy(commit)
    invalid['receipts'][1]['receiptSignature'] = invalid['receipts'][0]['receiptSignature']
    assert client.post('/mailroom',json=invalid).status_code == 422
    import hashlib
    eval_key = 'ga5:eval:' + hashlib.sha256(req['evaluationId'].encode()).hexdigest()
    assert storage.get(eval_key)['phase'] == 'ready'
    good = client.post('/mailroom',json=commit)
    assert good.status_code == 200, good.text
    assert [o['status'] for o in good.json()['outcomes']] == ['executed','rejected']


def test_unhashable_action_list_is_validation_error(env):
    client, req, _, calls, _ = env
    req['allowedActions'][0] = {'bad': 'object'}
    result = client.post('/mailroom',json=req)
    assert result.status_code == 422
    assert not calls
