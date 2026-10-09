import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, issueToken, readToken, permissionsFor } from '../src/auth.js';
import { securityHeaders, rateLimit } from '../src/security.js';

test('password hashing and verification', () => {
  const hash = hashPassword('Strong-Test#123');
  assert.notEqual(hash, 'Strong-Test#123');
  assert.equal(verifyPassword('Strong-Test#123', hash), true);
  assert.equal(verifyPassword('Wrong-Test#123', hash), false);
});

test('signed token rejects tampering and accepts valid token', () => {
  const token = issueToken({id:42, employeeId:'TEST-42', role:'Data Entry'});
  assert.equal(readToken(token)?.sub, 42);
  const parts = token.split('.');
  parts[1] = parts[1].slice(0,-1) + (parts[1].endsWith('A') ? 'B' : 'A');
  assert.equal(readToken(parts.join('.')), null);
  assert.equal(readToken('garbage'), null);
});

test('role permissions are explicit', () => {
  assert.ok(permissionsFor('Data Entry').includes('enter_actuals'));
  assert.ok(!permissionsFor('Data Entry').includes('approve_actuals'));
  assert.ok(permissionsFor('Super Admin').includes('*'));
});

test('security headers are applied', () => {
  const headers = new Map();
  const req = {};
  const res = {setHeader:(k,v)=>headers.set(k,v)};
  securityHeaders(req,res,()=>{});
  assert.equal(headers.get('X-Content-Type-Options'),'nosniff');
  assert.equal(headers.get('X-Frame-Options'),'DENY');
});

test('rate limiter blocks after configured threshold', () => {
  const limiter = rateLimit({windowMs:60000,max:1,key:()=>`test-${Date.now()}-${Math.random()}`});
  // A fixed key is needed to test the second request.
  let count=0; const fixed=rateLimit({windowMs:60000,max:1,key:()=> 'fixed-security-test'});
  const next=()=>{count++};
  const response=()=>({setHeader(){},status(code){return {json(){assert.equal(code,429)}}}});
  fixed({}, {setHeader(){},status(){return {json(){}}}}, next);
  assert.equal(count,1);
  fixed({}, response(), next);
  assert.equal(count,1);
  void limiter;
});
