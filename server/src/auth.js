import crypto from 'crypto';

export const ROLES = ['Super Admin','MIS/Admin','CEO/Director','Senior Management','Program Head','Program Officer','Data Entry'];

export const ROLE_PERMISSIONS = {
  'Super Admin': ['*'],
  'MIS/Admin': ['view_dashboard','view_programs','manage_programs','view_kpis','manage_kpis','manage_targets','enter_actuals','submit_actuals','approve_actuals','view_approvals','view_mis','view_reports','export_reports','manage_users','view_audit'],
  'CEO/Director': ['view_dashboard','view_programs','view_kpis','approve_actuals','view_approvals','view_mis','view_reports','export_reports','view_audit'],
  'Senior Management': ['view_dashboard','view_programs','view_kpis','approve_actuals','view_approvals','view_mis','view_reports','export_reports','view_audit'],
  'Program Head': ['view_dashboard','view_programs','manage_programs','view_kpis','manage_kpis','manage_targets','enter_actuals','submit_actuals','approve_actuals','view_approvals','view_mis','view_reports','export_reports'],
  'Program Officer': ['view_dashboard','view_programs','view_kpis','manage_kpis','manage_targets','enter_actuals','submit_actuals','view_mis'],
  'Data Entry': ['view_dashboard','view_programs','view_kpis','enter_actuals','submit_actuals']
};

const SECRET = String(process.env.AUTH_SECRET || '');
const TOKEN_TTL_SECONDS = Number(process.env.AUTH_TOKEN_TTL_SECONDS || 28800);
if (SECRET.length < 32 && process.env.NODE_ENV === 'production') {
  throw new Error('AUTH_SECRET must be at least 32 characters in production.');
}

const b64url = input => Buffer.from(input).toString('base64url');
const sign = value => crypto.createHmac('sha256', SECRET).update(value).digest('base64url');

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

export function verifyPassword(password, stored) {
  try {
    const [kind,salt,hash] = String(stored || '').split('$');
    if (kind !== 'scrypt' || !salt || !hash) return false;
    const candidate = crypto.scryptSync(String(password), salt, 64);
    const expected = Buffer.from(hash, 'hex');
    return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
  } catch { return false; }
}

export function issueToken(user) {
  const now = Math.floor(Date.now()/1000);
  const payload = {sub:user.id,employeeId:user.employeeId,role:user.role,iat:now,exp:now+TOKEN_TTL_SECONDS};
  const encoded = b64url(JSON.stringify(payload));
  return `${encoded}.${sign(encoded)}`;
}

export function readToken(token) {
  try {
    if (!token || !token.includes('.')) return null;
    const [encoded,signature] = token.split('.');
    if (!encoded || !signature) return null;
    const expected = sign(encoded);
    const a=Buffer.from(signature); const b=Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) return null;
    const payload = JSON.parse(Buffer.from(encoded,'base64url').toString('utf8'));
    if (!payload.sub || !payload.exp || payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

export function permissionsFor(role){ return ROLE_PERMISSIONS[role] || []; }
export function hasPermission(role, permission){ const p=permissionsFor(role); return p.includes('*') || p.includes(permission); }
