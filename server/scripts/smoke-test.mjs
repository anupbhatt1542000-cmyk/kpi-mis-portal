const base=(process.argv[2]||process.env.API_URL||'http://127.0.0.1:5000').replace(/\/$/,'');
for (const path of ['/api/health','/api/health/ready']) {
  const r=await fetch(base+path);
  const text=await r.text();
  if(!r.ok) throw new Error(`${path} returned ${r.status}: ${text}`);
  console.log(`${path}: OK ${text}`);
}
console.log('Aasraa Trust MIS smoke test passed.');
