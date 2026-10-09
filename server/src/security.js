const buckets = new Map();

export function clientKey(req) {
  return String(req.ip || req.socket?.remoteAddress || 'unknown');
}

export function rateLimit({windowMs=15*60*1000,max=20,key=clientKey}={}) {
  return (req,res,next)=>{
    const now=Date.now(); const k=key(req); const existing=buckets.get(k);
    if(!existing || now-existing.startedAt>windowMs){buckets.set(k,{startedAt:now,count:1});return next();}
    existing.count += 1;
    if(existing.count>max){
      const retry=Math.max(1,Math.ceil((windowMs-(now-existing.startedAt))/1000));
      res.setHeader('Retry-After',String(retry));
      return res.status(429).json({error:'Too many requests. Please try again later.'});
    }
    next();
  };
}

export function securityHeaders(req,res,next){
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');
  if(process.env.NODE_ENV==='production') res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');
  next();
}
