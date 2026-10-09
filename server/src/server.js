import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import { Op } from 'sequelize';
import { securityHeaders, rateLimit, clientKey } from './security.js';
import XLSX from 'xlsx';
import PDFDocument from 'pdfkit';
import { initDb, sequelize, Program, KPI, Target, Actual, User, AuditLog, ProgramMember, ApprovalHistory, Notification } from './db.js';
import { ROLES, permissionsFor, hasPermission, hashPassword, verifyPassword, issueToken, readToken } from './auth.js';

const app=express();
const allowedOrigins=String(process.env.CORS_ORIGIN||'http://localhost:5173').split(',').map(x=>x.trim()).filter(Boolean);
app.set('trust proxy', process.env.TRUST_PROXY==='true' ? 1 : false);
app.use(securityHeaders);
app.use(cors({origin:(origin,cb)=>{if(!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return cb(null,true); return cb(new Error('CORS origin not allowed'));},credentials:false}));
app.use(express.json({limit:'2mb'}));
app.use(express.urlencoded({extended:false,limit:'100kb'}));
const months=['April','May','June','July','August','September','October','November','December','January','February','March'];
const number=v=>Number.isFinite(Number(v))?Number(v):0;
const clean=v=>v===''||v===undefined?null:v;
const strongPassword=v=>{const p=String(v||'');return p.length>=10&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/[0-9]/.test(p)&&/[^A-Za-z0-9]/.test(p);};
const publicUser=u=>({id:u.id,employeeId:u.employeeId,name:u.name,email:u.email,role:u.role,department:u.department,designation:u.designation,active:u.active,mustChangePassword:u.mustChangePassword,lastLoginAt:u.lastLoginAt,permissions:permissionsFor(u.role)});

async function auth(req,res,next){
  const raw=req.headers.authorization||''; const token=raw.startsWith('Bearer ')?raw.slice(7):''; const payload=readToken(token);
  if(!payload)return res.status(401).json({error:'Authentication required'});
  const user=await User.findByPk(payload.sub); if(!user||!user.active)return res.status(401).json({error:'Account is inactive or unavailable'});
  req.user=user; next();
}
const permit=permission=>(req,res,next)=>hasPermission(req.user?.role,permission)?next():res.status(403).json({error:'You do not have permission to perform this action'});
const audit=async(user,action,entity,recordId,details={})=>AuditLog.create({userId:user?.id||null,userName:user?.name||user?.employeeId||'System',action,entity,recordId:String(recordId||''),details});
const notify=async(userIds,type,title,message,entity='',recordId='')=>{const ids=[...new Set((userIds||[]).map(Number).filter(Boolean))];if(!ids.length)return;await Notification.bulkCreate(ids.map(userId=>({userId,type,title,message,entity,recordId:String(recordId||'')})))};
const usersForProgram=async programId=>{const members=await ProgramMember.findAll({where:{programId,active:true},attributes:['userId'],raw:true});const global=await User.findAll({where:{role:['MIS/Admin','CEO/Director','Senior Management','Super Admin'],active:true},attributes:['id'],raw:true});return [...new Set([...members.map(x=>x.userId),...global.map(x=>x.id)])]};
const isGlobalScope=user=>['Super Admin','MIS/Admin','CEO/Director','Senior Management'].includes(user?.role);
const isReviewer=user=>hasPermission(user?.role,'approve_actuals');
const assignedProgramIds=async user=>isGlobalScope(user)?null:(await ProgramMember.findAll({where:{userId:user.id,active:true},attributes:['programId'],raw:true})).map(x=>x.programId);
const canAccessProgram=async(user,programId)=>{if(isGlobalScope(user))return true; const ids=await assignedProgramIds(user); return ids.includes(Number(programId));};
const canAccessKpi=async(user,kpiId)=>{const k=await KPI.findByPk(kpiId,{attributes:['id','programId']}); return Boolean(k&&await canAccessProgram(user,k.programId));};
const syncProgramAssignments=async(userId,programIds=[])=>{await ProgramMember.destroy({where:{userId}});const ids=[...new Set((programIds||[]).map(Number).filter(Boolean))];if(ids.length)await ProgramMember.bulkCreate(ids.map(programId=>({userId,programId,assignmentRole:'Member',active:true})));};

app.get('/api/health',(_req,res)=>res.json({ok:true,service:'Aasraa Trust KPI/MIS Portal',version:'1.0.0'}));
app.get('/api/health/ready',async(_req,res)=>{try{await sequelize.authenticate();res.json({ok:true,ready:true});}catch(e){res.status(503).json({ok:false,ready:false});}});
const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,key:clientKey});
app.post('/api/auth/login',loginLimiter,async(req,res)=>{
  const employeeId=String(req.body.employeeId||'').trim(); const password=String(req.body.password||'');
  if(!employeeId||!password)return res.status(400).json({error:'Employee ID and password are required'});
  const user=await User.findOne({where:{employeeId}});
  if(!user||!user.active||!verifyPassword(password,user.passwordHash))return res.status(401).json({error:'Invalid Employee ID or password'});
  user.lastLoginAt=new Date(); await user.save(); await audit(user,'LOGIN','User',user.id,{employeeId:user.employeeId});
  res.json({token:issueToken(user),user:publicUser(user)});
});
app.get('/api/auth/me',auth,(req,res)=>res.json(publicUser(req.user)));
app.post('/api/auth/change-password',auth,async(req,res)=>{
  const {currentPassword,newPassword}=req.body;
  if(!verifyPassword(currentPassword,req.user.passwordHash))return res.status(400).json({error:'Current password is incorrect'});
  if(!strongPassword(newPassword))return res.status(400).json({error:'Password must be at least 10 characters and include upper, lower, number and special character'});
  req.user.passwordHash=hashPassword(newPassword); req.user.mustChangePassword=false; await req.user.save(); await audit(req.user,'CHANGE_PASSWORD','User',req.user.id); res.json({ok:true});
});

app.use('/api',auth);
app.use('/api', (req,res,next)=>{
  if(req.user?.mustChangePassword && !req.path.startsWith('/auth/me') && !req.path.startsWith('/auth/change-password')) return res.status(403).json({error:'Password change required before continuing',code:'PASSWORD_CHANGE_REQUIRED'});
  next();
});

app.get('/api/programs',permit('view_programs'),async(req,res)=>{const where={};if(!isGlobalScope(req.user)){const ids=await assignedProgramIds(req.user);where.id=ids.length?ids:[-1];}const rows=await Program.findAll({where,include:[{model:KPI,include:[Target]}],order:[['id','ASC']]});res.json(rows);});
app.get('/api/programs/:id/members',permit('view_programs'),async(req,res)=>{if(!await canAccessProgram(req.user,req.params.id))return res.status(403).json({error:'You are not assigned to this program'});const members=await ProgramMember.findAll({where:{programId:req.params.id,active:true},include:[{model:User,attributes:['id','employeeId','name','role','department','designation','active']}],order:[['id','ASC']]});res.json(members.map(m=>({...m.toJSON(),user:m.User})));});
app.post('/api/programs',permit('manage_programs'),async(req,res)=>{const {programName,fluxxId,startDate,endDate,financialYear,status='Active'}=req.body;if(!programName||!financialYear)return res.status(400).json({error:'Program name and financial year are required'});const program=await Program.create({programName,fluxxId:clean(fluxxId),startDate:clean(startDate),endDate:clean(endDate),financialYear,status});if(!isGlobalScope(req.user))await ProgramMember.create({userId:req.user.id,programId:program.id,assignmentRole:req.user.role,active:true});await audit(req.user,'CREATE','Program',program.id,{programName});res.status(201).json(program);});
app.put('/api/programs/:id',permit('manage_programs'),async(req,res)=>{if(!await canAccessProgram(req.user,req.params.id))return res.status(403).json({error:'You are not assigned to this program'});const program=await Program.findByPk(req.params.id);if(!program)return res.status(404).json({error:'Program not found'});['programName','fluxxId','startDate','endDate','financialYear','status'].forEach(k=>{if(req.body[k]!==undefined)program[k]=clean(req.body[k]);});await program.save();await audit(req.user,'UPDATE','Program',program.id,req.body);res.json(program);});

app.get('/api/kpis',permit('view_kpis'),async(req,res)=>{const where={};if(req.query.programId){if(!await canAccessProgram(req.user,req.query.programId))return res.status(403).json({error:'You are not assigned to this program'});where.programId=req.query.programId;}else if(!isGlobalScope(req.user)){const ids=await assignedProgramIds(req.user);where.programId=ids.length?ids:[-1];}if(req.query.type)where.kpiType=req.query.type;res.json(await KPI.findAll({where,include:[Target],order:[['kpiType','ASC'],['id','ASC']]}));});
app.post('/api/kpis',permit('manage_kpis'),async(req,res)=>{const {programId,kpiType,kpiName,frequency='Monthly',weightage=0,unit='Number',formulaType='ratio',varianceExplanation=''}=req.body;if(!programId||!kpiType||!kpiName)return res.status(400).json({error:'Program, KPI type and KPI name are required'});if(!await canAccessProgram(req.user,programId))return res.status(403).json({error:'You are not assigned to this program'});const kpi=await KPI.create({programId,kpiType,kpiName,frequency,weightage:number(weightage),unit,formulaType,varianceExplanation:clean(varianceExplanation)});await audit(req.user,'CREATE','KPI',kpi.id,{kpiName,varianceExplanation:clean(varianceExplanation)});res.status(201).json(kpi);});
app.put('/api/kpis/:id',permit('manage_kpis'),async(req,res)=>{const kpi=await KPI.findByPk(req.params.id);if(kpi&&!await canAccessProgram(req.user,kpi.programId))return res.status(403).json({error:'You are not assigned to this program'});if(!kpi)return res.status(404).json({error:'KPI not found'});['kpiType','kpiName','frequency','weightage','unit','formulaType','varianceExplanation'].forEach(k=>{if(req.body[k]!==undefined)kpi[k]=req.body[k];});await kpi.save();await audit(req.user,'UPDATE','KPI',kpi.id,req.body);res.json(kpi);});
app.delete('/api/kpis/:id',permit('manage_kpis'),async(req,res)=>{const kpi=await KPI.findByPk(req.params.id);if(kpi&&!await canAccessProgram(req.user,kpi.programId))return res.status(403).json({error:'You are not assigned to this program'});if(!kpi)return res.status(404).json({error:'KPI not found'});await Actual.destroy({where:{kpiId:kpi.id}});await Target.destroy({where:{kpiId:kpi.id}});await kpi.destroy();await audit(req.user,'DELETE','KPI',req.params.id);res.json({ok:true});});

app.get('/api/targets',permit('view_kpis'),async(req,res)=>{const where={};if(req.query.kpiId){if(!await canAccessKpi(req.user,req.query.kpiId))return res.status(403).json({error:'You are not assigned to this program'});where.kpiId=req.query.kpiId;}else if(!isGlobalScope(req.user)){const ids=await assignedProgramIds(req.user);const kp=await KPI.findAll({where:{programId:ids.length?ids:[-1]},attributes:['id'],raw:true});where.kpiId=kp.length?kp.map(x=>x.id):[-1];}if(req.query.financialYear)where.financialYear=req.query.financialYear;res.json(await Target.findAll({where,order:[['id','ASC']]}));});
app.post('/api/targets',permit('manage_targets'),async(req,res)=>{const {kpiId,financialYear,programTarget,q1,q2,q3,q4,year1,year2,year3,year4,year5}=req.body;if(!kpiId||!financialYear)return res.status(400).json({error:'KPI and financial year are required'});if(!await canAccessKpi(req.user,kpiId))return res.status(403).json({error:'You are not assigned to this program'});let target=await Target.findOne({where:{kpiId,financialYear}});const created=!target;const data={programTarget:clean(programTarget),q1:clean(q1),q2:clean(q2),q3:clean(q3),q4:clean(q4),year1:clean(year1),year2:clean(year2),year3:clean(year3),year4:clean(year4),year5:clean(year5)};if(target){Object.assign(target,data);await target.save();}else target=await Target.create({kpiId,financialYear,...data});await audit(req.user,created?'CREATE':'UPDATE','Target',target.id,{kpiId,financialYear});res.json(target);});

app.get('/api/actuals',permit('view_kpis'),async(req,res)=>{const where={};if(req.query.kpiId){if(!await canAccessKpi(req.user,req.query.kpiId))return res.status(403).json({error:'You are not assigned to this program'});where.kpiId=req.query.kpiId;}else if(!isGlobalScope(req.user)){const ids=await assignedProgramIds(req.user);const kp=await KPI.findAll({where:{programId:ids.length?ids:[-1]},attributes:['id'],raw:true});where.kpiId=kp.length?kp.map(x=>x.id):[-1];}if(req.query.financialYear)where.financialYear=req.query.financialYear;if(req.query.month)where.month=req.query.month;res.json(await Actual.findAll({where,order:[['id','DESC']]}));});
app.post('/api/actuals',permit('enter_actuals'),async(req,res)=>{const {kpiId,financialYear,month,actualValue,comments}=req.body;if(!kpiId||!financialYear||!months.includes(month))return res.status(400).json({error:'kpiId, financialYear and valid month are required'});if(!await canAccessKpi(req.user,kpiId))return res.status(403).json({error:'You are not assigned to this program'});if(number(actualValue)<0)return res.status(400).json({error:'Actual value cannot be negative'});let record=await Actual.findOne({where:{kpiId,financialYear,month}});if(record){if(record.status==='Submitted')return res.status(409).json({error:'This actual is awaiting review. It cannot be edited until it is approved or rejected.'});if(record.status==='Approved')return res.status(409).json({error:'Approved actuals are locked.'});record.actualValue=number(actualValue);record.comments=comments;record.enteredBy=req.user.name;record.status='Draft';await record.save();}else{record=await Actual.create({kpiId,financialYear,month,actualValue:number(actualValue),comments,enteredBy:req.user.name,status:'Draft'});}await audit(req.user,'SAVE_DRAFT','Actual',record.id,{kpiId,financialYear,month,actualValue:number(actualValue)});res.json(record);});
app.post('/api/actuals/:id/submit',permit('submit_actuals'),async(req,res)=>{const record=await Actual.findByPk(req.params.id);if(!record)return res.status(404).json({error:'Not found'});if(!await canAccessKpi(req.user,record.kpiId))return res.status(403).json({error:'You are not assigned to this program'});const previousStatus=record.status;if(!['Draft','Rejected'].includes(previousStatus))return res.status(409).json({error:`Only Draft or Rejected records can be submitted. Current status: ${previousStatus}`});record.status='Submitted';record.enteredBy=req.user.name;record.submittedById=req.user.id;await record.save();await ApprovalHistory.create({actualId:record.id,action:previousStatus==='Rejected'?'Resubmitted':'Submitted',actorId:req.user.id,actorName:req.user.name,comments:req.body.comments||''});const k=await KPI.findByPk(record.kpiId,{attributes:['programId','kpiName']});if(k){const recipients=await usersForProgram(k.programId);await notify(recipients.filter(id=>id!==req.user.id),'APPROVAL','Actual submitted',`${req.user.name} submitted ${k.kpiName} for ${record.month}. Review is required.`,'Actual',record.id);}await audit(req.user,'SUBMIT','Actual',record.id,{previousStatus});res.json(record);});
app.get('/api/approvals/pending',permit('view_approvals'),async(req,res)=>{const records=await Actual.findAll({where:{status:'Submitted'},include:[{model:KPI,include:[{model:Program}]}],order:[['updatedAt','ASC']]});const scoped=[];for(const record of records){if(await canAccessKpi(req.user,record.kpiId))scoped.push(record);}res.json(scoped);});
app.get('/api/actuals/:id/history',permit('view_kpis'),async(req,res)=>{const record=await Actual.findByPk(req.params.id);if(!record)return res.status(404).json({error:'Not found'});if(!await canAccessKpi(req.user,record.kpiId))return res.status(403).json({error:'You are not assigned to this program'});res.json(await ApprovalHistory.findAll({where:{actualId:record.id},order:[['createdAt','ASC']]}));});
app.post('/api/actuals/:id/review',permit('approve_actuals'),async(req,res)=>{const record=await Actual.findByPk(req.params.id);if(!record)return res.status(404).json({error:'Not found'});if(!await canAccessKpi(req.user,record.kpiId))return res.status(403).json({error:'You are not assigned to this program'});if(record.status!=='Submitted')return res.status(409).json({error:`Only Submitted records can be reviewed. Current status: ${record.status}`});if(record.submittedById && Number(record.submittedById)===Number(req.user.id))return res.status(403).json({error:'A submission cannot be approved or rejected by the same employee who submitted it.'});const next=req.body.status;if(!['Approved','Rejected'].includes(next))return res.status(400).json({error:'Status must be Approved or Rejected'});if(next==='Rejected'&&!String(req.body.comments||'').trim())return res.status(400).json({error:'A rejection reason is required'});record.status=next;if(req.body.comments!==undefined)record.comments=req.body.comments;await record.save();await ApprovalHistory.create({actualId:record.id,action:next,actorId:req.user.id,actorName:req.user.name,comments:req.body.comments||''});const submitter=record.submittedById?await User.findOne({where:{id:record.submittedById,active:true}}):await User.findOne({where:{name:record.enteredBy,active:true}});if(submitter){await notify([submitter.id],next==='Approved'?'SUCCESS':'WARNING',`Actual ${next.toLowerCase()}`,`${req.user.name} ${next.toLowerCase()} the ${record.month} actual.${next==='Rejected'?' Reason: '+String(req.body.comments||''):''}`,'Actual',record.id);}await audit(req.user,next.toUpperCase(),'Actual',record.id,{comments:req.body.comments||''});res.json(record);});

app.get('/api/users',permit('manage_users'),async(_req,res)=>{const users=await User.findAll({order:[['name','ASC']]});const rows=[];for(const u of users){const assignments=await ProgramMember.findAll({where:{userId:u.id,active:true},attributes:['programId'],raw:true});rows.push({...publicUser(u),programIds:assignments.map(a=>a.programId)});}res.json(rows);});
app.post('/api/users',permit('manage_users'),async(req,res)=>{const {employeeId,name,email,role='Data Entry',department,designation,password,active=true,programIds=[]}=req.body;if(!employeeId||!name||!password)return res.status(400).json({error:'Employee ID, name and temporary password are required'});if(!ROLES.includes(role))return res.status(400).json({error:'Invalid role'});if(!strongPassword(password))return res.status(400).json({error:'Temporary password must be at least 10 characters and include upper, lower, number and special character'});try{const user=await User.create({employeeId:String(employeeId).trim(),name,email:clean(email),role,department:clean(department),designation:clean(designation),passwordHash:hashPassword(password),active:Boolean(active),mustChangePassword:true});await syncProgramAssignments(user.id,programIds);await audit(req.user,'CREATE','User',user.id,{employeeId:user.employeeId,role:user.role,programIds});res.status(201).json({...publicUser(user),programIds:programIds.map(Number)});}catch(e){res.status(400).json({error:e.name==='SequelizeUniqueConstraintError'?'Employee ID or email already exists':e.message});}});
app.put('/api/users/:id',permit('manage_users'),async(req,res)=>{const user=await User.findByPk(req.params.id);if(!user)return res.status(404).json({error:'Employee not found'});for(const k of ['name','email','role','department','designation','active'])if(req.body[k]!==undefined)user[k]=clean(req.body[k]);if(user.role&&!ROLES.includes(user.role))return res.status(400).json({error:'Invalid role'});if(req.body.password){if(!strongPassword(req.body.password))return res.status(400).json({error:'Password must be at least 10 characters and include upper, lower, number and special character'});user.passwordHash=hashPassword(req.body.password);user.mustChangePassword=true;}await user.save();if(Array.isArray(req.body.programIds))await syncProgramAssignments(user.id,req.body.programIds);const assignments=await ProgramMember.findAll({where:{userId:user.id,active:true},attributes:['programId'],raw:true});await audit(req.user,'UPDATE','User',user.id,{employeeId:user.employeeId,role:user.role,active:user.active,programIds:assignments.map(a=>a.programId)});res.json({...publicUser(user),programIds:assignments.map(a=>a.programId)});});
app.put('/api/users/:id/programs',permit('manage_users'),async(req,res)=>{const user=await User.findByPk(req.params.id);if(!user)return res.status(404).json({error:'Employee not found'});const ids=Array.isArray(req.body.programIds)?req.body.programIds:[];await syncProgramAssignments(user.id,ids);await audit(req.user,'ASSIGN_PROGRAMS','User',user.id,{programIds:ids});res.json({ok:true,programIds:ids.map(Number)});});
app.get('/api/notifications',async(req,res)=>{const limit=Math.min(Number(req.query.limit||30),100);const rows=await Notification.findAll({where:{userId:req.user.id},order:[['id','DESC']],limit});const unread=rows.filter(x=>!x.readAt).length;res.json({items:rows,unread});});
app.post('/api/notifications/read',async(req,res)=>{const ids=Array.isArray(req.body.ids)?req.body.ids.map(Number).filter(Boolean):[];if(ids.length)await Notification.update({readAt:new Date()},{where:{id:ids,userId:req.user.id}});else await Notification.update({readAt:new Date()},{where:{userId:req.user.id,readAt:null}});res.json({ok:true});});
app.get('/api/audit-logs',permit('view_audit'),async(req,res)=>{const limit=Math.min(Number(req.query.limit||100),500);const where={};if(req.query.action)where.action=req.query.action;if(req.query.entity)where.entity=req.query.entity;if(req.query.userId)where.userId=Number(req.query.userId);if(req.query.from||req.query.to)where.createdAt={};if(req.query.from)where.createdAt[Op.gte]=new Date(req.query.from);if(req.query.to)where.createdAt[Op.lte]=new Date(req.query.to+'T23:59:59.999Z');res.json(await AuditLog.findAll({where,order:[['id','DESC']],limit}));});
app.get('/api/dashboard/summary',permit('view_dashboard'),async(req,res)=>{const financialYear=String(req.query.financialYear||'FY 2026-27');const month=String(req.query.month||'September');const programs=await Program.findAll({order:[['programName','ASC']]});const visiblePrograms=isGlobalScope(req.user)?programs:programs.filter(p=>false);if(!isGlobalScope(req.user)){const ids=await assignedProgramIds(req.user);for(const p of programs)if(ids.includes(p.id))visiblePrograms.push(p);}const programIds=visiblePrograms.map(p=>p.id);const kpis=await KPI.findAll({where:programIds.length?{programId:programIds}:{programId:[-1]},include:[Target],raw:false});const kpiIds=kpis.map(k=>k.id);const actuals=await Actual.findAll({where:{financialYear, kpiId:kpiIds.length?kpiIds:[-1]},raw:true});const end=Math.max(0,months.indexOf(month));const ytdByKpi=new Map();for(const a of actuals){if(months.indexOf(a.month)<=end)ytdByKpi.set(a.kpiId,(ytdByKpi.get(a.kpiId)||0)+number(a.actualValue));}const quarter=Math.floor(end/3)+1;const rows=visiblePrograms.map(p=>{const ks=kpis.filter(k=>k.programId===p.id);let target=0,ytdTarget=0,ytdActual=0;for(const k of ks){const t=k.Target||{};target+=number(t.programTarget);for(let q=1;q<=quarter;q++)ytdTarget+=number(t['q'+q]);ytdActual+=number(ytdByKpi.get(k.id)||0);}return {id:p.id,name:p.programName,status:p.status,kpis:ks.length,annualTarget:target,ytdTarget,ytdActual,achievement:ytdTarget?Math.round(ytdActual/ytdTarget*1000)/10:null};});const pending=await Actual.count({where:{status:'Submitted',kpiId:kpiIds.length?kpiIds:[-1]}});const rejected=await Actual.count({where:{status:'Rejected',kpiId:kpiIds.length?kpiIds:[-1]}});const totalTarget=rows.reduce((s,r)=>s+r.annualTarget,0),totalYtdTarget=rows.reduce((s,r)=>s+r.ytdTarget,0),totalYtdActual=rows.reduce((s,r)=>s+r.ytdActual,0);const atRisk=rows.reduce((s,r)=>s+(r.achievement!==null&&r.achievement<70?1:0),0);res.json({financialYear,month,programs:rows,totals:{programs:rows.length,kpis:kpis.length,annualTarget:totalTarget,ytdTarget:totalYtdTarget,ytdActual:totalYtdActual,achievement:totalYtdTarget?Math.round(totalYtdActual/totalYtdTarget*1000)/10:null,pendingApprovals:pending,rejectedSubmissions:rejected,atRiskPrograms:atRisk}});});

async function buildManagementReport(user,financialYear,month){
  const programs=await Program.findAll({order:[['programName','ASC']]});
  const visible=isGlobalScope(user)?programs:programs.filter(p=>false);
  if(!isGlobalScope(user)){const ids=await assignedProgramIds(user);for(const p of programs)if(ids.includes(p.id))visible.push(p);}
  const ids=visible.map(p=>p.id);
  const kpis=await KPI.findAll({where:{programId:ids.length?ids:[-1]},include:[Target],raw:false});
  const kpiIds=kpis.map(k=>k.id);
  const actuals=await Actual.findAll({where:{financialYear,kpiId:kpiIds.length?kpiIds:[-1]},raw:true});
  const end=months.indexOf(month), quarter=Math.floor(end/3)+1;
  const programRows=[], kpiRows=[];
  for(const p of visible){
    const ks=kpis.filter(k=>k.programId===p.id); let annual=0,ytdTarget=0,ytdActual=0;
    for(const k of ks){const t=k.Target||{};annual+=number(t.programTarget);for(let q=1;q<=quarter;q++)ytdTarget+=number(t['q'+q]);ytdActual+=actuals.filter(a=>a.kpiId===k.id&&months.indexOf(a.month)<=end).reduce((x,a)=>x+number(a.actualValue),0);}
    programRows.push({id:p.id,name:p.programName,status:p.status,kpis:ks.length,annualTarget:annual,ytdTarget,ytdActual,achievement:ytdTarget?Math.round(ytdActual/ytdTarget*1000)/10:null});
    for(const k of ks){const t=k.Target||{};const ytdT=Array.from({length:quarter},(_,i)=>number(t['q'+(i+1)])).reduce((a,b)=>a+b,0);const ytdA=actuals.filter(a=>a.kpiId===k.id&&months.indexOf(a.month)<=end).reduce((a,b)=>a+number(b.actualValue),0);kpiRows.push({id:k.id,programId:p.id,program:p.programName,type:k.kpiType,name:k.kpiName,unit:k.unit,annualTarget:number(t.programTarget),ytdTarget:ytdT,ytdActual:ytdA,achievement:ytdT?Math.round(ytdA/ytdT*1000)/10:null});}
  }
  const status={onTrack:programRows.filter(x=>x.achievement===null||x.achievement>=90).length,watch:programRows.filter(x=>x.achievement!==null&&x.achievement>=70&&x.achievement<90).length,needsAttention:programRows.filter(x=>x.achievement!==null&&x.achievement<70).length};
  const approvalCounts={draft:0,submitted:0,approved:0,rejected:0}; for(const a of actuals){const key=String(a.status||'Draft').toLowerCase();approvalCounts[key]=(approvalCounts[key]||0)+1;}
  const totals={annualTarget:programRows.reduce((a,b)=>a+b.annualTarget,0),ytdTarget:programRows.reduce((a,b)=>a+b.ytdTarget,0),ytdActual:programRows.reduce((a,b)=>a+b.ytdActual,0)}; totals.achievement=totals.ytdTarget?Math.round(totals.ytdActual/totals.ytdTarget*1000)/10:null;
  return {financialYear,month,quarter,generatedAt:new Date().toISOString(),totals,status,approvalCounts,programs:programRows,kpis:kpiRows};
}
app.get('/api/reports/management',permit('view_reports'),async(req,res)=>{const financialYear=String(req.query.financialYear||'FY 2026-27'),month=String(req.query.month||'September');if(!months.includes(month))return res.status(400).json({error:'Invalid month'});res.json(await buildManagementReport(req.user,financialYear,month));});
app.get('/api/reports/management.xlsx',permit('export_reports'),async(req,res)=>{const financialYear=String(req.query.financialYear||'FY 2026-27'),month=String(req.query.month||'September');if(!months.includes(month))return res.status(400).json({error:'Invalid month'});const report=await buildManagementReport(req.user,financialYear,month);const wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(report.programs),'Program Summary');XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(report.kpis),'KPI Summary');XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet([{...report.totals,...report.status,...report.approvalCounts,Financial_Year:financialYear,Through_Month:month}]),'Management Summary');const buf=XLSX.write(wb,{type:'buffer',bookType:'xlsx'});res.setHeader('Content-Disposition',`attachment; filename="aasraa-management-report-${financialYear.replace(/[^A-Za-z0-9]/g,'-')}-${month}.xlsx"`);res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').send(buf);});

async function exportRows(user){
  let kpiWhere={};
  if(!isGlobalScope(user)){
    const ids=await assignedProgramIds(user);
    kpiWhere={programId:ids.length?ids:[-1]};
  }
  const kpis=await KPI.findAll({where:kpiWhere,include:[Target],raw:true,nest:true});
  const kpiIds=kpis.map(k=>k.id);
  const actuals=await Actual.findAll({where:{kpiId:kpiIds.length?kpiIds:[-1]},raw:true});
  return kpis.map(k=>({KPI_ID:k.id,KPI_Type:k.kpiType,KPI_Name:k.kpiName,Frequency:k.frequency,Unit:k.unit,Weightage:k.weightage,Variance_Explanation:k.varianceExplanation||'',Financial_Year:k.Target?.financialYear||'',Annual_Target:k.Target?.programTarget??'',Q1_Target:k.Target?.q1??'',Q2_Target:k.Target?.q2??'',Q3_Target:k.Target?.q3??'',Q4_Target:k.Target?.q4??'',...Object.fromEntries(months.map(m=>[m,actuals.filter(a=>a.kpiId===k.id&&a.month===m).reduce((s,a)=>s+number(a.actualValue),0)]))}));
}
app.get('/api/export/json',permit('export_reports'),async(req,res)=>{
  const scopedIds=isGlobalScope(req.user)?null:await assignedProgramIds(req.user);
  const programWhere=scopedIds?{id:scopedIds.length?scopedIds:[-1]}:{};
  const programs=await Program.findAll({where:programWhere,raw:true});
  const kpis=await KPI.findAll({where:scopedIds?{programId:scopedIds.length?scopedIds:[-1]}:{},raw:true});
  const kpiIds=kpis.map(k=>k.id);
  const [targets,actuals]=await Promise.all([Target.findAll({where:{kpiId:kpiIds.length?kpiIds:[-1]},raw:true}),Actual.findAll({where:{kpiId:kpiIds.length?kpiIds:[-1]},raw:true})]);
  const users=isGlobalScope(req.user)?await User.findAll({attributes:{exclude:['passwordHash']},raw:true}):[];
  const programMembers=isGlobalScope(req.user)?await ProgramMember.findAll({raw:true}):await ProgramMember.findAll({where:{programId:scopedIds&&scopedIds.length?scopedIds:[-1]},raw:true});
  const approvalHistory=await ApprovalHistory.findAll({where:{actualId:kpiIds.length?{[Op.in]:actuals.map(a=>a.id)}:[-1]},raw:true});
  const notifications=isGlobalScope(req.user)?await Notification.findAll({raw:true}):await Notification.findAll({where:{userId:req.user.id},raw:true});
  const auditLogs=isGlobalScope(req.user)?await AuditLog.findAll({raw:true}):await AuditLog.findAll({where:{userId:req.user.id},raw:true});
  res.setHeader('Content-Disposition','attachment; filename="kpi-full-backup.json"');res.json({generatedAt:new Date().toISOString(),schemaVersion:2,programs,kpis,targets,actuals,users,programMembers,approvalHistory,notifications,auditLogs});
});
app.get('/api/export/xlsx',permit('export_reports'),async(req,res)=>{const wb=XLSX.utils.book_new();XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(await exportRows(req.user)),'KPI Data');const buf=XLSX.write(wb,{type:'buffer',bookType:'xlsx'});res.setHeader('Content-Disposition','attachment; filename="kpi-data-export.xlsx"');res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').send(buf);});
app.get('/api/export/csv',permit('export_reports'),async(req,res)=>{const ws=XLSX.utils.json_to_sheet(await exportRows(req.user));res.setHeader('Content-Disposition','attachment; filename="kpi-data-export.csv"');res.type('text/csv').send(XLSX.utils.sheet_to_csv(ws));});
app.get('/api/export/pdf',permit('export_reports'),async(req,res)=>{const rows=await exportRows(req.user);const doc=new PDFDocument({margin:40});res.setHeader('Content-Disposition','attachment; filename="kpi-mis-report.pdf"');res.type('application/pdf');doc.pipe(res);doc.fontSize(18).text('Aasraa Trust - KPI MIS Report');doc.moveDown();rows.forEach((r,i)=>{doc.fontSize(10).text(`${i+1}. ${r.KPI_Name}`);doc.fontSize(8).text(`Type: ${r.KPI_Type} | Annual Target: ${r.Annual_Target} | Q1: ${r.Q1_Target} | Q2: ${r.Q2_Target} | Q3: ${r.Q3_Target} | Q4: ${r.Q4_Target}`);doc.moveDown(.5);if(doc.y>730)doc.addPage();});doc.end();});

app.use('/api',(_req,res)=>res.status(404).json({error:'API endpoint not found'}));

if(process.env.SERVE_FRONTEND==='true') {
  const __dirname=path.dirname(fileURLToPath(import.meta.url));
  const dist=path.resolve(__dirname, process.env.FRONTEND_DIST || '../../client/dist');
  app.use(express.static(dist,{index:'index.html',maxAge:'1d'}));
  app.get('*',(req,res)=>res.sendFile(path.join(dist,'index.html')));
}

app.use((err,req,res,next)=>{
  console.error('Unhandled request error:',err?.message||err);
  if(res.headersSent)return next(err);
  res.status(500).json({error:process.env.NODE_ENV==='production'?'Internal server error':(err?.message||'Internal server error')});
});

async function ensureBootstrapAdmin(){
  if(await User.count())return;
  const employeeId=process.env.BOOTSTRAP_ADMIN_ID; const password=process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if(!employeeId || !strongPassword(password)) throw new Error('Set BOOTSTRAP_ADMIN_ID and a strong BOOTSTRAP_ADMIN_PASSWORD before first production startup.');
  await User.create({employeeId,name:'System Administrator',email:null,passwordHash:hashPassword(password),role:'Super Admin',department:'MIS',designation:'System Administrator',active:true,mustChangePassword:true});
  console.log(`Bootstrap login created: ${employeeId}. Change the temporary password immediately.`);
}

const port=Number(process.env.PORT||5000);
initDb().then(ensureBootstrapAdmin).then(()=>app.listen(port,'0.0.0.0',()=>console.log(`Aasraa Trust KPI/MIS Portal running on port ${port}`))).catch(err=>{console.error(err);process.exit(1);});
