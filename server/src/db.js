import 'dotenv/config';
import { Sequelize, DataTypes } from 'sequelize';

export const sequelize = new Sequelize(
  process.env.DB_NAME || 'kpi_portal',
  process.env.DB_USER || 'kpi_user',
  process.env.DB_PASSWORD || 'CHANGE_ME_DB_PASSWORD',
  {host:process.env.DB_HOST || '127.0.0.1',port:Number(process.env.DB_PORT || 3306),dialect:'mysql',logging:false}
);

export const Program = sequelize.define('Program', {
  id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, programName:{type:DataTypes.STRING(255),allowNull:false}, fluxxId:DataTypes.STRING(100), startDate:DataTypes.DATEONLY, endDate:DataTypes.DATEONLY,
  financialYear:{type:DataTypes.STRING(20),allowNull:false}, status:{type:DataTypes.ENUM('Draft','Active','Closed'),defaultValue:'Active'}
});
export const KPI = sequelize.define('KPI', {
  id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, programId:{type:DataTypes.INTEGER,allowNull:false}, kpiType:{type:DataTypes.ENUM('Activity','Output','Outcome','Impact'),allowNull:false},
  kpiName:{type:DataTypes.TEXT,allowNull:false}, frequency:{type:DataTypes.STRING(50),defaultValue:'Quarterly'}, weightage:{type:DataTypes.DECIMAL(6,2),defaultValue:0}, unit:{type:DataTypes.STRING(30),defaultValue:'Number'}, formulaType:{type:DataTypes.STRING(50),defaultValue:'ratio'}, varianceExplanation:{type:DataTypes.TEXT,allowNull:true}
});
export const Target = sequelize.define('Target', {
  id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, kpiId:{type:DataTypes.INTEGER,allowNull:false}, financialYear:{type:DataTypes.STRING(20),allowNull:false}, year1:DataTypes.DECIMAL(18,4),year2:DataTypes.DECIMAL(18,4),year3:DataTypes.DECIMAL(18,4),year4:DataTypes.DECIMAL(18,4),year5:DataTypes.DECIMAL(18,4),programTarget:DataTypes.DECIMAL(18,4),q1:DataTypes.DECIMAL(18,4),q2:DataTypes.DECIMAL(18,4),q3:DataTypes.DECIMAL(18,4),q4:DataTypes.DECIMAL(18,4)
}, { indexes:[{unique:true,fields:['kpiId','financialYear']}] });
export const Actual = sequelize.define('Actual', {
  id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, kpiId:{type:DataTypes.INTEGER,allowNull:false}, financialYear:{type:DataTypes.STRING(20),allowNull:false}, month:{type:DataTypes.STRING(20),allowNull:false}, actualValue:{type:DataTypes.DECIMAL(18,4),allowNull:false,defaultValue:0}, comments:DataTypes.TEXT,
  status:{type:DataTypes.ENUM('Draft','Submitted','Approved','Rejected'),defaultValue:'Draft'}, enteredBy:DataTypes.STRING(120), submittedById:{type:DataTypes.INTEGER,allowNull:true}
}, { indexes:[{unique:true,fields:['kpiId','financialYear','month']}] });
export const User = sequelize.define('User', {
  id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, employeeId:{type:DataTypes.STRING(40),unique:true,allowNull:true}, name:{type:DataTypes.STRING(120),allowNull:false}, email:{type:DataTypes.STRING(180),unique:true,allowNull:true},
  passwordHash:{type:DataTypes.STRING(255),allowNull:true}, role:{type:DataTypes.STRING(50),allowNull:false,defaultValue:'Data Entry'}, department:DataTypes.STRING(120), designation:DataTypes.STRING(120), active:{type:DataTypes.BOOLEAN,defaultValue:true}, mustChangePassword:{type:DataTypes.BOOLEAN,defaultValue:true}, lastLoginAt:DataTypes.DATE
});
export const AuditLog = sequelize.define('AuditLog', {id:{type:DataTypes.BIGINT,autoIncrement:true,primaryKey:true},userId:{type:DataTypes.INTEGER,allowNull:true},userName:DataTypes.STRING(120),action:DataTypes.STRING(50),entity:DataTypes.STRING(80),recordId:DataTypes.STRING(80),details:DataTypes.JSON});
export const ProgramMember = sequelize.define('ProgramMember', {id:{type:DataTypes.INTEGER,autoIncrement:true,primaryKey:true}, userId:{type:DataTypes.INTEGER,allowNull:false}, programId:{type:DataTypes.INTEGER,allowNull:false}, assignmentRole:{type:DataTypes.STRING(60),defaultValue:'Member'}, active:{type:DataTypes.BOOLEAN,defaultValue:true}}, { indexes:[{unique:true,fields:['userId','programId']}] });
export const ApprovalHistory = sequelize.define('ApprovalHistory', {id:{type:DataTypes.BIGINT,autoIncrement:true,primaryKey:true}, actualId:{type:DataTypes.INTEGER,allowNull:false}, action:{type:DataTypes.ENUM('Submitted','Approved','Rejected','Resubmitted'),allowNull:false}, actorId:{type:DataTypes.INTEGER,allowNull:true}, actorName:{type:DataTypes.STRING(120),allowNull:false}, comments:DataTypes.TEXT});
export const Notification = sequelize.define('Notification', {id:{type:DataTypes.BIGINT,autoIncrement:true,primaryKey:true}, userId:{type:DataTypes.INTEGER,allowNull:false}, type:{type:DataTypes.STRING(40),defaultValue:'INFO'}, title:{type:DataTypes.STRING(180),allowNull:false}, message:{type:DataTypes.TEXT,allowNull:false}, entity:{type:DataTypes.STRING(80)}, recordId:{type:DataTypes.STRING(80)}, readAt:DataTypes.DATE});

Program.hasMany(KPI,{foreignKey:'programId'}); KPI.belongsTo(Program,{foreignKey:'programId'});
User.belongsToMany(Program,{through:ProgramMember,foreignKey:'userId',otherKey:'programId'}); Program.belongsToMany(User,{through:ProgramMember,foreignKey:'programId',otherKey:'userId'}); ProgramMember.belongsTo(User,{foreignKey:'userId'}); ProgramMember.belongsTo(Program,{foreignKey:'programId'}); KPI.hasOne(Target,{foreignKey:'kpiId'}); Target.belongsTo(KPI,{foreignKey:'kpiId'}); KPI.hasMany(Actual,{foreignKey:'kpiId'}); Actual.belongsTo(KPI,{foreignKey:'kpiId'}); Actual.hasMany(ApprovalHistory,{foreignKey:'actualId'}); ApprovalHistory.belongsTo(Actual,{foreignKey:'actualId'}); Notification.belongsTo(User,{foreignKey:'userId'}); User.hasMany(Notification,{foreignKey:'userId'});

export async function initDb(){
  await sequelize.authenticate();
  await sequelize.sync();
  // Phase 7 adds security/audit fields while preserving existing KPI data.
  await KPI.sync({alter:true});
  await Actual.sync({alter:true});
  await AuditLog.sync({alter:true});
  // The User model changed substantially in Phase 2; alter only this table to preserve existing KPI data.
  await User.sync({alter:true});
}

