param([string]$EnvFile=(Join-Path $PSScriptRoot '..\.env'))
$ErrorActionPreference='Stop'
if(!(Test-Path $EnvFile)){ throw "Missing .env file: $EnvFile" }
$cfg=@{}
Get-Content $EnvFile | ForEach-Object { if($_ -match '^\s*([^#=]+)\s*=\s*(.*)\s*$'){ $cfg[$matches[1].Trim()]=$matches[2].Trim().Trim('"') } }
$dbHost=if($cfg.DB_HOST){$cfg.DB_HOST}else{'127.0.0.1'}; $dbPort=if($cfg.DB_PORT){$cfg.DB_PORT}else{'3306'}; $dbName=$cfg.DB_NAME; $dbUser=$cfg.DB_USER; $dbPass=$cfg.DB_PASSWORD
if(!$dbName -or !$dbUser){throw 'DB_NAME and DB_USER are required in .env'}
$dir=if($cfg.BACKUP_DIR){$cfg.BACKUP_DIR}else{Join-Path $PSScriptRoot '..\backups'}; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stamp=Get-Date -Format 'yyyyMMdd-HHmmss'; $file=Join-Path $dir "kpi_portal-$stamp.sql"
$env:MYSQL_PWD=$dbPass
try { & mysqldump.exe --host=$dbHost --port=$dbPort --user=$dbUser --single-transaction --routines --triggers --events --databases $dbName | Out-File -FilePath $file -Encoding utf8; if($LASTEXITCODE -ne 0){throw "mysqldump failed with exit code $LASTEXITCODE"} } finally { Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue }
$retention=[int](if($cfg.BACKUP_RETENTION_DAYS){$cfg.BACKUP_RETENTION_DAYS}else{30}); Get-ChildItem $dir -Filter '*.sql' | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-$retention)} | Remove-Item -Force
Write-Host "Backup created: $file"
