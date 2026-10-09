param([Parameter(Mandatory=$true)][string]$BackupFile,[string]$EnvFile=(Join-Path $PSScriptRoot '..\.env'))
$ErrorActionPreference='Stop'; if(!(Test-Path $BackupFile)){throw "Backup file not found: $BackupFile"}; if(!(Test-Path $EnvFile)){throw "Missing .env: $EnvFile"}
$cfg=@{}; Get-Content $EnvFile | ForEach-Object {if($_ -match '^\s*([^#=]+)\s*=\s*(.*)\s*$'){$cfg[$matches[1].Trim()]=$matches[2].Trim().Trim('"')}}
$env:MYSQL_PWD=$cfg.DB_PASSWORD
try { Get-Content -Raw -Path $BackupFile | & mysql.exe --host=$(if($cfg.DB_HOST){$cfg.DB_HOST}else{'127.0.0.1'}) --port=$(if($cfg.DB_PORT){$cfg.DB_PORT}else{'3306'}) --user=$cfg.DB_USER $cfg.DB_NAME; if($LASTEXITCODE -ne 0){throw "mysql restore failed with exit code $LASTEXITCODE"} } finally {Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue}
Write-Host 'Restore completed. Restart the application and run the smoke test.'
