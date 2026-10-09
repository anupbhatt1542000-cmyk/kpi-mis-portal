@echo off
cd /d "%~dp0server"
if not exist .env copy .env.example .env
if not exist node_modules call npm install
call npm run seed
call npm run dev
pause
