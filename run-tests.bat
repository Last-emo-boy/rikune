@echo off
cd /d %~dp0
call npm test -- tests/unit/frida-script-inject.test.ts tests/unit/frida-runtime-instrument.test.ts tests/unit/frida-trace-capture.test.ts tests/unit/setup-guidance.test.ts
