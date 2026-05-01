@REM builder_cpp/agent/build.bat
@echo off
setlocal
where g++ >nul 2>nul
if %errorlevel%==0 (
    g++ -O2 -std=c++17 -static -static-libgcc -static-libstdc++ ^
        -DSECURITY_WIN32 ^
        -DSERVER_HOST=\"dev.local\" -DSERVER_PORT=443 ^
        -DBUILD_SLUG=\"1.0.0\" -DVERIFY_CERT=0 ^
        cmd/agent/main.cpp -o agent.exe ^
        -lwinhttp -lws2_32 -ladvapi32 -luser32 -lsecur32 -lcrypt32
    exit /b %errorlevel%
)
echo ERROR: g++ not found in PATH
exit /b 1
