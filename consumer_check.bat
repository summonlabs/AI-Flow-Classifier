@echo off
rem Configure, build and run the independent downstream consumer against the installed prefix.
rem
rem This runs from an ordinary shell with the Visual Studio environment established here, so it proves
rem what an external project would experience rather than what this build tree can do.
rem
rem The consumer is a single-configuration project, so the configuration is stated explicitly.  A
rem consumer that silently picked Debug while the installed library is Release would fail at link time
rem with a runtime-library mismatch, which says nothing about whether the package is usable.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo failed to initialise the Visual Studio environment & exit /b 1)
set PREFIX=%CD%\build\prefix
set CONFIG=Release
if not "%~1"=="" set CONFIG=%~1
cmake -S tests/downstream_consumer -B build/consumer -G Ninja -DCMAKE_BUILD_TYPE=%CONFIG% "-DCMAKE_PREFIX_PATH=%PREFIX%"
if errorlevel 1 exit /b 1
cmake --build build/consumer --parallel
if errorlevel 1 exit /b 1
build\consumer\consumer.exe
if errorlevel 1 exit /b 1
echo === consumer ok ===
exit /b 0