@echo off
rem Release-configuration validation: configure, build, test, install to a clean prefix, then build
rem and run an independent consumer against the installed copy.
rem
rem The prefix is fixed at build/prefix so that the procedure is one command with no arguments.
rem
rem No timeout is passed to ctest or to any test binary.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo failed to initialise the Visual Studio environment & exit /b 1)
set PREFIX=%CD%\build\prefix
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release -DAIFC_WARNINGS_AS_ERRORS=ON -DAIFC_BUILD_TESTS=ON -DAIFC_BUILD_EXAMPLES=ON -DAIFC_BUILD_TOOLS=ON -DAIFC_REQUIRE_ALL_SURFACES=ON
if errorlevel 1 exit /b 1
cmake --build build/release --parallel
if errorlevel 1 exit /b 1
echo === release ctest ===
cd build\release
ctest --output-on-failure
if errorlevel 1 exit /b 1
cd ..\..
echo === install ===
cmake --install build/release --prefix "%PREFIX%"
if errorlevel 1 exit /b 1
echo === downstream consumer ===
cmake -S tests/downstream_consumer -B build/consumer -G Ninja -DCMAKE_PREFIX_PATH="%PREFIX%"
if errorlevel 1 exit /b 1
cmake --build build/consumer --parallel
if errorlevel 1 exit /b 1
build\consumer\consumer.exe
if errorlevel 1 exit /b 1
echo === consumer ok ===
exit /b 0