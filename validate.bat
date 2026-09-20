@echo off
rem Full local validation: configure, build, and run the whole registered suite.
rem
rem   validate.bat [extra cmake arguments]
rem
rem No timeout is passed to ctest or to any test binary.  A hanging test is a defect to
rem diagnose, so the harness is allowed to sit there until it is understood.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo failed to initialise the Visual Studio environment & exit /b 1)
cmake -S . -B build/msvc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAIFC_WARNINGS_AS_ERRORS=ON -DAIFC_BUILD_TESTS=ON -DAIFC_BUILD_EXAMPLES=ON -DAIFC_BUILD_TOOLS=ON %*
if errorlevel 1 exit /b 1
cmake --build build/msvc --parallel
if errorlevel 1 exit /b 1
cd build\msvc
ctest --output-on-failure
exit /b %errorlevel%