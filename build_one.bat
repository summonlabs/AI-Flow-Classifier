@echo off
rem Configure (if needed) and build exactly one target.  Useful while a test surface is being
rem authored, because a failure in an unrelated target does not stop this build.
rem
rem   build_one.bat <target>
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo failed to initialise the Visual Studio environment & exit /b 1)
if not exist build/msvc/build.ninja (
  cmake -S . -B build/msvc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAIFC_WARNINGS_AS_ERRORS=ON -DAIFC_BUILD_TESTS=ON -DAIFC_REQUIRE_ALL_SURFACES=OFF
  if errorlevel 1 exit /b 1
)
cmake --build build/msvc --target %1
exit /b %errorlevel%