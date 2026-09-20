@echo off
rem Configure and build AI Flow Classifier with MSVC via Ninja into build/msvc.
rem
rem   build_msvc.bat                       Debug, library + tools + examples
rem   build_msvc.bat -DAIFC_BUILD_TESTS=ON  also build the test suite
rem
rem The Visual Studio environment is established here rather than by the caller so that
rem every documented command in the README works from an ordinary shell.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (echo failed to initialise the Visual Studio environment & exit /b 1)
cmake -S . -B build/msvc -G Ninja -DCMAKE_BUILD_TYPE=Debug -DAIFC_WARNINGS_AS_ERRORS=ON %*
if errorlevel 1 exit /b 1
cmake --build build/msvc --parallel
exit /b %errorlevel%