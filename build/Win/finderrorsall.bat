@echo off
setlocal
echo Checking files - each "." represents a single file.
dir ..\..\src\*.cc /s /b >filelist.txt
dir ..\..\src\*.h /s /b >>filelist.txt
findstr /i /v "src\talk src\qt src\transport src\protobuf src\tools Done Total src\examples src\tests src\gui\img\images.cc .pb. src\gui\3rdparty src\fs\w_fuse\dokan src\fs\w_fuse\dokan_control src\fs\w_fuse\dokan_mount src\fs\w_fuse\sys src\doxys_" filelist.txt > filelist2.txt
cd ..\..\
set rootpath=%cd%
cd build\Win
echo Setup>code_style_errors.txt
set count=0
for /f %%g in (filelist2.txt) do (
  @"cmd /c %rootpath%\src\cpplint.py "%%g" 2>>code_style_errors.txt"
  <nul (set/p z=".")
)
findstr /i /v /b "Setup Done Total" code_style_errors.txt > code_style_errors2
del filelist.txt filelist2.txt code_style_errors.txt
set count=0
for /f  %%g in (code_style_errors2) do (call :s_do_sums)
cls & echo. & echo. & echo.
if %count% geq 1 echo There are %count% errors! & echo Good God, man - that's totally pish.  Get it sorted out, ya jobby.
if %count% equ 1 echo Only one error left.  I bet you wish you'd fixed it, ya fanny.
if %count% equ 0 echo There aren't any errors just now.  Not too bad I suppose. & echo I'm sure it won't be long 'till they're back though.
echo. & echo.
goto :eof
:s_do_sums
 set /a count+=1
 goto :eof
::exit
