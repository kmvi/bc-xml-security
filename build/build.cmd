@echo off

del /f /q *.nupkg
del /f /q README.md
rmdir /s /q lib
rmdir /s /q ..\src\bin
rmdir /s /q ..\src\obj
rmdir /s /q ..\samples\bin
rmdir /s /q ..\samples\obj
rmdir /s /q ..\tests\bin
rmdir /s /q ..\tests\obj
mkdir lib\net461
mkdir lib\netstandard2.0
copy ..\README.md .

msbuild ..\XmlSecurity.sln /t:Clean /p:Configuration=Release
msbuild ..\XmlSecurity.sln /t:Restore
msbuild ..\XmlSecurity.sln /p:Configuration=Release

copy ..\src\bin\Release\net461\bc-xml-security.dll lib\net461\bc-xml-security.dll
copy ..\src\bin\Release\netstandard2.0\bc-xml-security.dll lib\netstandard2.0\bc-xml-security.dll

nuget pack -exclude build.cmd XmlSecurity.nuspec
