@echo off

del /f /q *.nupkg
rmdir /s /q lib
rmdir /s /q ..\src\bin
rmdir /s /q ..\src\obj
rmdir /s /q ..\samples\bin
rmdir /s /q ..\samples\obj
rmdir /s /q ..\tests\bin
rmdir /s /q ..\tests\obj
mkdir lib\net40

msbuild ..\XmlSecurity.sln /t:Clean /p:Configuration=Release
msbuild ..\XmlSecurity.sln /t:Restore
msbuild ..\XmlSecurity.sln /p:Configuration=Release

copy ..\src\bin\Release\bc-xml-security.dll lib\net40\bc-xml-security.dll

nuget pack -exclude build.cmd XmlSecurity.nuspec
