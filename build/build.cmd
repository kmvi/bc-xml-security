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
mkdir lib\netstandard2.0
mkdir lib\netstandard2.1

msbuild ..\XmlSecurity.sln /t:Clean /p:Configuration=Release
msbuild ..\XmlSecurity.sln /t:Restore
msbuild ..\XmlSecurity.sln /p:Configuration=Release

copy ..\src\bin\Release\net40\bc-xml-security.dll lib\net40\bc-xml-security.dll
copy ..\src\bin\Release\netstandard2.0\bc-xml-security.dll lib\netstandard2.0\bc-xml-security.dll
copy ..\src\bin\Release\netstandard2.1\bc-xml-security.dll lib\netstandard2.1\bc-xml-security.dll

nuget pack -exclude build.cmd XmlSecurity.nuspec
