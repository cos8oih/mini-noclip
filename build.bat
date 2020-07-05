@echo off
del /f /s /q build
mkdir build\files
nasm -fwin32 ./source/winapi.s -Ox -o ./build/files/winapi.obj
nasm -fwin32 ./source/main.s -Ox -o ./build/files/main.obj
golink /entry _start ./build/files/winapi.obj ./build/files/main.obj /fo ./build/noclip.exe