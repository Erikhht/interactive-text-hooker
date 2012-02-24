@echo off
SET _result=%DATE:/=.%
echo const wchar_t* version=L"Interactive Text Hooker 3.0 (%_result%)\r\n"; >%1%\include\ITH\version.h
@echo on
echo %_result%