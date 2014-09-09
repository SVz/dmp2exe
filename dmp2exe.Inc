WinMain proto :DWORD,:DWORD,:DWORD,:DWORD
include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
include \masm32\include\gdi32.inc
include \masm32\include\masm32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\advapi32.inc
include \masm32\include\ComCtl32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\gdi32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\comdlg32.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\ComCtl32.lib

.const
 IDC_OPEN                                           equ 3000
 IDC_EXIT                                           equ 3001
 IDC_FILENAME                                       equ 3002
 IDC_FILESIZE                                       equ 3003
 IDC_NBSECTION                                      equ 3004
 IDC_CREXE                                          equ 3005
 IDC_LSNAME                                         equ 3006
 IDC_LSSIZE                                         equ 3007
 IDC_EIP                                            equ 3008
 IDC_IMPORT                                         equ 3009
 IDC_LIST                                           equ 3010
 IDC_ATEND                                          equ 3011
 
 MAXSIZE equ 260

