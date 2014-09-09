.386
.model flat,stdcall
option casemap:none

include dmp2exe.inc

.data
ClassName 			db "DLGCLASS",0
MenuName 			db "MyMenu",0
DlgName 			db "SVDialog",0
;AppName 			db "SV",0
ofn   				OPENFILENAME <>
buffer 				db MAXSIZE dup(0)
hMapFile 			HANDLE 0
hwMapFile 			HANDLE 0
FilterString 		db "Dump Files",0,"*.dmp",0,0
FilterString_copy 	db "Bin Files",0,"*.bin",0,0
FilterStringexe 	db "PE Files",0,"*.exe",0,0
Defextexe 			db ".exe",0
template 			db "%X",0  
section_template 	db "%-8s%08X %08X %08X %08X",0             
MsgCaption      	db "Error",0
MsgCaption_good 	db "Good",0
MsgBoxText      	db "File can't be opened or not PE valid !",0
texterrorsize      	db "File size doesn't match with PE header size !",0
MsgBoxText_good 	db "PE successfully created !",0
MsgBoxText_copyok 	db "Section copy completed !",0
MsgBoxText_alert 	db "New IT Alert. PE size increase by 200 !",0
compteur 			dd 0
low_raw 			dd 0ffffffffh
fontname 			db "Lucida Console",0
title_section_copy 	db "Select section file to be copied",0
szsvKey 			db  '\Software\SV',0
szsvDir 			db  'dir',0
szSIZE 				dd 256

.data?
hInstance 			HINSTANCE ?
CommandLine 		LPSTR ?
hFileRead 			HANDLE ?
file_size 			DWORD ?
hFileWrite 			HANDLE ?
SizeWritten 		DWORD ?
pMemory 			DWORD ?
pwMemory 			DWORD ?
stubsize 			DWORD ?
nbsection 			DWORD ?
first_raw_offset 	DWORD ?
index_raw_offset 	DWORD ?
v_offset 			DWORD ?
v_size 				DWORD ?
;raw_size 			DWORD ?
mem_deb_section 	DWORD ?
vs 					DWORD ?
vo 					DWORD ?
rs 					DWORD ?
ro 					DWORD ?
textbuffer 			db 512 dup(?)
hFile_copy 			DWORD ?
hMapFile_copy 		DWORD ?
pMemory_copy 		DWORD ?
dirbuffer 			db 512 dup(?)
hReg 				dd ?
lpdwDisposition 	dd ?


.code
;--------------------------------------------------------------------
   
;--------------------------------------------------------------------
;--------------------------------------------------------------------
;--------------------------------------------------------------------
start:
    invoke GetModuleHandle, NULL
    mov    hInstance,eax
    invoke GetCommandLine
    call svdirregopen
    invoke InitCommonControls
    invoke WinMain, hInstance,NULL,CommandLine, SW_SHOWDEFAULT
exit:
    invoke ExitProcess,eax
    
WinMain proc hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
    LOCAL wc:WNDCLASSEX
    LOCAL msg:MSG
    LOCAL hDlg:HWND
    
    mov   wc.cbSize,SIZEOF WNDCLASSEX
    mov   wc.style, CS_HREDRAW or CS_VREDRAW
    mov   wc.lpfnWndProc, OFFSET WndProc
    mov   wc.cbClsExtra,NULL
    mov   wc.cbWndExtra,DLGWINDOWEXTRA
    push  hInst
    pop   wc.hInstance
    mov   wc.hbrBackground,COLOR_BTNFACE+1
    mov   wc.lpszClassName,OFFSET ClassName
    
    invoke LoadIcon,hInst,1
    mov   wc.hIcon,eax
    mov   wc.hIconSm,eax
    invoke LoadCursor,NULL,IDC_ARROW
    mov   wc.hCursor,eax
    invoke RegisterClassEx, addr wc
    invoke CreateDialogParam,hInstance,ADDR DlgName,NULL,NULL,NULL
    mov   hDlg,eax
    INVOKE ShowWindow, hDlg,SW_SHOWNORMAL
    INVOKE UpdateWindow, hDlg

    mov ofn.lStructSize,SIZEOF ofn
    push hDlg
    pop  ofn.hWndOwner
    push hInstance
    pop  ofn.hInstance
    mov  ofn.lpstrFilter, OFFSET FilterString
    mov  ofn.lpstrFile, OFFSET buffer
    mov  ofn.nMaxFile,MAXSIZE

    .WHILE TRUE
                INVOKE GetMessage, ADDR msg,NULL,0,0
                .BREAK .IF (!eax)
                invoke IsDialogMessage, hDlg, ADDR msg
                .if eax==FALSE
                        INVOKE TranslateMessage, ADDR msg
                        INVOKE DispatchMessage, ADDR msg
                .endif
    .ENDW
    mov     eax,msg.wParam
    ret
WinMain endp
WndProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
 LOCAL hdc:HDC 
 LOCAL ps:PAINTSTRUCT 
 LOCAL hfont:HFONT
    .IF uMsg==WM_DESTROY
        invoke PostQuitMessage,NULL
    .ELSEIF uMsg==WM_PAINT
        invoke BeginPaint,hWnd, ADDR ps 
        mov    hdc,eax 
        mov eax,wParam
        invoke CreateFont,10,0,0,0,400,0,FALSE,0,OEM_CHARSET,\ 
                                       OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,\ 
                                       DEFAULT_QUALITY,DEFAULT_PITCH or FF_SCRIPT,\ 
                                       ADDR fontname 
        invoke SelectObject, hdc, eax 
        mov    hfont,eax
        invoke SelectObject, hdc, hfont 
        mov    hfont,eax
        invoke GetDlgItem,hWnd,IDC_LIST
        invoke SendMessage,eax,WM_SETFONT,hfont,TRUE
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
        .IF dx==LBN_DBLCLK
            .IF ax==IDC_LIST
                invoke GetDlgItem,hWnd,IDC_LIST
                invoke SendMessage,eax,LB_GETCURSEL,0,0
                imul eax,28h
                add eax,pMemory
                add eax,stubsize
                add eax,0F8h
                mov ebx,[eax+08h]
                mov vs,ebx
                mov ebx,[eax+0ch]
                mov vo,ebx
                mov ofn.Flags, OFN_FILEMUSTEXIST or \
                                OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
                                OFN_EXPLORER or OFN_HIDEREADONLY
                mov ofn.lpstrFilter, OFFSET FilterString_copy
                mov ofn.lpstrTitle , OFFSET title_section_copy
                lea eax,buffer
                xor ebx,ebx
                mov [eax],bl                            ;filename a vide
                invoke GetOpenFileName, ADDR ofn
                .if eax==TRUE
                    invoke CreateFile,ADDR buffer,\
                                   GENERIC_READ ,\
                                   FILE_SHARE_READ,\
                                   NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,\
                                   NULL
                    .if (eax)
                        mov hFile_copy,eax
                        invoke GetFileSize,hFile_copy,NULL
                        .if (eax==vs)
                            invoke CreateFileMapping,hFile_copy,NULL,PAGE_READONLY,0,0,NULL
                            .if (eax)
                                mov  hMapFile_copy,eax
                                invoke MapViewOfFile,hMapFile_copy,FILE_MAP_READ,0,0,0
                                .if (eax)
                                    mov pMemory_copy,eax
                                    mov ecx,vs
                                    mov esi,pMemory_copy
                                    mov edi,pMemory
                                    add edi,vo
                                    rep movsb
                                    invoke CloseHandle,hMapFile_copy
                                    invoke CloseHandle,hFile_copy
                                    invoke MessageBox, NULL,addr MsgBoxText_copyok, addr MsgCaption_good, MB_OK
                                .endif
                            .endif
                        .else
                            invoke MessageBox, NULL,addr texterrorsize, addr MsgCaption, MB_OK
                        .endif
                    .endif
                .endif          
;                invoke wsprintf,addr textbuffer,offset section_template,eax,vs,vo,rs,ro
            .ENDIF
        .ELSEIF dx==BN_CLICKED
            .IF ax==IDC_OPEN
                .if hMapFile!=0
                    invoke UnmapViewOfFile,pMemory
                    call CloseMapFile
                .endif
                mov  ofn.Flags, OFN_FILEMUSTEXIST or \
                                OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
                                OFN_EXPLORER or OFN_HIDEREADONLY
                mov  ofn.lpstrFilter, OFFSET FilterString
                mov ofn.lpstrInitialDir, offset dirbuffer
                invoke GetOpenFileName, ADDR ofn
                .if eax==TRUE
                    invoke CreateFile,ADDR buffer,\
                                                GENERIC_READ or GENERIC_WRITE ,\
                                                FILE_SHARE_READ or FILE_SHARE_WRITE,\
                                                NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,\
                                                NULL
                    test eax,eax
                    jz error                                                
                    mov hFileRead,eax
                    invoke RegSetValueExA,hReg,offset szsvDir,0,REG_SZ,offset buffer,255
                    invoke CreateFileMapping,hFileRead,NULL,PAGE_READWRITE,0,0,NULL
                    test eax,eax
                    jz error                                                
                    mov  hMapFile,eax
                    mov    eax,OFFSET buffer
                    movzx  edx,ofn.nFileOffset
                    add    eax,edx
                    invoke SetDlgItemText,hWnd,IDC_FILENAME,eax
                    invoke MapViewOfFile,hMapFile,FILE_MAP_ALL_ACCESS,0,0,0
                    test eax,eax
                    jz error
                    mov pMemory,eax
                    add eax,3Ch
                    mov eax,[eax]
                    mov stubsize,eax
                    mov eax,pMemory
                    add eax,stubsize
                    movsx edx,byte ptr [eax]
                    cmp edx,'P'
                    jnz error
                    inc eax
                    movsx edx,byte ptr [eax]
                    cmp edx,'E'
                    jnz error
                    add eax,5       ; Nb Section
                    movsx eax,byte ptr [eax]
                    mov nbsection,eax
                    invoke wsprintf,addr textbuffer,offset template,eax
                    invoke SetDlgItemText,hWnd,IDC_NBSECTION,addr textbuffer
                    mov eax,pMemory
                    add eax,stubsize
                    add eax,50h       ; Size
                    mov eax,[eax]
                    mov file_size,eax
                    invoke wsprintf,addr textbuffer,offset template,eax
                    invoke SetDlgItemText,hWnd,IDC_FILESIZE,addr textbuffer
                    mov eax,pMemory
                    add eax,stubsize
                    add eax,28h       ; EIP
                    mov eax,[eax]
                    invoke wsprintf,addr textbuffer,offset template,eax
                    invoke SetDlgItemText,hWnd,IDC_EIP,addr textbuffer
                    mov eax,pMemory
                    add eax,stubsize
                    add eax,80h       ; Import RVA
                    mov eax,[eax]
                    invoke wsprintf,addr textbuffer,offset template,eax
                    invoke SetDlgItemText,hWnd,IDC_IMPORT,addr textbuffer
                    invoke GetDlgItem,hWnd,IDC_CREXE
                    invoke EnableWindow,eax,TRUE
                    invoke GetDlgItem,hWnd,IDC_EIP
                    invoke EnableWindow,eax,TRUE
                    invoke GetDlgItem,hWnd,IDC_IMPORT
                    invoke EnableWindow,eax,TRUE
                    invoke GetDlgItem,hWnd,IDC_EIP
                    invoke SetFocus,eax 
                    invoke GetFileSize,hFileRead,NULL
                    .if (eax!=file_size) ; test si la size read est la meme que le pe
                        invoke MessageBox, NULL,addr texterrorsize, addr MsgCaption, MB_OK
                        call   CloseMapFile
                    .endif
                    invoke GetDlgItem,hWnd,IDC_LIST
                    invoke SendMessage,eax,LB_RESETCONTENT,0,0
                    xor esi,esi
                    .while (esi<nbsection) ;boucle sur section raw la plus basse
                        mov ecx,esi         ;(header  size?)
                        imul ecx,28h
                        mov eax,pMemory
                        add eax,stubsize
                        movzx edx,word ptr [eax+14h]
                        add eax,edx
                        add eax,18h
                        add eax,ecx ;section raw
                        mov ebx,[eax+08h]
                        mov vs,ebx
                        mov ebx,[eax+0ch]
                        mov vo,ebx
                        mov ebx,[eax+10h]
                        mov rs,ebx
                        mov ebx,[eax+14h]
                        mov ro,ebx
                        invoke wsprintf,addr textbuffer,offset section_template,eax,vs,vo,rs,ro
                        invoke GetDlgItem,hWnd,IDC_LIST
                        invoke SendMessage,eax,LB_ADDSTRING,0,addr textbuffer
                        inc esi
                    .endw
                    
                    jmp finerror
error:
                    invoke MessageBox, NULL,addr MsgBoxText, addr MsgCaption, MB_OK
                    call   CloseMapFile
finerror:
                .endif
            .ELSEIF ax==IDC_CREXE
                pushad
                mov ofn.Flags,OFN_LONGNAMES or\
                                OFN_EXPLORER or OFN_HIDEREADONLY
                mov ofn.lpstrFilter, OFFSET FilterStringexe
                mov ofn.lpstrDefExt, OFFSET Defextexe
                lea eax,buffer
                xor ebx,ebx
                mov [eax],bl                            ;filename a vide
                invoke GetSaveFileName, ADDR ofn
                .if eax==TRUE
                    invoke CreateFile,ADDR buffer,\
                                                GENERIC_READ or GENERIC_WRITE ,\
                                                FILE_SHARE_READ or FILE_SHARE_WRITE,\
                                                NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,\
                                                NULL
                    test eax,eax
                    jz error2                                               
                    mov hFileWrite,eax
                    xor edi,edi
                    .while (edi<nbsection)  ;boucle sur section raw la plus basse ;modif <=
                        mov ecx,edi         ;(header  size?)
                        imul ecx,28h
                        add ecx,14h
                        mov eax,pMemory
                        add eax,stubsize
                        movzx edx,word ptr [eax+14h]
                        add eax,edx
                        add eax,18h
                        add eax,ecx ;section raw
                        mov eax,[eax]
                        .if (eax<low_raw) && (eax)
                            mov low_raw,eax
                        .endif
                        inc edi
                    .endw

                    mov eax,pMemory			;test pour voir si 200 pas trop juste pour rajouter une section
                    add eax,stubsize
                    movzx edx,word ptr [eax+14h]
                    add eax,edx
                    add eax,18h
                    sub eax,pMemory
                    mov ecx,nbsection
                    inc ecx
                    imul ecx,28h
                    add eax,ecx
                    .if (eax>low_raw)
	                   invoke MessageBox, NULL,addr MsgBoxText_alert, addr MsgCaption,MB_OK or MB_ICONWARNING
	                   add low_raw,200h
                    .endif
                    
                    
                    mov eax,low_raw
                    mov first_raw_offset,eax
                    invoke WriteFile,hFileWrite,pMemory,eax,ADDR SizeWritten,NULL

                    invoke CreateFileMapping,hFileWrite,NULL,PAGE_READWRITE,0,0,NULL
                    test eax,eax
                    jz error2                                                
                    mov  hwMapFile,eax
                    invoke MapViewOfFile,hwMapFile,FILE_MAP_ALL_ACCESS,0,0,0
                    mov pwMemory,eax
                    ; Si new EIP
                    invoke GetDlgItemText,hWnd,IDC_EIP,addr textbuffer,10
                    invoke htodw,addr textbuffer
                    .if (eax)
                        mov edx,eax
                        mov eax,pwMemory
                        add eax,stubsize
                        add eax,28h     ; Maj EIP
                        mov [eax],edx
                    .endif
                    ; Si new ImportRVA
                    invoke GetDlgItemText,hWnd,IDC_IMPORT,addr textbuffer,10
                    invoke htodw,addr textbuffer
;                    .if (eax)
                        mov edx,eax
                        mov eax,pwMemory
                        add eax,stubsize
                        add eax,80h     ; Maj ImportRVA
                        mov [eax],edx
;                    .endif
                    ; E0000020
                    mov eax,pwMemory
                    add eax,stubsize
                    add eax,11Ch     ; Maj Caracteristic First Section
                    mov edx,0E0000040h
                    mov [eax],edx

                    mov eax,first_raw_offset
                                        
                    mov index_raw_offset,eax
                    mov compteur,0
loopws:             
                    mov edx,compteur
                    cmp edx,nbsection
                    jz closefile
                    imul edx,28h        ; add all section
                    mov eax,pMemory
                    add eax,stubsize
                    movzx ecx,word ptr [eax+14h]
                    add eax,ecx
                    add eax,18h
                    add eax,edx

                    add eax,08h         ;Virtual size                      
                    mov ecx,[eax]
                    mov v_size,ecx

                    add eax,04h         ;Virtual offset               
                    mov ecx,[eax]
                    mov v_offset,ecx

                    mov eax,pMemory     ; on pointe a la fin
                    add eax,v_offset
                    mov mem_deb_section,eax
                    add eax,v_size
                    dec eax
loop_search:                            ; on recherche de la fin en remontant 
                    movsx edx,byte ptr [eax]    ;le premier byte non null
                    test edx,edx
                    jnz suite_search
                    dec eax
                    cmp eax,mem_deb_section ;cas bss ou pas de byte non null
                    jnz loop_search
                    xor ecx,ecx
                    jmp jmp_bss
suite_search:
                    sub eax,pMemory ; calcul de la size en modulo 200h
                    sub eax,v_offset
                    add eax,2
                    mov ebx,200h
                    cdq
                    idiv ebx
                    test edx,edx
                    jz suite_modulo
                    inc eax
suite_modulo:
                    imul eax,200h
                    mov ecx,eax
jmp_bss:                    
                    mov eax,pwMemory    ; mise a jour du raw_size
                    add eax,stubsize
                    add eax,0F8h        ; First Section
                    mov edx,compteur
                    imul edx,28h        ; add all section
                    add eax,edx         ; on point sur la section en cour 
                    
                                       
                    add eax,10h         ; raw_size
                    mov [eax],ecx       ; la nouvelle size
                    add eax,4h
                    mov ebx,index_raw_offset
                    mov [eax],ebx       ;new offset
                                               
                    mov eax,pMemory
                    add eax,v_offset
                    
                    add index_raw_offset,ecx
                    invoke WriteFile,hFileWrite,eax,ecx,ADDR SizeWritten,NULL

                    add compteur,1  ; Section suivante

                    jmp loopws
closefile:
                    invoke UnmapViewOfFile,pwMemory
                    invoke CloseHandle,hwMapFile
                    invoke CloseHandle,hFileWrite
                    invoke MessageBox, NULL,addr MsgBoxText_good,addr MsgCaption_good, MB_OK
                    jmp finerror2
error2:
                    invoke MessageBox, NULL,addr MsgBoxText, addr MsgCaption, MB_OK
finerror2:

                .endif
                popad
            .ELSEIF ax==IDC_ATEND
                invoke GetDlgItemText,hWnd,IDC_FILESIZE,addr textbuffer,10
                invoke SetDlgItemText,hWnd,IDC_IMPORT,addr textbuffer
            .ELSEIF ax==IDC_EXIT
                invoke RegCloseKey,hReg
                invoke UnmapViewOfFile,pMemory
                call   CloseMapFile
                invoke DestroyWindow,hWnd
            .ENDIF
        .ENDIF
    .ENDIF
    invoke DefWindowProc,hWnd,uMsg,wParam,lParam
    ret
WndProc endp
svdirregopen PROC
    invoke RegCreateKeyExA,HKEY_CURRENT_USER,offset szsvKey,0,0,0,\
    1F0003h,0,offset hReg,offset lpdwDisposition
    invoke RegQueryValueExA,hReg,offset szsvDir,0,0,offset dirbuffer,offset szSIZE
    ret
svdirregopen endp
CloseMapFile PROC
        invoke CloseHandle,hMapFile
        mov    hMapFile,0
        invoke CloseHandle,hFileRead
        ret
CloseMapFile endp
end start
