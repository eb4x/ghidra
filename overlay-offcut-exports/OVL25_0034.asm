; ============================================================================
; OVL25_0034  —  stub 281f:05b6  ->  OVERLAY_24::010034  (overlay page 25)
;
; Stub callers (live): FUN_130d_0290 (2x), FUN_130d_0172, FUN_137f_0228
;
; NOTE: Ghidra could NOT keep a defined function here. The stub target 010034
; is "offcut" relative to the page's dominant (fall-through) disassembly, which
; decodes 010033 as a 4-byte  AND byte ptr [BP+SI+0x928],BL  (bytes 20 9a 28 09)
; that swallows byte 010034. Ghidra's function-body repair pass therefore
; deletes the 010034 function. The bytes DO decode cleanly when entered at
; 010034 (the authoritative runtime entry the overlay manager jumps to).
;
; The listing below is a manual decode from the raw bytes starting at the
; stub-target alignment (010034), i.e. what actually runs when the stub fires:
;
;   raw: 9a 28 09 00 10 83 c4 04 0b d0 74 03 e9 bc 0a 50
;        56 9a 1c 09 00 10 1e 50 ff 36 a8 08 ff 36 96 08
;        9a 1a 03 00 10 83 c4 0c 56 9a 1c 09 00 10 1e 50
; ============================================================================

010034: CALLF  0x1000:0928          ; 9a 28 09 00 10   call main-code helper 0928
010039: ADD    SP,0x4               ; 83 c4 04         pop 2 args
01003c: OR     DX,AX                ; 0b d0            test 32-bit result (DX:AX)
01003e: JZ     0x010043             ; 74 03
010040: JMP    0x010aff             ; e9 bc 0a         (result != 0 -> branch away)
010043: PUSH   AX                   ; 50
010044: PUSH   SI                   ; 56
010045: CALLF  0x1000:091c          ; 9a 1c 09 00 10   call main-code helper 091c
01004a: PUSH   DS                   ; 1e
01004b: PUSH   AX                   ; 50
01004c: PUSH   word ptr [0x08a8]    ; ff 36 a8 08
010050: PUSH   word ptr [0x0896]    ; ff 36 96 08
010054: CALLF  0x1000:031a          ; 9a 1a 03 00 10   call main-code helper 031a
010059: ADD    SP,0xc               ; 83 c4 0c         pop 6 args
01005c: PUSH   SI                   ; 56
01005d: CALLF  0x1000:091c          ; 9a 1c 09 00 10   call helper 091c again
010062: PUSH   DS                   ; 1e
010063: PUSH   AX                   ; 50
;  ... continues (further arg pushes + far calls into the 1000: main segment) ...
