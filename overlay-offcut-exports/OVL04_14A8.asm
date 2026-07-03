; ============================================================================
; OVL04_14A8  —  stub 281f:0574  ->  OVERLAY_03::0114A8  (overlay page 4)
;
; Stub caller (live): FUN_130d_0290
;
; NOTE: The stub target 0114A8 lands INSIDE an instruction under the page's
; dominant alignment: the real code is a run of far-call argument pushes
;   0114a5: PUSH word ptr [0x2dae]   (ff 36 ae 2d)   <- spans 0114a5..0114a8
;   0114a9: PUSH word ptr [0x2dac]   (ff 36 ac 2d)
;   0114ad: PUSH word ptr [0x2daa]   (ff 36 aa 2d)
; so 0114A8 is the last byte (0x2d) of the first PUSH. Decoding FROM 0114A8
; therefore produces garbage. This is the one of the three whose stub-target
; alignment does NOT yield sensible code — the real routine is entered one byte
; later (0114A9 / the PUSH run), so 0114A8 itself is an unusable entry.
;
; The listing below is exactly what Ghidra defined at OVL04_14A8 (the offcut
; garbage function, 0114a8-0114bd). It is NOT meaningful code; kept only to
; document the offcut.
;
;   raw @ 0114a2: fc 19 00 ff 36 ae 2d ff 36 ac 2d ff 36 aa 2d ff
; ============================================================================

0114a8: SUB   AX,0x36ff             ; 2d ff 36   (offcut - not real code)
0114ab: LODSB SI                    ; ac
0114ac: SUB   AX,0x36ff             ; 2d ff 36
0114af: STOSB ES:DI                 ; aa
0114b0: SUB   AX,0x36ff             ; 2d ff 36
0114b3: TEST  AL,0x2d               ; a8 2d
0114b5: PUSH  0x77                  ; 6a 77
0114b7: MOV   AX,0x57               ; b8 57 00
0114ba: MOV   DX,0x19               ; ba 19 00
0114bd: RETF                        ; cb
