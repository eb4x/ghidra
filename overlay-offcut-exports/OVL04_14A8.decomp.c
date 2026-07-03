/* ============================================================================
 * OVL04_14A8  (stub 281f:0574 -> OVERLAY_03::0114A8)
 *
 * This decompile is NOT meaningful. The stub target 0114A8 is offcut (it is the
 * last byte of "PUSH word ptr [0x2dae]" in the page's alignment), so Ghidra's
 * function there is a 21-byte garbage decode (SUB AX,0x36ff / LODSB / STOSB /
 * ... / MOV AX,0x57; MOV DX,0x19; RETF). Shown only to document the offcut.
 *
 * The real code around it is a run of far-call argument pushes:
 *     PUSH [0x2dac]; PUSH [0x2daa]; PUSH [0x2da8]; ...   (0114A9 onward)
 * i.e. the intended routine sets up and makes a far call, but its true entry is
 * one byte past the stub target, so 0114A8 as decoded is unusable.
 *
 * Stub caller (live): FUN_130d_0290.
 * ========================================================================= */

undefined2 __cdecl16far OVL04_14A8(void)   /* GARBAGE - offcut decode, not real */
{
  char *unaff_SI;
  char *unaff_DI;

  *unaff_DI = *unaff_SI + '\x01';   /* LODSB/STOSB junk */
  return 0x57;                      /* MOV AX,0x57; RETF */
}
