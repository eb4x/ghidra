/* ============================================================================
 * OVL24_025A  (stub 281f:0000 -> OVERLAY_23::01025A)
 *
 * OVL24_025A itself is a 2-instruction trampoline:
 *     void OVL24_025A(void) { FUN_OVERLAY_23__010246(); return; }   // LES; JMP 010246
 *
 * The real work is FUN_OVERLAY_23__010246 below — a menu / list-selection UI
 * handler: it saves the screen region ([0x83a0..0x83a4]), renders each list
 * item as a NUL-terminated string (the 0x011120 loop calling putchar-style
 * 0x0111a6 and C-runtime helpers de26/d9b4/d8e2), reads keyboard input and
 * dispatches on scancodes — 0x20 (space), 0x1b (ESC), 0x148/0x150 (up/down
 * arrows) seen in the asm — highlights the current entry and returns the
 * chosen index. Called once from the startup path FUN_1d1d_0150.
 *
 * The decompile is partial ("bad instruction data") because the offcut entry
 * corrupts Ghidra's boundary/flow for this routine. Shown as-is.
 * ========================================================================= */

undefined2 FUN_OVERLAY_23__010246(void)   /* the routine OVL24_025A tail-jumps to */
{
  int in_AX;
  int iVar2, iVar3, iVar5;
  undefined2 uVar4;
  int *unaff_BP;
  undefined2 unaff_CS;

  unaff_BP[-0x22] = unaff_BP[-0x22] + 1;
  while( true ) {
    if (unaff_BP[-0x2a] < 3) {
      if (3 < (uint)unaff_BP[-0x2a]) {
                    /* WARNING: Subroutine does not return */
        thunk_FUN_OVERLAY_23__010b9e();
      }
      if (in_AX == 0) {
        *(undefined2 *)0x201e = 1;
      }
      FUN_OVERLAY_23__01119c();
      FUN_OVERLAY_23__0111ab();
      unaff_BP[-2] = 1;
      while (unaff_BP[-2] < unaff_BP[3]) {          /* for each list item ... */
        iVar2 = unaff_BP[-2];
        iVar5 = unaff_BP[4];
        iVar3 = func_0x0000de26(unaff_CS,0x2073);   /* C-runtime helper */
        if (iVar3 != 0) {
          unaff_BP[-1] = *(int *)(iVar5 + iVar2 * 2);
          while (*(char *)unaff_BP[-1] != '\0') {   /* draw the item string   */
            FUN_OVERLAY_23__0111a6(0xd1d,unaff_BP + -1);
            unaff_BP[-1] = unaff_BP[-1] + 1;
          }
        }
        unaff_BP[-2] = unaff_BP[-2] + 1;
        unaff_CS = 0xd1d;
      }
      func_0x0000d9b4(unaff_CS,0x8554);
      uVar4 = FUN_1ade_0048();
      if (*(int *)0x822 != 0) {
        uVar4 = func_0x0000d8e2();
      }
      return uVar4;                                  /* return selection */
    }
    unaff_BP[-0x29] = unaff_BP[-0x29] + 1;
    if (3 < unaff_BP[-0x29]) break;
    unaff_BP[-0x2a] = 0;
  }

  /* ... screen-save / prompt setup (pushes [0x83a0..0x83a4], calls 01044e,
     cursor save/restore 0103b6 / 0103f4) ... truncated by bad instruction data */
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
