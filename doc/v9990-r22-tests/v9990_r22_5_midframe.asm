;-----------------------------------------------------------------------------
; v9990_r22_5_midframe.rom
;
; Does R#22 take effect immediately, or is it latched once per frame?
;
; Every frame this ROM clears SDA during vertical blanking and then sets SDA
; again half way down the display, using the V9990's own display-position
; interrupt flag (P#6 bit 1) to find the middle of the screen.  No CPU
; interrupts are used - the flags are polled, which is why R#9 stays 0.
;
;   -> if SDA acts immediately, the lower half of the screen differs from
;      the upper half (a horizontal split around line 106)
;   -> if SDA is latched at display start, the screen is identical to
;      v9990_r22_1_none.rom, because at every display start R#22 is 0
;
; openMSX issue #1466.
;-----------------------------------------------------------------------------

SPLIT_LINE  equ 106                 ; middle of the 212 visible lines

    ORG     0x4000

    db      "AB"                    ; auto-start cartridge signature
    dw      Start                   ; INIT
    dw      0, 0, 0                 ; STATEMENT, DEVICE, TEXT
    dw      0, 0, 0                 ; reserved

    INCLUDE "v9990_r22_lib.asm"

Start:
    di
    call    V9BuildP1Screen

    ld      a, 10                   ; interrupt line, bits 7-0
    ld      b, SPLIT_LINE
    call    V9SetReg
    ld      a, 11                   ; IEHM = 0 -> use the line in R#10/R#11
    ld      b, 0x00
    call    V9SetReg

MainLoop:
    ; ---- wait until the display period of this frame has finished
WaitVI:
    in      a, (V9_INTFLAG)
    and     V9_FLAG_VI
    jr      z, WaitVI
    ld      a, V9_FLAG_VI | V9_FLAG_HI
    out     (V9_INTFLAG), a         ; clear both flags

    ; ---- inside vertical blanking: SDA off, so the frame starts clean
    ld      a, 22
    ld      b, 0x00
    call    V9SetReg

    ; ---- wait until the raster reaches the middle of the display
WaitHI:
    in      a, (V9_INTFLAG)
    and     V9_FLAG_HI
    jr      z, WaitHI
    ld      a, V9_FLAG_HI
    out     (V9_INTFLAG), a

    ; ---- half way down: SDA on
    ld      a, 22
    ld      b, 0x80
    call    V9SetReg

    jr      MainLoop

    ds      0x4000 - ($ - 0x4000), 0xFF
