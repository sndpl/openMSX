;-----------------------------------------------------------------------------
; v9990_r22_6_p2.rom
;
; Do SDA/SDB do anything outside P1 mode?
;
; P2 mode has only one pattern layer, so if SDA/SDB are wired to the P1 layer
; logic they should do nothing here.  This ROM shows a P2 screen and toggles
; R#22 between 0x00 and 0xC0 (both bits set) roughly once per second, so a
; single ROM answers the question:
;
;   -> screen visibly changes  => SDA/SDB affect P2 mode as well
;   -> screen never changes    => SDA/SDB are P1 only
;
; openMSX issue #1466.
;-----------------------------------------------------------------------------

PHASE_FRAMES    equ 60              ; ~1 second per phase

    ORG     0x4000

    db      "AB"                    ; auto-start cartridge signature
    dw      Start                   ; INIT
    dw      0, 0, 0                 ; STATEMENT, DEVICE, TEXT
    dw      0, 0, 0                 ; reserved

    INCLUDE "v9990_r22_lib.asm"

Start:
    di
    call    V9BuildP2Screen

MainLoop:
    ld      c, 0x00                 ; SDA and SDB clear
    call    RunPhase
    ld      c, 0xC0                 ; SDA and SDB both set
    call    RunPhase
    jr      MainLoop

; Write C into R#22, then sit still for PHASE_FRAMES frames.
RunPhase:
    ld      a, 22
    ld      b, c
    call    V9SetReg
    ld      b, PHASE_FRAMES
WaitFrames:
    in      a, (V9_INTFLAG)
    and     V9_FLAG_VI
    jr      z, WaitFrames
    ld      a, V9_FLAG_VI
    out     (V9_INTFLAG), a
    djnz    WaitFrames
    ret

    ds      0x4000 - ($ - 0x4000), 0xFF
