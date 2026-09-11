;-----------------------------------------------------------------------------
; v9990_r22_2_sda.rom - R#22 = 0x80
; SDA set - manual claims layer A and sprites off
;
; openMSX issue #1466.  See README.md for the expected screen layout.
;-----------------------------------------------------------------------------

R22_VALUE   equ 0x80

    ORG     0x4000

    db      "AB"                    ; auto-start cartridge signature
    dw      Start                   ; INIT
    dw      0, 0, 0                 ; STATEMENT, DEVICE, TEXT
    dw      0, 0, 0                 ; reserved

    INCLUDE "v9990_r22_lib.asm"

Start:
    di                              ; no interrupts anywhere in these tests
    call    V9BuildP1Screen
    ld      a, 22
    ld      b, R22_VALUE
    call    V9SetReg
Forever:
    jr      Forever

    ds      0x4000 - ($ - 0x4000), 0xFF
