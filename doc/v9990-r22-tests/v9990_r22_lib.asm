;-----------------------------------------------------------------------------
; Shared V9990 helpers + test screens for the R#22 SDA/SDB tests.
;
; openMSX issue #1466 - https://github.com/openMSX/openMSX/issues/1466
;
; R#22 bits 7 (SDA) and 6 (SDB) are an undocumented setting; they appear only
; on http://msxbanzai.tni.nl/v9990/manual.html which claims:
;       SDA: Set to "1" to disable layer "A" and sprites.
;       SDB: Set to "1" to disable layer "B" and sprites.
; Real hardware contradicts the "and sprites" part, so these ROMs are built to
; pin the behaviour down exactly.  See README.md.
;
; Assemble with sjasmplus (see build.sh).
;-----------------------------------------------------------------------------

; ---- V9990 I/O ports --------------------------------------------------------
V9_VRAM     equ 0x60        ; P#0 VRAM data
V9_PAL      equ 0x61        ; P#1 palette data
V9_CMD      equ 0x62        ; P#2 command data
V9_REGDATA  equ 0x63        ; P#3 register data
V9_REGSEL   equ 0x64        ; P#4 register select
V9_STATUS   equ 0x65        ; P#5 status
V9_INTFLAG  equ 0x66        ; P#6 interrupt flag
V9_SYSCTRL  equ 0x67        ; P#7 system control

; ---- P#6 interrupt flags ----------------------------------------------------
V9_FLAG_VI  equ 0x01        ; vertical display period completed
V9_FLAG_HI  equ 0x02        ; display position (line) reached
V9_FLAG_CE  equ 0x04        ; command completed

; ---- P1 mode VRAM layout (fixed by the hardware) ----------------------------
P1_PAT_A    equ 0x00000     ; layer A pattern data
P1_SPR_PAT  equ 0x30000     ; sprite pattern data (lives in layer A pattern area)
P1_SPR_ATR  equ 0x3FE00     ; sprite attribute table
P1_PAT_B    equ 0x40000     ; layer B pattern data
P1_NAM_A    equ 0x7C000     ; layer A name table
P1_NAM_B    equ 0x7E000     ; layer B name table

; ---- P2 mode VRAM layout ----------------------------------------------------
; Note that P2 puts the sprite attribute table at 0x7BE00, not at 0x3FE00 like
; P1 does.  This is what the manual's P2 VRAM map says and it matches the
; address translation openMSX verified against a real Graphics9000.
P2_PAT      equ 0x00000     ; pattern data           (0x00000-0x77FFF)
P2_SPR_PAT  equ 0x18000     ; sprite pattern data    (shared with pattern data)
P2_SPR_ATR  equ 0x7BE00     ; sprite attribute table (0x7BE00-0x7BFFF)
P2_NAM      equ 0x7C000     ; name table             (0x7C000-0x7FFFF)

; ---- misc -------------------------------------------------------------------
BACKDROP    equ 63          ; palette entry 63 = block 3 / colour 15 (grey)
SPRITES     equ 125         ; number of entries in the sprite attribute table
TILE_ROWS   equ 27          ; visible tile rows (212 lines / 8, rounded up)


;=============================================================================
; Low level helpers
;=============================================================================

; Write value B into register A.
V9SetReg:
    out     (V9_REGSEL), a
    ld      a, b
    out     (V9_REGDATA), a
    ret

; Point the VRAM write pointer at A:DE (A = address bits 18-16, DE = bits 15-0).
; Auto-increment is enabled (AII = 0).  Preserves DE and HL.
V9SetWriteAddr:
    push    af
    xor     a
    out     (V9_REGSEL), a          ; select R#0, register auto-increment on
    ld      a, e
    out     (V9_REGDATA), a         ; R#0  address bits  7-0
    ld      a, d
    out     (V9_REGDATA), a         ; R#1  address bits 15-8
    pop     af
    and     0x07                    ; R#2  address bits 18-16, AII = 0
    out     (V9_REGDATA), a
    ret

; A:DE = A:DE + IX.  Preserves BC and HL.
AddrAddIX:
    push    hl
    push    de
    pop     hl                      ; HL = DE
    push    ix
    pop     de                      ; DE = stride
    add     hl, de                  ; carry tells us if bit 16 overflowed
    push    hl
    pop     de                      ; DE = result
    jr      nc, AddrAddIX_done
    inc     a
AddrAddIX_done:
    pop     hl
    ret

; Load 16 colours into palette block A (0-3) from HL (16 x R,G,B, 5 bits each).
V9LoadPalette:
    ld      c, a
    ld      a, 14
    out     (V9_REGSEL), a          ; R#14 palette pointer
    ld      a, c
    add     a, a
    add     a, a
    add     a, a
    add     a, a
    add     a, a
    add     a, a                    ; block * 64 -> colour block * 16, PLTP = 0
    out     (V9_REGDATA), a
    ld      c, V9_PAL
    ld      b, 48                   ; 16 colours * 3 bytes
    otir
    ret

; Write B rows of C bytes, taken from HL each time, starting at A:DE.
; IX is the distance in bytes between successive rows.
V9WriteRows:
    push    hl                      ; keep the address of the row data
V9WriteRows_row:
    push    bc
    push    af
    push    de
    call    V9SetWriteAddr
    pop     de
    pop     af
    pop     bc
    pop     hl                      ; re-read the row data for every row
    push    hl
    push    bc
    ld      b, c
    ld      c, V9_VRAM
    otir                            ; leaves A and DE alone, unlike a ld a,(hl) loop
    pop     bc
    call    AddrAddIX
    djnz    V9WriteRows_row
    pop     hl
    ret

; Fill a name table starting at A:DE.  HL points at B bytes, one tile number
; per tile row; every row gets C copies of that tile number.  The rows of a
; name table are contiguous, so this is written as one auto-incrementing burst.
V9WriteNameTable:
    push    hl
    call    V9SetWriteAddr
    pop     hl
V9WriteNam_row:
    ld      d, (hl)                 ; tile number -> low byte of the name entry
    inc     hl
    push    bc
    ld      b, c
V9WriteNam_ent:
    ld      a, d
    out     (V9_VRAM), a
    xor     a
    out     (V9_VRAM), a            ; high byte of the name entry
    djnz    V9WriteNam_ent
    pop     bc
    djnz    V9WriteNam_row
    ret

; Write the sprite attribute table at A:DE.  HL points at 4*B bytes of active
; sprite entries; every remaining entry is parked below the screen and marked
; disabled so that uninitialised VRAM can never produce stray sprites.
V9WriteSpriteAttrs:
    call    V9SetWriteAddr
    ld      a, b
    ld      c, a                    ; C = number of active sprites
    add     a, a
    add     a, a
    ld      b, a                    ; 4 bytes per sprite
V9WriteSprAtr_on:
    ld      a, (hl)
    inc     hl
    out     (V9_VRAM), a
    djnz    V9WriteSprAtr_on
    ld      a, SPRITES
    sub     c
    ld      b, a                    ; B = number of unused sprites
V9WriteSprAtr_off:
    ld      a, 216
    out     (V9_VRAM), a            ; Y: below the visible display
    xor     a
    out     (V9_VRAM), a            ; pattern number
    out     (V9_VRAM), a            ; X
    ld      a, 0x10
    out     (V9_VRAM), a            ; attributes: D = 1 (sprite disabled)
    djnz    V9WriteSprAtr_off
    ret


;=============================================================================
; P1 test screen
;
;   tile rows  0- 1   backdrop
;   tile rows  2- 5   ZONE 1  layer A only
;   tile row   6      backdrop
;   tile rows  7-10   ZONE 2  layer B only
;   tile row  11      backdrop
;   tile rows 12-15   ZONE 3  layer A and layer B both opaque (A has priority)
;   tile row  16      backdrop
;   tile rows 17-20   ZONE 4  layer A only, with a BEHIND sprite inside it
;   tile row  21      backdrop
;   tile rows 22-23   ZONE 5  backdrop only, with a FRONT sprite inside it
;   tile rows 24-26   backdrop
;
; Sprite 2 (front, red) also sits inside zone 3.
; R#22 is deliberately never written here - each test ROM sets it itself.
;=============================================================================

V9BuildP1Screen:
    xor     a
    out     (V9_SYSCTRL), a         ; MCS = 0
    ld      hl, P1RegTable
    call    V9ApplyRegTable

    ld      a, 0
    ld      hl, PaletteGreen
    call    V9LoadPalette           ; block 0 -> layer A
    ld      a, 1
    ld      hl, PaletteBlue
    call    V9LoadPalette           ; block 1 -> layer B
    ld      a, 2
    ld      hl, PaletteSprite
    call    V9LoadPalette           ; block 2 -> sprites
    ld      a, 3
    ld      hl, PaletteBackdrop
    call    V9LoadPalette           ; block 3 -> backdrop (colour 63)

    ; tile patterns: 8 rows of 4+4 bytes, pattern rows are 128 bytes apart
    ld      ix, 128
    ld      a, P1_PAT_A >> 16
    ld      de, P1_PAT_A & 0xFFFF
    ld      bc, (8 << 8) | 8
    ld      hl, TileRowData
    call    V9WriteRows
    ld      a, P1_PAT_B >> 16
    ld      de, P1_PAT_B & 0xFFFF
    ld      bc, (8 << 8) | 8
    ld      hl, TileRowData
    call    V9WriteRows

    ; sprite patterns: 16 rows of 3 sprites, rows are 128 bytes apart
    ld      a, P1_SPR_PAT >> 16
    ld      de, P1_SPR_PAT & 0xFFFF
    ld      bc, (16 << 8) | 24
    ld      hl, SpriteRowData
    call    V9WriteRows

    ; name tables: 64 entries per row in P1 mode
    ld      a, P1_NAM_A >> 16
    ld      de, P1_NAM_A & 0xFFFF
    ld      bc, (TILE_ROWS << 8) | 64
    ld      hl, NameRowsA
    call    V9WriteNameTable
    ld      a, P1_NAM_B >> 16
    ld      de, P1_NAM_B & 0xFFFF
    ld      bc, (TILE_ROWS << 8) | 64
    ld      hl, NameRowsB
    call    V9WriteNameTable

    ld      a, P1_SPR_ATR >> 16
    ld      de, P1_SPR_ATR & 0xFFFF
    ld      b, 3
    ld      hl, SpriteAttrP1
    call    V9WriteSpriteAttrs
    ret


;=============================================================================
; P2 test screen - two solid bands plus one front sprite, single layer.
;=============================================================================

V9BuildP2Screen:
    xor     a
    out     (V9_SYSCTRL), a         ; MCS = 0
    ld      hl, P2RegTable
    call    V9ApplyRegTable

    ld      a, 0
    ld      hl, PaletteGreen
    call    V9LoadPalette
    ld      a, 2
    ld      hl, PaletteSprite
    call    V9LoadPalette
    ld      a, 3
    ld      hl, PaletteBackdrop
    call    V9LoadPalette

    ; P2 pattern rows are 256 bytes apart
    ld      ix, 256
    ld      a, P2_PAT >> 16
    ld      de, P2_PAT & 0xFFFF
    ld      bc, (8 << 8) | 8
    ld      hl, TileRowData
    call    V9WriteRows

    ; P2 sprite pattern rows are also 256 bytes apart, 8 bytes per sprite
    ld      a, P2_SPR_PAT >> 16
    ld      de, P2_SPR_PAT & 0xFFFF
    ld      bc, (16 << 8) | 8
    ld      hl, SpriteRowData
    call    V9WriteRows

    ; P2 name table: 128 entries per row
    ld      a, P2_NAM >> 16
    ld      de, P2_NAM & 0xFFFF
    ld      bc, (TILE_ROWS << 8) | 128
    ld      hl, NameRowsP2
    call    V9WriteNameTable

    ld      a, P2_SPR_ATR >> 16
    ld      de, P2_SPR_ATR & 0xFFFF
    ld      b, 1
    ld      hl, SpriteAttrP2
    call    V9WriteSpriteAttrs
    ret


; Apply a table of register/value pairs at HL, terminated by 0xFF.
V9ApplyRegTable:
    ld      a, (hl)
    inc     hl
    cp      0xFF
    ret     z
    ld      b, (hl)
    inc     hl
    push    hl
    call    V9SetReg
    pop     hl
    jr      V9ApplyRegTable


;=============================================================================
; Register tables
;=============================================================================

P1RegTable:
    db   6, 0x05        ; DSPM=0 (P1), DCKM=0, XIMM=1, CLRM=1 (4 bits/pixel)
    db   7, 0x00        ; NTSC, non-interlaced
    db   8, 0x82        ; DISP=1, SPD=0 (sprites enabled), bit 1 is fixed at 1
    db   9, 0x00        ; no interrupts routed to the INT pins
    db  10, 0x00        ; interrupt line
    db  11, 0x00        ; IEHM=0
    db  12, 0x00        ; interrupt X
    db  13, 0x04        ; PLTO: layer A -> block 0, layer B -> block 1
    db  15, BACKDROP    ; backdrop colour
    db  16, 0x00        ; display adjust
    db  17, 0x00        ; layer A scroll Y low
    db  18, 0x00        ; layer A scroll Y high, R512/R256 = 0
    db  19, 0x00        ; layer A scroll X low
    db  20, 0x00        ; layer A scroll X high
    db  21, 0x00        ; layer B scroll Y low
                        ; R#22 is set by the individual test ROMs
    db  23, 0x00        ; layer B scroll X low
    db  24, 0x00        ; layer B scroll X high
    db  25, 0x0C        ; SGBA -> sprite patterns at 0x30000
    db  26, 0x00        ; LCD control
    db  27, 0x00        ; priority control: layer A in front over the whole screen
    db  28, 0x00        ; cursor palette offset
    db  0xFF

P2RegTable:
    db   6, 0x59        ; DSPM=1 (P2), DCKM=1, XIMM=2, CLRM=1
    db   7, 0x00        ; NTSC, non-interlaced
    db   8, 0x82        ; DISP=1, SPD=0 (sprites enabled)
    db   9, 0x00
    db  10, 0x00
    db  11, 0x00
    db  12, 0x00
    db  13, 0x00        ; both palette offsets -> block 0
    db  15, BACKDROP
    db  16, 0x00
    db  17, 0x00
    db  18, 0x00
    db  19, 0x00
    db  20, 0x00
    db  21, 0x00
                        ; R#22 is set by the test ROM
    db  23, 0x00
    db  24, 0x00
    db  25, 0x03        ; SGBA -> sprite patterns at 0x18000
    db  26, 0x00
    db  27, 0x00
    db  28, 0x00
    db  0xFF


;=============================================================================
; Pattern / name table / sprite data
;=============================================================================

; One pattern row holds tile 0 in the first 4 bytes and tile 1 in the next 4.
; 4 bits per pixel, so 4 bytes = 8 pixels = one tile row.
TileRowData:
    db  0x00, 0x00, 0x00, 0x00      ; tile 0: every pixel colour 0 (transparent)
    db  0xFF, 0xFF, 0xFF, 0xFF      ; tile 1: every pixel colour 15 (solid)

; One sprite pattern row: sprite 0 and 2 solid colour 15, sprite 1 colour 14.
SpriteRowData:
    db  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      ; sprite 0
    db  0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE      ; sprite 1
    db  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF      ; sprite 2

; Tile number for each of the 27 visible tile rows.
NameRowsA:
    db  0, 0                        ; rows  0- 1  backdrop
    db  1, 1, 1, 1                  ; rows  2- 5  ZONE 1  layer A only
    db  0                           ; row   6
    db  0, 0, 0, 0                  ; rows  7-10  ZONE 2  (layer A transparent)
    db  0                           ; row  11
    db  1, 1, 1, 1                  ; rows 12-15  ZONE 3  A and B both opaque
    db  0                           ; row  16
    db  1, 1, 1, 1                  ; rows 17-20  ZONE 4  layer A + behind sprite
    db  0, 0, 0, 0, 0, 0            ; rows 21-26

NameRowsB:
    db  0, 0                        ; rows  0- 1
    db  0, 0, 0, 0                  ; rows  2- 5  (layer B transparent)
    db  0                           ; row   6
    db  1, 1, 1, 1                  ; rows  7-10  ZONE 2  layer B only
    db  0                           ; row  11
    db  1, 1, 1, 1                  ; rows 12-15  ZONE 3  A and B both opaque
    db  0                           ; row  16
    db  0, 0, 0, 0                  ; rows 17-20
    db  0, 0, 0, 0, 0, 0            ; rows 21-26

NameRowsP2:
    db  0, 0                        ; rows  0- 1  backdrop
    db  1, 1, 1, 1, 1, 1, 1, 1, 1, 1        ; rows  2-11  solid
    db  0, 0                        ; rows 12-13  backdrop (front sprite here)
    db  1, 1, 1, 1, 1, 1, 1, 1, 1, 1        ; rows 14-23  solid
    db  0, 0, 0                     ; rows 24-26  backdrop

; Sprite attribute entries: Y, pattern, X, attributes.
; Y is one line above the actual display position.
; Attributes: bits 7-6 palette block, bit 5 = 1 means behind the front layer,
;             bit 4 = 1 disables the sprite, bits 1-0 are X bits 9-8.
SpriteAttrP1:
    db  175, 0, 120, 0x80           ; front, red,    over the backdrop (zone 5)
    db  143, 1, 120, 0xA0           ; BEHIND, yellow, inside layer A   (zone 4)
    db  103, 2,  56, 0x80           ; front, red,    inside A over B   (zone 3)

SpriteAttrP2:
    db   95, 0, 240, 0x80           ; front, red, over the backdrop

;=============================================================================
; Palettes - 16 colours of R,G,B, 5 bits per component
;=============================================================================

PaletteGreen:
    DUP 15
    db   0,  0,  0
    EDUP
    db   0, 31,  0                  ; colour 15: bright green

PaletteBlue:
    DUP 15
    db   0,  0,  0
    EDUP
    db   0,  0, 31                  ; colour 15: bright blue

PaletteSprite:
    DUP 14
    db   0,  0,  0
    EDUP
    db  31, 31,  0                  ; colour 14: yellow
    db  31,  0,  0                  ; colour 15: red

PaletteBackdrop:
    DUP 15
    db   0,  0,  0
    EDUP
    db  11, 11, 11                  ; colour 15 (= palette entry 63): grey
