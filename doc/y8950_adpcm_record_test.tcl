# Regression test for the Y8950 (MSX-Audio) ADPCM record-mode freeze.
#
# Background: the MSX-Audio BIOS "record PCM sample" routine (reached from
# MSX-BASIC's `CALL REC PCM (n)`) programs the Y8950 ADPCM unit for
# record-into-sample-RAM (register 0x07 = START|REC|MEMORY_DATA = 0xE0) and then
# waits for the end-of-sample status/IRQ. openMSX used to treat the REC bit as
# "not playing", so the address counter never advanced, EOS/BUF_RDY was never
# raised, and the BIOS busy-waited forever (the emulated MSX appeared frozen).
#
# This test drives the ADPCM record registers directly (no BIOS needed) and
# verifies the unit now advances and completes: it records silence into sample
# RAM (reset value 0xFF -> 0x00) and stops. It does NOT depend on which status
# bit the BIOS polls; the RAM transition only happens when the fixed
# record/advance path runs.
#
# Run with any Y8950-equipped machine + the Panasonic FS-CA1 extension, e.g.:
#   openmsx -machine Sony_HB-F700S -ext Panasonic_FS-CA1 \
#           -script doc/y8950_adpcm_record_test.tcl
# Exits 0 on PASS, 1 on FAIL.

set renderer none
set throttle off
set save_settings_on_exit off

set regs "Panasonic FS-CA1 MSX-Audio regs"
set ram  "Panasonic FS-CA1 MSX-Audio RAM"

proc fail {msg} { puts stderr "Y8950 ADPCM record test: FAIL - $msg"; exit 1 }
proc pass {msg} { puts stderr "Y8950 ADPCM record test: PASS - $msg"; exit 0 }

# Let power-on reset settle: Y8950Adpcm::reset() clears sample RAM to 0xFF.
after time 3 {
    if {[debug read $::ram 0] != 0xFF} {
        fail "sample RAM not at reset value 0xFF before recording"
    }

    # Program ADPCM for record-into-sample-RAM:
    debug write $::regs 0x09 0x00   ;# START ADDR low  -> startAddr = 0
    debug write $::regs 0x0A 0x00   ;# START ADDR high
    debug write $::regs 0x0B 0x10   ;# STOP ADDR low   -> RAM bytes 0..~0x43
    debug write $::regs 0x0C 0x00   ;# STOP ADDR high
    debug write $::regs 0x10 0x00   ;# DELTA-N low
    debug write $::regs 0x11 0x80   ;# DELTA-N high    -> delta = 0x8000
    debug write $::regs 0x04 0x10   ;# unmask EOS IRQ (R04 bit4)
    debug write $::regs 0x07 0xE0   ;# START | REC | MEMORY_DATA -> record into RAM

    # Advance emulated time well past the record duration.
    after time 3 {
        set b0  [debug read $::ram 0]
        set b16 [debug read $::ram 16]
        set b40 [debug read $::ram 40]
        if {$b0 == 0 && $b16 == 0 && $b40 == 0} {
            pass "record advanced and wrote silence into sample RAM (no freeze)"
        } else {
            fail "sample RAM still 0xFF (b0=$b0 b16=$b16 b40=$b40); record mode did not advance -> BIOS would hang"
        }
    }
}
