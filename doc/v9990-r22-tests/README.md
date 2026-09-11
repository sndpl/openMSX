# V9990 R#22 SDA/SDB test ROMs

Test ROMs for [openMSX issue #1466](https://github.com/openMSX/openMSX/issues/1466).

**If you have a real V9990 (GFX9000 / Video9000 / TRH9000): please run these six
ROMs and post a photo of each.** The section
["What to send back"](#what-to-send-back) says exactly what is needed.

## Why another set of test ROMs?

R#22 bits 7 (SDA) and 6 (SDB) are an **undocumented setting**. They do not
appear in the official Yamaha documentation, only on
<http://msxbanzai.tni.nl/v9990/manual.html>, which claims:

> SDA: Set to "1" to disable layer "A" and sprites.
> SDB: Set to "1" to disable layer "B" and sprites.

openMSX does not implement these two bits at all. They are accepted and stored
(the write mask for R#22 is `0xC1`) and then fed into `scrollBYHigh`, where they
only ever add exact multiples of 512 to the layer B scroll offset and therefore
vanish under the `& 0x1FF` mask. So all four combinations render identically.

In 2023 André Baptista (albs_br) posted four test ROMs and Daemos ran them on a
Panasonic FS-A1ST with a TRH9000. Two things came out of that thread:

* the four ROMs *did* look different on real hardware, and
* with **both** bits set, the sprite was **still visible** — so the "and
  sprites" part of the documentation above is wrong.

Unfortunately the photos were hosted on `msx.pics`, the links are dead, and
there is no copy in the Internet Archive. So the surviving evidence is only
prose, and nobody can now tell from the record which bit hid which layer, or
what became visible in place of a hidden layer. That is what this set is for.

These ROMs also try to answer two questions that were raised in that thread but
never tested (GhostwriterP asked the first one).

## The ROMs

| ROM | R#22 | Purpose |
|---|---|---|
| `v9990_r22_1_none.rom` | `0x00` | reference picture, nothing disabled |
| `v9990_r22_2_sda.rom` | `0x80` | SDA set |
| `v9990_r22_3_sdb.rom` | `0x40` | SDB set |
| `v9990_r22_4_both.rom` | `0xC0` | SDA and SDB set |
| `v9990_r22_5_midframe.rom` | changes during the frame | is R#22 latched once per frame, or does it act immediately? |
| `v9990_r22_6_p2.rom` | toggles `0x00`/`0xC0` | do SDA/SDB do anything in P2 mode? |

ROMs 1-4 are byte-identical apart from the single R#22 value, so any difference
you see between them is caused by SDA/SDB and nothing else:

```
$ cmp -l v9990_r22_1_none.rom v9990_r22_2_sda.rom
   807   0 200
```

They are plain 16 kB auto-starting cartridge ROMs. Nothing is written to R#22
except the one deliberate write, and the screen is built with a bounded number
of VRAM writes (no half-minute full-VRAM clear), so the picture appears
immediately.

## The test screen (ROMs 1-4)

P1 mode, 256x212, layer A in front of layer B over the whole screen
(R#27 = 0, so no PRX/PRY priority split). Five horizontal bands, each 4 tile
rows tall, on a **grey backdrop**:

```
        pixel rows
        ----------
          0- 15   grey backdrop
 ZONE 1  16- 47   layer A opaque, layer B transparent        -> GREEN
          48- 55  grey backdrop
 ZONE 2  56- 87   layer A transparent, layer B opaque        -> BLUE
          88- 95  grey backdrop
 ZONE 3  96-127   layer A AND layer B both opaque            -> GREEN (A wins)
                  + a FRONT sprite at x=56                   -> red square
         128-135  grey backdrop
 ZONE 4 136-167   layer A opaque, layer B transparent        -> GREEN
                  + a BEHIND sprite at x=120                 -> hidden by layer A
         168-175  grey backdrop
 ZONE 5 176-191   backdrop only
                  + a FRONT sprite at x=120                  -> red square
         192-211  grey backdrop
```

Colours are deliberately unambiguous: **layer A is green, layer B is blue, the
backdrop is grey, front sprites are red, and the one behind-sprite is yellow.**
Yellow appears nowhere in the reference picture, because that sprite sits behind
layer A's opaque pixels.

`reference_p1_screen.png` is what ROM 1 looks like (captured from openMSX —
where, today, all four ROMs produce exactly this).

Each zone answers a different question:

* **zones 1 and 2** say which bit hides which layer.
* **zone 3** says what becomes visible where a hidden layer used to be: if it
  turns **blue**, layer B shows through; if it turns **grey**, the layer is
  removed all the way down to the backdrop.
* **zone 4** says whether hiding a layer also releases the sprite priority: if
  the **yellow** square appears, a behind-sprite becomes visible once the layer
  in front of it is disabled.
* **zone 5** is the sprites-are-alive indicator. Its red square has no layer
  pixels anywhere near it, so it should survive unless SDA/SDB really do kill
  sprites.

### Expected results

If SDA/SDB simply hide their layer and leave sprites alone, this is what should
appear (the two cells marked "?" are the genuinely unknown parts):

| | ROM 1 `0x00` | ROM 2 `0x80` SDA | ROM 3 `0x40` SDB | ROM 4 `0xC0` both |
|---|---|---|---|---|
| zone 1 (A only) | green | **grey** | green | **grey** |
| zone 2 (B only) | blue | blue | **grey** | **grey** |
| zone 3 (A over B) | green | **blue?** | green | **grey?** |
| zone 4 (A + behind sprite) | green | **grey + yellow?** | green | **grey + yellow?** |
| zone 5 (front sprite) | grey + red | grey + red | grey + red | grey + red |

If instead the banzai manual is literally correct, ROMs 2, 3 and 4 would show
**no red squares at all**. The 2023 thread says that is not what happens, but
please confirm it.

## ROM 5 - is R#22 latched once per frame?

Several V9990 registers are only sampled at the start of the display period.
This ROM clears SDA during vertical blanking and sets SDA again half way down
the display, once per frame, using the V9990's own display-position flag
(P#6 bit 1, with the line in R#10/R#11) to find the middle of the screen. No
CPU interrupts are involved, the flags are just polled.

* **A horizontal split around line 106** (top and bottom halves differ)
  -> R#22 acts immediately, mid-frame.
* **A picture identical to ROM 1** -> R#22 is latched at display start, because
  at every display start R#22 is 0.

There is no third outcome, so this one is easy to read off a photo.

## ROM 6 - does R#22 affect P2 mode?

P2 mode has only one pattern layer. This ROM shows a P2 screen (two solid green
bands and a red sprite on a grey backdrop, see `reference_p2_screen.png`) and
toggles R#22 between `0x00` and `0xC0` about once per second.

* **The picture visibly changes/flickers** -> SDA/SDB affect P2 mode too.
* **The picture never changes** -> SDA/SDB are P1 only.

## What to send back

For ROMs 1-4: one photo each, with the whole display area visible. Please keep
them labelled — the entire point of this exercise is knowing which picture goes
with which R#22 value, and that is exactly what got lost last time.

For ROM 5: one photo. For ROM 6: a short video, or two photos taken a second
apart, or just a note saying whether anything on screen ever changes.

Also worth mentioning: which V9990 cartridge and which MSX machine, and whether
the machine is PAL or NTSC. These ROMs set R#7 = 0 (NTSC timing), same as the
2023 ROMs, so on a PAL machine the picture may sit high or roll slightly. That
is harmless for this test.

## Building

Needs [sjasmplus](https://github.com/z00m128/sjasmplus):

```sh
./build.sh                              # uses sjasmplus from $PATH
SJASMPLUS=/path/to/sjasmplus ./build.sh # or point at a specific build
```

Each ROM is assembled to exactly 16384 bytes. `v9990_r22_lib.asm` holds the
shared V9990 helpers and the screen data; the six `v9990_r22_N_*.asm` files are
small wrappers that set up their particular case.

## Notes on the VRAM layout used here

Taken from the P1/P2 VRAM maps in the banzai manual, and cross-checked against
openMSX's renderer:

| | P1 | P2 |
|---|---|---|
| pattern data | `0x00000` (layer A), `0x40000` (layer B) | `0x00000` |
| sprite pattern data | shared with pattern data, base from R#25 | shared, base from R#25 |
| sprite attribute table | `0x3FE00` | `0x7BE00` |
| name table | `0x7C000` (A), `0x7E000` (B) | `0x7C000` |

Pattern data is laid out as a 4bpp bitmap cut into 8x8 tiles, so successive
pixel rows of one tile are **128 bytes** apart in P1 and **256 bytes** apart in
P2. The P2 sprite attribute table really is at `0x7BE00` and not at `0x3FE00`;
getting that wrong just makes the sprite silently disappear.
