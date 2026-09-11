10 ' Test F (new line) bounds for each rotation
20 ' Expected after fix:
30 '   Rot 0 (Y-, down): still triggers a new page when Y < -1354
40 '   Rot 1 (X-, left):  pen clamps at X = 0
50 '   Rot 2 (Y+, up):    pen clamps at Y = 30
60 '   Rot 3 (X+, right): pen clamps at X = 960
70 ' Each rotation prints a burst of characters with F between them.
80 ' Without the fix, rot 1/2/3 walk off the paper and you see fewer glyphs.
90 ' With the fix, glyphs pile up at the paper edge (overstrike).
100 '
110 LPRINT:LPRINT CHR$(&H1B);"#"
120 LPRINT "S2"
130 '
140 ' --- Rotation 1: feeds X-, start near right edge ---
150 LPRINT "H"
160 LPRINT "M900,-100"
170 LPRINT "Q1"
180 FOR I=1 TO 50
190 LPRINT "PB"
200 LPRINT "F"
210 NEXT I
220 '
230 ' --- Rotation 2: feeds Y+, start near bottom ---
240 LPRINT "H"
250 LPRINT "M100,-1300"
260 LPRINT "Q2"
270 FOR I=1 TO 80
280 LPRINT "PB"
290 LPRINT "F"
300 NEXT I
310 '
320 ' --- Rotation 3: feeds X+, start near left edge ---
330 LPRINT "H"
340 LPRINT "M50,-200"
350 LPRINT "Q3"
360 FOR I=1 TO 50
370 LPRINT "PB"
380 LPRINT "F"
390 NEXT I
400 '
410 ' --- Rotation 0 sanity check: should flush to a new page ---
420 LPRINT "H"
430 LPRINT "Q0"
440 FOR I=1 TO 80
450 LPRINT "PB"
460 LPRINT "F"
470 NEXT I
480 '
490 LPRINT "A"
500 END
