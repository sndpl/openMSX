10 ' Test pen-down dwell-time ink + multi-color drawing.
20 ' Each pen-up/pen-down transition should deposit an extra ink dot
30 ' at the pen position, producing visibly darker start/end points
40 ' and darker shared vertices between successive D/J commands.
50 '
60 ' What to look for:
70 '   Test 1: start/end corner of each square is darker than the
80 '           three interior corners.
90 '   Test 2: chained D commands form a single continuous path;
100 '           only the two outer endpoints are darker, the shared
101 '           midpoint is NOT darker (no dwell dot between segments).
110 '   Test 3: each line's two endpoints are darker than its middle.
120 '   Test 4: star center is much darker than any single spoke.
130 '   Test 5: printed text has a CLEAN baseline (no dots under chars).
140 '   Test 6: colored lines crossing each other - inks mix at
141 '           every intersection (all 4 colors involved).
142 '
150 LPRINT:LPRINT CHR$(&H1B);"#"
160 '
170 ' --- Test 1: four squares, one per pen color ---
180 FOR I=0 TO 3
190  LPRINT "C";I
200  LPRINT "M";20+I*100;",-20"
210  LPRINT "J 0,-60,60,0,0,60,-60,0"
220 NEXT I
230 '
240 ' --- Test 2: chained D commands, shared midpoint ---
250 LPRINT "C0"
260 LPRINT "M 20,-140"
270 LPRINT "D 200,-140"
280 LPRINT "D 380,-140"
290 '
300 ' --- Test 3: one short horizontal line per pen color ---
310 FOR I=0 TO 3
320  LPRINT "C";I
330  LPRINT "M 20,";-180-I*20
340  LPRINT "D 380,";-180-I*20
350 NEXT I
360 '
370 ' --- Test 4: 12-spoke star radiating from one center point ---
380 LPRINT "C3"
390 FOR A=0 TO 330 STEP 30
400  X=480+COS(A*3.14159/180)*40
410  Y=-300+SIN(A*3.14159/180)*40
420  LPRINT "M 480,-300"
430  LPRINT "D";INT(X);",";INT(Y)
440 NEXT A
450 '
460 ' --- Test 5: text baseline ---
470 LPRINT "C0":LPRINT "S1"
480 LPRINT "M 20,-380"
490 LPRINT "P Text: no baseline dots"
500 '
510 ' --- Test 6: colored lines crossing ---
520 ' Three horizontal lines (C0/C1/C2), three vertical lines
530 ' (C1/C2/C3), plus two diagonals (C0, C3). All four pen colors
540 ' participate and every intersection mixes two different inks.
550 FOR I=0 TO 2
560  LPRINT "C";I
570  LPRINT "M 440,";-440-I*40
580  LPRINT "D 740,";-440-I*40
590 NEXT I
600 FOR I=0 TO 2
610  LPRINT "C";I+1
620  LPRINT "M";480+I*80;",-400"
630  LPRINT "D";480+I*80;",-600"
640 NEXT I
650 LPRINT "C0":LPRINT "M 440,-400":LPRINT "D 740,-600"
660 LPRINT "C3":LPRINT "M 440,-600":LPRINT "D 740,-400"
670 '
680 LPRINT "A"
690 END
