# WaveGame extension for openMSX (openmsx-plotter)

## Context

The MSX Pico's new "Wave Game" cartridge mode
(https://www.msxpico.com/downloads/WaveGameReadme.txt) has two independent
behaviours:

1. **Game ROM loader.** The physical Pico cart can internally be any of
   five mapper flavours (plain, ASCII 8, ASCII 16, Konami without SCC,
   Konami with SCC). openMSX already has a complete class per flavour and
   robust auto-detection via `RomFactory::guessRomType()` — nothing to do.
2. **WAV music device.** The game writes byte commands to I/O port
   **0x92** (play / loop / fade / pause / queue-next). The Pico plays
   matching `.wav` files (48 kHz mono 16-bit PCM) from its SD card and
   honours sibling `.cfg` files that give loop + start offsets (in sample
   counts). Firmware version is probed at BIOS work RAM `0xF91E`
   (0 = v1.49-v2.06, 1 = v2.07+).

Per the chosen direction, the plan adds a **single standalone extension**
that listens on port 0x92 and plays WAV files out of a user-configurable
**directory** — chosen the same way a floppy drive picks a host folder to
mount as a disk. The user slots the game ROM in one cart slot (with
whatever mapper openMSX already supports) and this new extension in the
other; then uses the **Media menu** to point Wave Game at a directory.

No changes to `RomTypes.hh`, `RomFactory.cc`, `RomInfo.cc`, or any
existing mapper — the change surface stays narrow.

## Architecture

```
                +-----------------------------+
   Media menu   |  ImGuiMedia::showMenu(mb)   |
   (ImGui)      |    -> probes TclObject("wavegame") |
                |    -> adds "Wave Game" entry|
                +--------------+--------------+
                               |  selectDirectory()  /  insertMedia()
                               v
                 Tcl:  wavegame insert <dir>
                               |
                               v
                +-----------------------------+
                |  WaveGameCommand             |  (registered in ctor)
                |    parse & dispatch to ...   |
                +--------------+--------------+
                               v
                +-----------------------------+
                |  WaveGame  :                 |
                |    MSXDevice                 |
                |    ResampledSoundDevice      |
                |    MediaProvider             |
                |                             |
                |  - I/O 0x92 writes           |
                |  - generateChannels()        |
                |  - getMediaInfo/setMedia     |
                +-----------------------------+
```

The extension is a single class `WaveGame` in `src/sound/`. It is
simultaneously:

- An **MSXDevice** so it can be inserted/removed via `-ext` /
  `insert_extension` and serialize state.
- A **ResampledSoundDevice** so it plugs into `MSXMixer` like `SCC`,
  `SamplePlayer`, `DACSound16S` do.
- A **MediaProvider** so the ImGui Media menu picks it up automatically
  and the usual "ejected" / "inserted" UX works.

## Files

### New

| File | Purpose |
|------|---------|
| `src/sound/WaveGame.hh` / `.cc` | The class described above, plus the nested `WaveGameCommand` that exposes `wavegame insert <dir>` / `wavegame eject` to Tcl. |
| `share/extensions/WaveGame.xml` | Default extension descriptor (below). |
| `doc/test_wavegame.bas` | Test ROM: `OUT &H92,...:PRINT PEEK(&HF91E)`. |

### Modified

| File | Change |
|------|--------|
| `src/imgui/ImGuiMedia.cc` | In `showMenu(MSXMotherBoard*)` add a block after the LaserDisc check (~line 701) that tries `TclObject("wavegame").executeCommand(...)` to discover the device, and on success appends a "Wave Game" `MenuItem` that opens a new popup window. Add `wavegameMenu()` analogous to `cassetteMenu()` that uses `selectDirectory()` (helper at line 921) plus an **Eject** and **Open folder** button. Wire recent-directory history the same way `diskMenu()` does. |
| `src/imgui/ImGuiMedia.hh` | Declare `wavegameMenu()` and a `MediaInfo wavegameMediaInfo`. |
| `src/config/devicefactory.cc` | Register new `<WaveGame>` XML device type so `createDevice()` constructs `WaveGame`. Pattern mirrors existing sound-device registrations. |
| `src/sound/build_info.mk` / `CMakeLists.txt` | Add `WaveGame.cc` to sources. |

No changes to any ROM mapper code.

### Reused, not rewritten

- `src/sound/WavData.hh` — full WAV parser (rejects non-PCM, handles
  chunk walking, mmap'ed). Used as-is for each `.wav` in the directory.
- `src/sound/ResampledSoundDevice.hh` — base for auto-rate conversion.
- `src/sound/SamplePlayer.hh` — structural precedent for the ctor
  signature and `generateChannels()` loop. Not subclassed (it assumes a
  numbered basename layout and no loop points).
- `src/MSXMotherBoard.hh::MediaProvider` (line 64) and
  `registerMediaProvider()` (line 250) — exactly what the Media menu
  needs.
- `src/imgui/ImGuiMedia.cc::selectDirectory()` (line 921) — directory
  picker.
- `src/imgui/ImGuiMedia.cc::insertMedia()` (line 1635) — builds the Tcl
  command and handles "Recent" history.
- `src/fdc/DiskChanger.cc` + `DirAsDSK` — reference for how a host
  directory is plumbed through a Tcl command; we're borrowing the idea
  (not the code).

## WaveGame.hh sketch

```cpp
class WaveGameCommand;

class WaveGame final : public MSXDevice
                     , public ResampledSoundDevice
                     , public MediaProvider
{
public:
    explicit WaveGame(const DeviceConfig& config);
    ~WaveGame() override;

    void reset(EmuTime time) override;
    void powerUp(EmuTime time) override;

    void writeIO(uint16_t port, byte value, EmuTime time) override;
    byte peekIO (uint16_t port, EmuTime time) const override;

    // MediaProvider — makes the Media menu discover us and round-trip
    // the "currently-loaded directory" path.
    void getMediaInfo(TclObject& result) override;  // {"target", dir, "type", "directory"}
    void setMedia   (const TclObject& info, EmuTime time) override;

    void setSamplesDir(const std::string& dir); // used by command + setMedia
    void eject();

    template<typename Archive> void serialize(Archive& ar, unsigned version);

private:
    // SoundDevice
    void generateChannels(std::span<float*> bufs, unsigned num) override;
    float getAmplificationFactorImpl() const override;

    void loadSongsFrom(const std::string& dir);
    void handleCommand(byte cmd);
    void writeFirmwareByte(EmuTime time);

    struct Song {
        WavData wav;
        size_t startSample = 0;     // from .cfg (optional)
        size_t loopSample  = 0;     // from .cfg, 0 = no loop
        bool   hasLoop     = false;
    };

    std::string currentDir;         // "" == ejected
    std::vector<Song> songs;

    unsigned current = unsigned(-1);
    unsigned queued  = unsigned(-1);
    size_t   playPos = 0;
    float    fadeGain = 1.0f;
    float    fadeStep = 0.0f;
    bool     paused   = false;
    bool     looping  = false;
    byte     firmwareValue = 1;     // written into 0xF91E on reset

    std::unique_ptr<WaveGameCommand> command; // "wavegame ..." Tcl command
};
```

### `wavegame` Tcl command

Analogous to `diska`, `cda`, `hda`. Registered in the ctor, unregistered
in the dtor. Grammar:

```
wavegame                    -> show current directory (or "empty")
wavegame insert <path>      -> set directory
wavegame eject              -> clear directory
```

`setMedia()` simply forwards to `setSamplesDir()` / `eject()` based on
the Tcl dict contents, so Media-menu picks and CLI scripting go through
the same path.

## ImGui Media-menu hook (src/imgui/ImGuiMedia.cc)

```cpp
// Near line 701, after the LaserDisc block in showMenu(MSXMotherBoard*):
if (motherBoard->findMediaProvider("wavegame")) {
    im::Menu("Wave Game", [&]{
        auto& info = wavegameMediaInfo;
        ImGui::MenuItem("Select directory...", nullptr, &info.show);
    });
}
```

`wavegameMenu()` (new, modelled after `diskMenu()` at line 1276) draws a
popup with:

- A read-only label showing the currently selected directory (queried
  via `TclObject("wavegame").executeCommand()`).
- A "Browse..." button invoking `selectDirectory(group, "Wave Game samples
  folder", current, ...)`.
- "Insert" / "Eject" buttons that call `insertMedia(TclObject("wavegame"),
  item)` / `execute(makeTclList("wavegame", "eject"))`.
- A "Recent" dropdown (reuses the existing recent-list machinery).

This is the same UX pattern used for "dir as disk" at line 1332.

## Extension XML

`share/extensions/WaveGame.xml`:

```xml
<?xml version="1.0" ?>
<!DOCTYPE msxconfig SYSTEM 'msxconfig2.dtd'>
<msxconfig>
  <info>
    <manufacturer>MSX Pico</manufacturer>
    <code>WaveGame</code>
    <release_year>2025</release_year>
    <description>MSX Pico Wave Game audio cartridge. Streams WAV music
      files on I/O port 0x92. Use Media > Wave Game to point it at a
      directory of NN.wav / NN.cfg files.</description>
    <type>Cartridge</type>
  </info>
  <devices>
    <WaveGame id="WaveGame">
      <firmware>1</firmware>   <!-- 0 = v1.49-2.06, 1 = v2.07+ -->
      <sound>
        <volume>9000</volume>
      </sound>
    </WaveGame>
  </devices>
</msxconfig>
```

No `<samples>` element — the directory lives in the MediaProvider state,
set via the Media menu. This matches how disk drives start empty and the
user inserts media after the fact.

## Typical user flow

```
1. openmsx -cart GAME.rom -romtype KonamiSCC -ext WaveGame
2. Menu -> Media -> Wave Game -> Select directory... -> /path/to/songs
3. Game writes `OUT &H92,<cmd>` -> WAV plays through the MSX mixer
```

From Tcl / CLI:

```
insert_extension WaveGame
wavegame insert /path/to/songs
```

## Port 0x92 caveat

On real MSX hardware port 0x92 is unused in the official spec but some
extensions stomp on it. We only register with `register_IO_Out`, never
reads. Note this in `<description>` so users can avoid combining Wave
Game with a (hypothetical) device that also writes 0x92.

## Verification

1. **Build**: `make staticbindist` clean (no new warnings).
2. **Unit test** `src/sound/WaveGameTest.cc`:
   - Construct with a `setSamplesDir(tmp)` containing `00.wav`,
     `00.cfg`.
   - `handleCommand(CMD_PLAY); handleCommand(0);` -> `current == 0`,
     `playPos == startSample`.
   - `generateChannels()` across a long buffer -> loop wraps at
     `loopSample`.
   - Fade command ramps `fadeGain` to ~0 within the documented frame
     count.
3. **Tcl command round-trip**:
   ```tcl
   insert_extension WaveGame
   wavegame insert /tmp/songs
   wavegame                          ;# -> "/tmp/songs"
   wavegame eject
   ```
4. **Media menu**: with the extension inserted, `Menu -> Media -> Wave
   Game` exists, shows current directory, opens directory picker, inserts
   via Tcl, updates label on success.
5. **Firmware byte**: after reset, `PEEK(&HF91E)` in BASIC returns `1`.
6. **Smoke test**: `openmsx -ext WaveGame -cart doc/test_wavegame.bas`
   boots to a BASIC program that starts song 0 and prints the firmware
   byte.
7. **Regression**: unchanged behaviour for `-ext MegaFlashROM_SCC+`,
   `-ext Konami_Ultimate_Collection`, standard disk drives (still appear
   in Media menu, still pick folders via "dir as disk").

## Out of scope (deliberate YAGNI)

- No new `RomType`, no `RomWaveGame` mapper class. Users pick the mapper
  for their game ROM with openMSX's existing `-romtype` / XML
  `<mappertype>` mechanism.
- Per-title XMLs baking in a fixed directory — the Media menu makes this
  unnecessary. A user can still write one if they want to script things.
- Watching the directory for changes. Songs are re-scanned only on
  insert / eject.
- Anything other than 48 kHz mono 16-bit PCM — `WavData` supports more,
  but the hardware mandates this and non-conforming files are rejected
  at load with a clear `MSXException`.
