# DEVELOPER GUIDE — DecryptLab Ultimate

## Layout

```
include/dlu/        public headers (core/, engines/, vpn/, util/)
src/                implementations mirroring include/
apps/cli/           CLI (main.cpp)
apps/web/           installable PWA (index.html, app.js, styles.css, sw.js, manifest)
apps/telegram/      bot.py (stdlib only)
tests/              framework.hpp + test_main.cpp
scripts/            build/install/test/run/package/serve-web
```

## Build & test

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
./build/bin/dlu_tests          # 22 cases
ctest --test-dir build --output-on-failure
```

Warnings are on (`-Wall -Wextra -Wpedantic`). Keep the build warning-clean.

## Conventions

- C++20, namespace `dlu` with sub-namespaces (`core`, `engines`, `vpn`, `util`).
- Hot paths return `Result<T>` (no exceptions); parsing helpers may throw and are
  caught at the boundary.
- Each capability should be honest about its `Support` level.
- Secrets pass through `vpn::mask_*` before display.

## Add a new signature

Append to `src/core/signatures.cpp::builtin_signatures()`:

```cpp
{"cab","MS Cabinet","archive",{0x4D,0x53,0x43,0x46},0,"application/vnd.ms-cab-compressed",{"cab"}},
```

## Add a new format engine

1. Create `include/dlu/engines/foo.hpp` with a report struct + an inspector
   class exposing `Report inspect(const std::string& path)`.
2. Implement in `src/engines/foo.cpp`.
3. Route it in `core/analyzer.cpp::analyze` (by extension or top format id).
4. Add tests in `tests/test_main.cpp`.

The glob in `CMakeLists.txt` picks up new `src/**/*.cpp` automatically
(re-run CMake).

## Add a VPN protocol

- Extend `vpn::Protocol` + `to_string` / `protocol_from_string`.
- Parsing: add a branch in `vpn/uri.cpp` or `vpn/parser.cpp` filling `VpnProfile`.
- Generation: add a case in `vpn/generator.cpp::generate`.
- Emit/convert: handle it in `to_uri` / `generate_outbound_json` as applicable.

## The `IFileEngine` contract (V2 direction)

Today each engine returns a typed report and is wired in the orchestrator.
Section 5 of the brief calls for a common `IFileEngine` (declare formats,
analyze, report, execute authorized op, structured result, error handling).
V2 promotes the current structs to a registered polymorphic interface plus a
plugin loader (`core/plugin_manager`), keeping the same report shapes.

## Shared-core rule

Never duplicate engine logic in the CLI, Web or Telegram layer. The CLI calls
`libdlucore` directly; the bot shells out to `decryptlab`; the PWA mirrors a
documented subset in JS for offline use and can call the core via an optional
API in V2. Results must match across interfaces.
