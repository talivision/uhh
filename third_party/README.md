# Vendored dependencies (offline builds)

The build uses these sources by default (`UHH_VENDORED_DEPS=ON`), so configuring and
building needs no network. Licences are in each directory (both MIT).

| Directory   | Upstream                                  | Version | Changes |
|-------------|-------------------------------------------|---------|---------|
| safetyhook/ | https://github.com/cursey/safetyhook      | v0.7.0  | `cmake/patch_safetyhook.cmake` already applied (frozen-patch switch, `uhh_trampoline()`); `test/`, `docs/`, `example/` removed |
| zydis/      | https://github.com/zyantific/zydis        | v4.1.0  | includes the `dependencies/zycore` submodule; `tests/`, `msvc/`, `assets/`, `man/` removed |

To refresh: replace the directory with a clean checkout of the new tag (Zydis with
`--recurse-submodules`), re-run `cmake -DSRC=third_party/safetyhook -P cmake/patch_safetyhook.cmake`
for SafetyHook (idempotent), and update this table.
