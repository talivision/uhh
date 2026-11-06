#ifndef UHH_PROBE_SYMBOLS_HPP
#define UHH_PROBE_SYMBOLS_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace uhh_sym {

struct symbol_entry {
    std::string name;
    std::uint64_t address = 0;
    std::uint32_t size = 0;
    bool is_export = false;
};

bool init(HANDLE process, std::string &which_dbghelp_or_error);
void register_module(HANDLE process, const std::wstring &image_path,
                     std::uint64_t base, std::uint32_t size_of_image);
void unregister_module(HANDLE process, std::uint64_t base);
bool resolve(HANDLE process, const std::string &module, const std::string &name,
             std::uint64_t &address);
std::string symbolize(HANDLE process, std::uint64_t address);
// The function (from the PDB) that contains address: its start and size. False when
// unknown (no PDB, an export-only symbol has no size, or address is past its end).
bool containing_function(HANDLE process, std::uint64_t address, std::uint64_t &start, std::uint32_t &size);
bool walk_stack(HANDLE process, HANDLE thread, CONTEXT ctx,
                std::uint64_t pc, std::uint64_t sp, std::uint64_t fp,
                std::vector<std::uint64_t> &frames, std::size_t max_frames);
// A virtual unwind from ctx (its pc / sp): after each step, the caller's pc and its stack
// pointer on return (x64: from the images' unwind data, as the OS unwinder). False when
// dbghelp is not up; the list stops where the walk does.
bool unwind_frames(HANDLE process, HANDLE thread, CONTEXT ctx,
                   std::vector<std::pair<std::uint64_t, std::uint64_t>> &pc_sp, std::size_t max_frames);
bool enumerate(HANDLE process, const std::string &module, const std::string &mask,
               std::vector<symbol_entry> &out);
void cleanup(HANDLE process);

std::string active_dbghelp_path();
bool has_symbol_server();

} // namespace uhh_sym

#endif
