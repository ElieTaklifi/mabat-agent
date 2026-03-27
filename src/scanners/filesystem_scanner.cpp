#include "filesystem_scanner.h"

#include <filesystem>
#include <set>
#include <string>

// ════════════════════════════════════════════════════════════════
//  Internal helpers — anonymous namespace, not exported.
// ════════════════════════════════════════════════════════════════
namespace {

// ── Scan roots ────────────────────────────────────────────────
// Every directory that is a legitimate source of executable
// surfaces on a Windows host.  Grouped by threat-hunt priority:
//
//   Standard install paths   — expected, low baseline noise
//   User-writable paths      — elevated suspicion; no admin needed to plant
//   Staging / download paths — very high suspicion; classic dropper locations
//   System directories       — should match known-good binaries; watch for imposters

#ifdef _WIN32
const std::vector<std::filesystem::path> kScanRoots = {

    // ── Standard install paths ────────────────────────────────
    // Low expected noise.  Most software lands here via a proper
    // installer with an Uninstall key; cross-reference with registry.
    { "C:/Program Files"         },
    { "C:/Program Files (x86)"   },

    // ── ProgramData ───────────────────────────────────────────
    // Machine-wide app data.  Agents, AV, system tools write here.
    // Malware also abuses this because it is writable by standard users.
    { "C:/ProgramData"           },

    // ── User profile paths ────────────────────────────────────
    // All-users roaming / local app data.  Scripts and agents
    // frequently live here; so do a large class of infostealers.
    { "C:/Users"                 },   // recursive — captures all profiles

    // ── Windows temporary directories ─────────────────────────
    // Classic dropper / stager locations.  Any executable found
    // here is a near-certain finding that warrants investigation.
    { "C:/Windows/Temp"          },
    { "C:/Temp"                  },
    { "C:/Tmp"                   },

    // ── Windows system directories ────────────────────────────
    // Should contain only known-good Microsoft binaries.
    // Adversaries plant DLLs and EXEs here for DLL-search-order
    // hijacking and binary impersonation (T1574.001, T1036.005).
    { "C:/Windows/Tasks"         },  // scheduled task binaries

    // ── Recycle Bin ───────────────────────────────────────────
    // Malware occasionally hides executables in $RECYCLE.BIN
    // entries to evade casual directory browsing.
    { "C:/$RECYCLE.BIN"          },
};
#endif

// ── Executable extensions ─────────────────────────────────────
// All file types that can be launched directly by Windows or
// through a registered handler without explicit user intent.
// Grouped by threat-hunt priority:
//
//   Tier 1 — direct execution, no handler required
//   Tier 2 — script / interpreted execution (LOLBins, wscript, etc.)
//   Tier 3 — library / plugin code loaded into host processes

#ifdef _WIN32
const std::set<std::string> kExecutableExtensions = {

    // Tier 1 — native Windows executables / loaders
    ".exe",   // standard PE executable
    ".com",   // legacy DOS / PE COM executable
    ".scr",   // screen-saver: identical to .exe, commonly abused
    ".pif",   // program information file: launches .exe, abused for hiding payloads

    // Tier 2 — script interpreters (wscript.exe, cscript.exe, powershell.exe, cmd.exe)
    ".bat",   // batch script
    ".cmd",   // NT command script (same as .bat, different association)
    ".ps1",   // PowerShell script
    ".vbs",   // VBScript (wscript / cscript)
    ".vbe",   // VBScript encoded
    ".js",    // JScript (wscript / cscript)
    ".jse",   // JScript encoded
    ".wsf",   // Windows Script File (multi-language)
    ".wsh",   // Windows Script Host settings file (can launch scripts)
    ".hta",   // HTML Application — runs with full trust outside the browser sandbox

    // Tier 3 — DLL / in-process code loaded by PE loaders or COM
    ".dll",   // dynamic-link library (rundll32 abuse, DLL hijacking)
    ".ocx",   // ActiveX control (regsvr32 abuse — T1218.010)
    ".cpl",   // Control Panel applet (rundll32 / direct launch)
    ".sys",   // kernel driver (also caught by ServiceScanner via registry)
};
#endif

// ── Extension normaliser ──────────────────────────────────────
// std::filesystem::path::extension() preserves original case on
// Windows (NTFS is case-insensitive but stores the original).
// Normalise to lower-case so the set lookup is reliable.

std::string lowerExt(const std::filesystem::path& p) {
    std::string ext = p.extension().string();
    for (char& c : ext)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return ext;
}

}  // namespace

// ════════════════════════════════════════════════════════════════
//  FilesystemScanner::scan
// ════════════════════════════════════════════════════════════════
std::vector<RawSoftwareEntry> FilesystemScanner::scan() {
    std::vector<RawSoftwareEntry> entries;

    try {
#ifdef _WIN32
        for (const auto& root : kScanRoots) {
            if (!std::filesystem::exists(root)) {
                continue;
            }

            for (const auto& item : std::filesystem::recursive_directory_iterator(
                     root, std::filesystem::directory_options::skip_permission_denied)) {

                if (!item.is_regular_file()) {
                    continue;
                }

                const std::string ext = lowerExt(item.path());

                if (kExecutableExtensions.find(ext) == kExecutableExtensions.end()) {
                    continue;
                }

                RawSoftwareEntry entry;
                entry.name   = item.path().stem().string();
                entry.path   = item.path().string();
                entry.source = "filesystem";

                // ── Metadata ───────────────────────────────────
                // Keys mirror the naming convention used across the
                // other scanners so the normalizer and dashboard
                // query-builder can treat them uniformly.

                entry.rawMetadata["extension"]  = ext;

                // Parent directory — useful for path-based triage
                // without re-parsing the full path in the dashboard.
                entry.rawMetadata["directory"]  = item.path().parent_path().string();

                // File size in bytes — anomaly signal: 0-byte files,
                // unusually small EXEs, and suspiciously large scripts.
                std::error_code ec;
                const auto sizeBytes = std::filesystem::file_size(item.path(), ec);
                entry.rawMetadata["fileSizeBytes"] = ec ? "" : std::to_string(sizeBytes);

                // Last-write time as an ISO-8601-style string.
                // ftime_t → system_clock needed for formatting.
                const auto lastWrite = std::filesystem::last_write_time(item.path(), ec);
                if (!ec) {
                    // Convert file_time_type to time_t via the clock cast
                    // available in C++20; fall back to a raw duration count
                    // on C++17 to remain buildable on both standards.
                    const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                        lastWrite - std::filesystem::file_time_type::clock::now()
                        + std::chrono::system_clock::now());
                    const std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
                    std::tm utc = {};
#ifdef _WIN32
                    gmtime_s(&utc, &tt);
#else
                    gmtime_r(&tt, &utc);
#endif
                    char buf[32] = {};
                    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
                    entry.rawMetadata["fileModifiedTime"] = buf;
                } else {
                    entry.rawMetadata["fileModifiedTime"] = "";
                }

                entries.push_back(std::move(entry));
            }
        }
#endif
    } catch (const std::exception&) {
        // Non-fatal for scan pass; return partial discovery results.
    }

    return entries;
}