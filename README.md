[English](https://github.com/vu1Art1st/fileleak/blob/main/README.md) | [简体中文](https://github.com/vu1Art1st/fileleak/blob/main/README_CN.md)

# FileLeak

A comprehensive file leakage exploitation tool that integrates the strengths of five major tools — GitHack, GitHacker, ds_store_exp, dumpall, and dvcs-ripper — supporting automatic detection and exploitation of 7 leakage types.

## Supported Leak Types

| Type | Description | Scenarios |
|------|-------------|-----------|
| Git | `.git` directory leakage, supports quick/full recovery | Source code leaks, commit history, reflog, stash recovery |
| SVN | `.svn` directory leakage, auto-detects version | SVN 1.7+ (wc.db) and legacy versions, restore deleted files |
| Mercurial | `.hg` directory leakage | dirstate/fncache parsing and recovery |
| Bazaar | `.bzr` directory leakage | dirstate/pack files, repository/packs/ download |
| CVS | `CVS/` directory leakage | Recursive Entries parsing, download Baseline/Tag metadata |
| DS_Store | macOS `.DS_Store` file leakage | Recursive directory structure discovery, optional raw file saving |
| Directory Listing | Web server with Directory Listing enabled | Auto-crawl and download all files |

## Core Features

- **asyncio Async Architecture** — High-concurrency downloads with excellent performance
- **Smart 404 Detection** — Automatically identifies servers returning fake 200 responses
- **Plugin-based Design** — BaseDumper base class + 7 independent Dumper modules, easy to extend
- **Dual Git Modes** — `--quick` for fast current source recovery / `--full` for complete repository history recovery
- **SVN Full Copy** — `--full-copy` creates a complete `.svn` working copy, restoring deleted files
- **DS_Store Raw Files** — `--save-raw` saves original `.DS_Store` files for later analysis
- **Bazaar Enhanced** — Supports repository/packs/ directory, auto-downloads pack files
- **CVS Metadata** — Downloads Baseline, Tag, Options and other complete CVS metadata
- **Proxy Support** — HTTP/SOCKS5 proxy
- **Random User-Agent** — Rotating UA to reduce detection risk
- **Resume Support** — `--resume` skips already downloaded files
- **Honeypot Detection** — Path traversal protection and anomaly detection
- **Colorized Output** — Beautiful progress display via Rich library

## Installing Dependencies

### Using uv (Recommended)

```bash
cd fileleak
uv sync
```

### Using pip

```bash
cd fileleak
pip install -r requirements.txt
```

Dependencies:
- aiohttp >= 3.8.0
- aiohttp-socks >= 0.7.0
- click >= 8.0.0
- rich >= 12.0.0

## Usage

### Running Directly (No Installation Required)

```bash
# Using Python script
python fileleak.py -u <URL>

# Or using uv
uv run fileleak.py -u <URL>
```

### After Installation

```bash
# Install via pip
pip install -e .
fileleak -u <URL>

# Or install via uv
uv sync
uv run fileleak -u <URL>
```

## Examples

### Git Leak Exploitation

```bash
# Quick mode - recover current version source only
python fileleak.py -u http://target.com/.git/ --quick

# Full mode - recover all historical commits, reflog, stash
python fileleak.py -u http://target.com/.git/ --full

# Sample output:
# [+] Found 15 commit hashes in logs
# [+] Downloading commit objects ...
# [+] fsck round 1/10 ...
# [+] Found 6 missing objects
# [+] git reset --hard completed
# [+] Full dump complete
```

### SVN Leak Exploitation

```bash
# Standard mode - download current version files and deleted files
python fileleak.py -u http://target.com/.svn/

# Full copy mode - create a complete .svn working copy structure
python fileleak.py -u http://target.com/.svn/ --full-copy

# Sample output (full copy mode):
# [*] Downloading SVN metadata files...
# [*] Downloading wc.db ...
# [+] Found 2 file(s) in wc.db
# Downloaded: 6 | Failed: 1 | Skipped: 2
# 
# Output directory structure:
# output/svn/target/.svn/
# ├── format
# ├── wc.db
# ├── entries
# ├── pristine/
# │   ├── bf/bf45c36a4dfb73378247a6311eac4f80f48fcb92.svn-base
# │   └── 00/0018e10c8b931e075aeb9116b885e9be4bbad794.svn-base
# ├── index.html           # Current version file
# └── flag_187671701.txt   # Deleted file (recovered from PRISTINE)
```

### Bazaar Leak Exploitation

```bash
# Standard mode - download .bzr metadata and restore working files
python fileleak.py -u http://target.com/.bzr/

# Sample output:
# [BzrDumper] Downloading metadata files...
# [BzrDumper] Downloading 3 pack file(s)...
# [green]bzr revert succeeded[/green]
```

### CVS Leak Exploitation

```bash
# CVS leak - recursively download all subdirectory files
python fileleak.py -u http://target.com/CVS/

# Downloaded metadata files:
# - CVS/Root, CVS/Repository, CVS/Entries
# - CVS/Baseline, CVS/Tag, CVS/Options
# - CVS/Checkin.prog, CVS/Update.prog
```

### DS_Store Leak Exploitation

```bash
# Standard mode - only parse and download discovered files
python fileleak.py -u http://target.com/.DS_Store

# Save raw mode - also save the .DS_Store file itself
python fileleak.py -u http://target.com/.DS_Store --save-raw

# Sample output:
# Found 12 entries in http://target.com/.DS_Store
# Downloaded: 8 | Failed: 2 | Skipped: 0
# 
# With --save-raw:
# output/ds_store/target/
# ├── .DS_Store              # Original .DS_Store file
# ├── index.html
# ├── style.css
# └── ...
```

### Proxy and Advanced Options

```bash
# Use SOCKS5 proxy
python fileleak.py -u http://target.com/.git/ --proxy socks5://127.0.0.1:1080

# Use HTTP proxy
python fileleak.py -u http://target.com/.git/ --proxy http://127.0.0.1:8080

# High concurrency + skip SSL verification
python fileleak.py -u http://target.com/.git/ -t 50 --no-ssl-verify

# Debug mode + timeout setting
python fileleak.py -u http://target.com/.git/ -vv --timeout 60
```

## Technical Comparison

| Feature | dvcs-ripper | fileleak (Optimized) |
|---------|-------------|----------------------|
| DS_Store Parsing | ✓ | ✓ |
| DS_Store Raw Files | ✓ | ✓ (`--save-raw`) |
| Bazaar Pack Download | ✓ | ✓ (Fixed) |
| Bazaar Revert | ✓ | ✓ |
| CVS Recursion | ✓ | ✓ |
| CVS Metadata | Basic | Complete (Baseline/Tag etc.) |
| SVN PRISTINE | ✓ | ✓ |
| SVN Full Copy | Partial | ✓ (`--full-copy`) |
| SVN Deleted Files | ✓ | ✓ (Auto-recovery) |
| Git Reflog | ✓ | ✓ |
| Git Stash | ✓ | ✓ (Enhanced) |
| Output Friendliness | Requires post-processing | Direct file output |
| Cross-platform | Perl dependency | Pure Python implementation |
| Async Concurrency | ✗ | ✓ (asyncio) |
| Smart 404 Detection | ✗ | ✓ |

### Complete Parameter List

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-u, --url` | Target URL (required) | - |
| `-o, --output` | Output directory | Auto-generated |
| `-t, --threads` | Concurrency count | 20 |
| `--proxy` | Proxy address (http/socks5) | None |
| `--full` | Git full recovery mode (recover all history commits) | Off |
| `--quick` | Git quick mode (current version only) | Default |
| `--full-copy` | SVN full copy mode (create .svn working directory structure) | Off |
| `--save-raw` | DS_Store save raw .DS_Store files | Off |
| `--no-ssl-verify` | Ignore SSL verification | Off |
| `-v, --verbose` | Verbose output (stackable: -v INFO, -vv DEBUG) | Off |
| `--resume` | Resume download (skip already downloaded files) | Off |
| `--timeout` | Request timeout (seconds) | 30 |
| `--type` | Force type (git/svn/hg/bzr/cvs/ds_store/dir) | Auto-detect |
| `--version` | Show version number | - |

## Project Structure

```
fileleak/
├── fileleak.py              # Script entry (run via python fileleak.py)
├── fileleak/
│   ├── __init__.py
│   ├── __version__.py
│   ├── cli.py              # Click CLI definition
│   ├── core/
│   │   ├── base.py         # BaseDumper base class
│   │   ├── http.py         # Async HTTP client
│   │   └── utils.py        # Utility functions
│   ├── dumpers/
│   │   ├── git.py          # Git Dumper
│   │   ├── svn.py          # SVN Dumper
│   │   ├── hg.py           # Mercurial Dumper
│   │   ├── bzr.py          # Bazaar Dumper
│   │   ├── cvs.py          # CVS Dumper
│   │   ├── ds_store.py     # DS_Store Dumper
│   │   └── directory.py    # Directory Listing Dumper
│   └── data/
│       └── user_agents.txt # User-Agent list
├── requirements.txt
└── setup.py
```

## Tech Stack

- Python 3.9+
- aiohttp — Async HTTP requests
- aiohttp-socks — SOCKS proxy support
- click — CLI framework
- rich — Colorized terminal output

## Design Highlights

1. **Five-in-One** — Combines GitHack's lightweight speed, GitHacker's full recovery, ds_store_exp's recursive probing, dumpall's async architecture, and dvcs-ripper's multi-system support
2. **Auto-Detection** — Automatically identifies leak type from URL path, no manual specification needed
3. **Intelligent Fault Tolerance** — Fake 404 detection, request retries, path safety validation, honeypot detection
4. **Easy to Extend** — Adding new leak types only requires subclassing BaseDumper and implementing the `start()` method
5. **Comparable to dvcs-ripper** — Achieves dvcs-ripper's recovery capability with a better user experience
6. **Cross-Platform Support** — Pure Python implementation, fixed Windows compatibility issues
7. **Direct Output** — No post-processing required, directly outputs readable files
8. **High Concurrency** — asyncio async architecture, significantly outperforms single-threaded tools

## Changelog

### v1.1.0 (2026-05-31) - Enhanced Against dvcs-ripper

**Git Module**:
- Enhanced stash, remote branch, and reflog scanning
- Improved fsck output parsing (dual stdout+stderr read)
- Support for `broken link` cross-line format parsing
- Windows compatibility fix (subprocess STARTUPINFO)

**SVN Module**:
- Added `--full-copy` option to create complete `.svn` working copy
- Restore deleted files from PRISTINE table (refcount=0)
- Download metadata files (all-wcprops, format, entries)
- Improved filename mapping (repos_path → filename)

**Bazaar Module**:
- Fixed pack file download path (repository/packs/)
- Added metadata: repository/indices, upload, locks
- Optimized dirstate parsing logic

**CVS Module**:
- Added metadata files: Baseline, Tag, Options
- Added script files: Checkin.prog, Update.prog
- Achieved full coverage against dvcs-ripper

**DS_Store Module**:
- Added `--save-raw` option to save original `.DS_Store` files
- Retained parsing and downloading of discovered files

### v1.0.0 (Initial Release)

- Integrated strengths of GitHack, GitHacker, ds_store_exp, dumpall, dvcs-ripper
- Supports 7 leak types
- asyncio async architecture + Rich colorized output
- Smart 404 detection + path safety validation

## Acknowledgements

This project was inspired by and references the following outstanding open-source projects:

| Project | Description | Link |
|---------|-------------|------|
| GitHack | Lightweight and fast Git leak exploitation tool | [github.com/lijiejie/GitHack](https://github.com/lijiejie/GitHack) |
| GitHacker | Tool for complete Git repository history recovery | [github.com/WangYihang/GitHacker](https://github.com/WangYihang/GitHacker) |
| ds_store_exp | macOS .DS_Store file leak exploitation tool | [github.com/lijiejie/ds_store_exp](https://github.com/lijiejie/ds_store_exp) |
| dumpall | Async architecture file leak exploitation tool | [github.com/0xHJK/dumpall](https://github.com/0xHJK/dumpall) |
| dvcs-ripper | Multi-version control system leak exploitation tool | [github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper) |

Thank you to all the authors of the above projects for their contributions to the security community!
