# 可选加密备份（Encrypted Backup）设计说明

## 目标
- 本机数据库保持明文，不改动 SQLite。
- 开启后，**数据库备份在离开本机之前就加密**：WebDAV 上传的、本地备份保存出去的，都是密文；只有输入密码才能解密。
- 默认关闭，可选开启。
- **完全兼容旧的明文备份**：无论开关是否打开，旧的 `.zip` 备份都能照常恢复。

## 文件格式（版本 1）
| 字段 | 长度 |
|---|---|
| 魔数 `SBDENC` | 6 B |
| 格式版本 `1` | 1 B |
| KDF 标识（1 = PBKDF2-SHA256） | 1 B |
| PBKDF2 迭代次数（默认 600,000） | 4 B |
| 分块大小（默认 1 MiB） | 4 B |
| 随机盐 | 16 B |
| 随机基础 nonce | 12 B |
| 头部 HMAC-SHA256 | 32 B |
| 密文分块 … | 每块 = 密文 + 16 B GCM tag |

- 密钥：密码先做 Unicode NFC 规范化，再用 PBKDF2-SHA256 派生 64 字节，前 32 字节为 AES-256-GCM 加密密钥，后 32 字节为头部 HMAC 密钥。
- 第 i 块 nonce = 基础 nonce XOR 块序号；AAD = 完整头部 + 块序号 + 末块标志。可防止篡改、截断、追加、换序、拼接。
- 头部参数有上下限校验，恶意文件无法诱导超大内存分配或超长密钥派生。
- 流式处理，50 MB 备份实测内存占用低于 20 MB。

## 兼容与识别
- 恢复时**只看文件头**判断：以 `PK` 开头走原明文流程，以 `SBDENC` 开头弹窗要密码，与当前开关状态无关；改名后的加密文件同样能识别。
- 加密文件命名为 `*.encrypted.zip`，以沿用现有的 `.zip` 过滤（WebDAV 列表、文件选择器）。代价：解压软件会把它当成损坏的 zip。
- 恢复旧备份时不会覆盖“备份加密”这个开关（加入 `excludedSettings`）。

## 实现位置
- `Rcl/Services/BackupEncryption/`：`BackupCrypto`（加密核心）、`BackupEncryptionService`（文件级加解密、临时文件、命名）、异常类型。
- `Rcl.Hybird/Services/WebDAV/EncryptedWebDAV.cs`：`IWebDAV` 装饰器，上传时加密、下载时按文件头自动解密，只处理 `*.zip`。
- `LocalBackupsPage`：备份时打包后加密并删除明文导出包；恢复时先识别再解密。
- `WebDAVBackupsPage`：密码弹窗、错误提示，结束后清除内存中的密码。
- `Components/BackupEncryption/`：开关与密码弹窗（备份时输两次、至少 8 位；恢复时输一次）。
- DI：Gtk / Maui 调用 `AddWebDAVWithBackupEncryption()`；Server / WebAssembly 调用 `DisableBackupEncryption()`。

## 已知限制
- **忘记密码无法恢复**。密码不保存，每次备份、恢复都要输入。
- 服务器上仍能看到文件名和大小。
- 只加密数据库备份；JSON / MD / TXT / XLSX 导出仍为明文。
- Web 端禁用：WebAssembly 不支持 AES-GCM；Blazor Server 由浏览器异步下载，无法保证“出本机前加密”。Web 端遇到加密文件会给出明确提示。
- `Cache/DB` 暂存目录仍有明文副本（与原行为一致，等同本机明文数据库）。
- 托管内存中的密码字符串无法彻底擦除。
- 若上游 PR #123 合并，它给 `IWebDAV` 新增的方法需要在 `EncryptedWebDAV` 中补透传；其同步文件不是 `.zip`，装饰器不会处理。

## 测试
- `tests/SwashbucklerDiary.Rcl.Tests`（xUnit）：`dotnet test tests/SwashbucklerDiary.Rcl.Tests`。
