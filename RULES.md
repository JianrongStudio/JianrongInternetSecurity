# YARA 规则说明（RULES.md）

本仓库的 YARA 规则体系用于本地静态查杀与启发式检测。规则文件不全部入库（`rules/sigbase/` 下约 752 个规则文件体积过大），本文档说明规则来源、加载机制与扩充方法。

## 一、规则来源

1. **core 家族规则**（`rules/core/`）
   - 约 300 个 `.yar` 文件，按威胁家族前缀命名：
     - `APT_*`：高级持续性威胁家族
     - `MALW_*`：通用恶意软件
     - `RANSOM_*`：勒索软件
     - `RAT_*`：远程控制木马（CobaltStrike、AsyncRAT 等）
     - `WShell_*`：WebShell
     - `EK_*`：漏洞利用套件（Exploit Kit）
     - `TOOLKIT_*`：黑客工具包
     - `POS_*`：POS 机盗卡类
   - 这些规则已并入本地引擎，随发布版本一同分发。

2. **sigbase 规则库**（`rules/sigbase/`）
   - 约 752 个 YARA 规则文件，为扩展特征库。
   - **不入库**（体积过大），仅在本地引擎与发布包中存在。
   - 如需重建，可从开源规则集（如 YARA 官方 rules、Neo23x0/signature-base、Yara-Rules/rules）按目录结构整理。

3. **自定义规则**（`rules/custom/jianrong_custom.yar`）
   - 金荣安全自研规则，针对银狐、WDAC 绕过、本地投递样本等。

4. **默认规则**（`rules/default.yar`）
   - 引擎启动时加载的入口规则集，include 其他规则文件。

5. **已禁用规则**（`rules/_disabled/`）
   - 引擎运行时跳过此目录下的规则；可临时移入 `core/` 启用。

## 二、YaraEngine 加载机制

`Engine/YaraEngine.cs` 负责加载与匹配：

1. 启动时遍历 `rules/core/`、`rules/custom/`、`rules/default.yar`，编译所有 `.yar` 规则。
2. 扫描文件时，将文件字节流传入 YARA 编译器进行匹配。
3. 命中规则后，规则名以 `YARA:<规则名>` 形式上报到 `ScanEngine`，再由 `MlAnalyzer` 按维度评分。
4. `rules/_disabled/` 目录下的规则被跳过，不参与编译。
5. 规则编译失败时记录日志并跳过该文件，不影响其余规则加载。

## 三、如何扩充开源规则

1. **获取规则**：从开源仓库下载 `.yar` 文件，例如：
   - https://github.com/Yara-Rules/rules
   - https://github.com/Neo23x0/signature-base
   - https://github.com/bartblaze/Yara-rules

2. **命名规范**：
   - 按家族前缀命名：`APT_*`、`MALW_*`、`RANSOM_*`、`RAT_*` 等。
   - 一个规则文件可包含多条规则，但文件内 `rule` 名必须全局唯一。

3. **去重**：
   - 新增规则前，用 YARA 编译器在本地试编译，确认无 `duplicated identifier` 错误。
   - 与现有 core 规则重名时，重命名新规则或合并条件。

4. **性能注意**：
   - 规则数量增加会延长扫描时间；单文件扫描超时阈值在 `ScanEngine` 中控制。
   - 避免在 `strings` 中使用过短或过泛的字符串（如 `"http"`、`"dll"`），否则匹配爆炸。
   - 大量 `condition` 中使用 `filesize`、`uint16(0)`、`pe` 模块可显著提速。

5. **更新 sigbase**：
   - `rules/sigbase/` 不入库；更新时直接替换本地目录并重新发布。
   - 建议在发布包说明中记录 sigbase 版本号与更新日期。

## 四、云引擎与 ApiKey 配置

`Engine/CloudQuery.cs` 与 `Engine/CloudVerdictEngine.cs` 实现云端查询：

- 端点：`https://jianrongstudio.pythonanywhere.com`
  - `/api/query_hash`：按哈希查询云查杀判决
  - `/api/submit_tlsh`：提交 TLSH 模糊哈希进行云聚类
- ApiKey 从 `AppConfig.Instance.JinRongApiKey` 读取，**不硬编码在源码中**。

### 配置方式

- 仓库只提供 `config.example.json`（字段模板，`JinRongApiKey` 为空字符串占位）。
- 实际部署时复制为 `config.json`，填入真实 ApiKey：

```json
{
  "JinRongApiKey": "你的真实ApiKey"
}
```

- `config.json` 已在 `.gitignore` 中排除，**不会入库**。
- 未配置 ApiKey 时，云引擎静默跳过（本地引擎仍正常工作），不报错。
