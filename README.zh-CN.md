# Authorized AppSec Testing Skill（中文说明）

> English canonical version: [`README.md`](./README.md). 本文件是中文翻译，权威内容以英文版和 `SKILL.md` 为准。

授权 Web、API 和应用安全评估的 CLI 工作流。

**入口文件**：`SKILL.md`（版本号和权威规则在此）。
**状态管理**：`memory-protocol.md`。

## 核心设计

- **证据驱动**：每个确认的发现都有当前任务的原始证据支撑。不单凭路径形状、L3 召回或历史案例定级。
- **门控定级模型**：默认低危；仅当利用链确认闭合时才升为 High/Critical。缺陷存在 ≠ 可利用。
- **分层知识**：`payloads/`（安全层，流程内默认用）→ 可选私有 `references/`（不随公开版本发布，仅在用户显式要求时加载）→ L3（本地历史假设）。
- **覆盖可见**：报告显式暴露未测/降级的测试面，而非隐藏在一份看起来干净的报告背后。

## 核心文件

```text
authorized-appsec/
├── SKILL.md                  # 入口，权威规则
├── memory-protocol.md        # 任务状态管理
├── commands/                 # 方法论和命令参考（9 个文件）
│   ├── capabilities.md       # 运行时工具发现
│   ├── recon.md              # 按能力组织的侦察工作流
│   ├── ports.md              # Web 端口选择
│   ├── stack-mapping.md      # 技术栈 → 漏洞映射
│   ├── threat-modeling.md    # STRIDE 方法论
│   ├── source-code-review.md # 源码审查方法论
│   ├── brute-force.md        # 凭据爆破
│   ├── modern-auth.md        # OTP/滑块/SSO/MFA/令牌生命周期
│   └── authenticated-testing.md  # Phase 3 鉴权测试分支
├── payloads/                 # 55 个漏洞 payload 文件（安全层，流程内）
├── templates/                # 23 个输出模板（含覆盖核对表）
└── scripts/                  # 19 个自动化脚本
```

公开版本不包含 `references/`、`l3/`、历史任务结果、原始证据、截图、HAR/PCAP/Burp 文件或真实报告。`references/` 和 `l3/` 仅作为本地私有扩展存在。

## 中文用户须知

- 所有公开核心文件（SKILL.md、commands、templates、scripts、payloads）均为**英文**，这是 canonical 版本。
- 本 README 是中文翻译文档，帮助中文用户理解 skill 结构。
- 使用时请以英文文件为准；如遇歧义，以 `SKILL.md` 为权威。

## 快速开始

```bash
# 初始化一个测试任务
python3 scripts/init_task.py https://example.com --type url

# 生成结构化输出和报告
python3 scripts/ensure_structured_outputs.py <task_dir>
python3 scripts/generate_report.py <task_dir>
```

详见 [`README.md`](./README.md)（英文）。

## License

本项目使用 Apache License 2.0。详见 [`LICENSE`](./LICENSE)。
