# AGENTS.md — DVLAA 项目指南

本文件面向 AI 编码代理，介绍 DVLAA（Damn Vulnerable LLM and Agent Application）项目的架构、开发约定与常用命令。阅读者无需任何项目背景。

## 项目概览

DVLAA 是面向大模型与智能体应用安全学习的**中文漏洞靶场**（Flask Web 应用），由五个赛道组成，共 **81 道本地题目**：

- **24 道 OWASP LLM 题目**：10 个大类（LLM01–LLM10），其中 LLM01 提示词注入含 12 个子关卡。
- **10 道 Agent 应用安全题目**（ASI01–ASI10）：每题一个模拟业务系统实验室，题目页提供业务审计任务、工具命令交互与含修复设计的题解（WP）。
- **11 道 AI 综合攻防题目**：独立会话、本地判定器、专属 Flag，WP 覆盖业务基线、状态机关联、复现步骤与修复设计。
- **30 道 AWDP 攻防赛题目**：AWDP01-10 映射 Dify/RAGFlow/Langflow/Flowise/Open WebUI/n8n 公开 CVE；AWDP11-20 改编自 AWDP 赛事真题、AWDP21-30 改编自同赛事真题。附件源码保存在 `dvlaa/content/awdp_finals/<NN>/{vulnerable,fixed}`，共享判定引擎在 `integrations/targets/finals_core.py`（native 目标与 console 回归双端同源，PRELIM_IDS/FINALS_IDS 分段），补丁契约按 language 字段区分 python/text/js 三类静态检查。**双轨环境**——产品仿真模拟轨默认可用（`integrations/targets/`），官方真实容器轨按需一键启动；同一套 Flag 判定、补丁部署与回归逻辑。全部流量经 5080 单端口网关路由，不额外占用宿主机端口。
- **6 道真实赛题**（REAL01–REAL06）：改编自真实 AI 安全竞赛的大模型投毒赛道。附件题提供只读材料工作区 + 交互式判定动作；REAL05 另有独立同源 Web 环境（`/real-web/5/`）。WP 通过按钮按需加载。

代码主体位于 `dvlaa/` 包（`server.py` 为 Flask 主应用），根目录 `app.py` 仅是兼容旧脚本的入口。UI 为 DVLAA 暗色攻防控制台风格，**全项目禁止使用 Emoji 表情符**。

## 技术栈

- **Python 3.11+**（语法使用 `str | None` 等 3.10+ 特性；系统自带 Python 3.9 无法运行）。本机用 `/opt/homebrew/bin/python3.13` 运行测试。
- **Flask 3.0**（Web 服务与 API，无前端框架，Jinja2 模板 + 原生 JS/CSS）。
- **PyTorch + Transformers + accelerate + safetensors**（可选）：本地 HuggingFace 模型推理（`dvlaa/llm_engine.py`）。
- **openai SDK**：DeepSeek / OpenRouter / 硅基流动 / Ollama / OpenAI 兼容接口的统一客户端（`dvlaa/llm_client.py`）。
- **nginx 网关**（`integrations/gateway/nginx.conf`）：单端口路由，`localhost` → 控制台，`awdpNN.localhost` 虚拟主机 → 对应目标应用，`/awdp-target/<id>` 前缀 → 模拟目标服务。
- 依赖清单见 `requirements.txt`；无 lint/格式化工具配置。

## 运行与测试命令

```bash
# 本地启动（开发模式）
python -m dvlaa
# 兼容入口
python app.py

# 运行全部测试（unittest 兼容 pytest；离线运行，不依赖 LLM 后端与容器）
python3.13 -m pytest tests -q          # 当前基线：35 passed
python3.13 -m unittest discover -s tests -v

# 官方 payload 全链路回归（需先启动服务并配置可用 LLM）
python3.13 scripts/verify_official_payloads.py --base-url http://127.0.0.1:5080

# AWDP 模拟目标容器（题目页默认依赖）
cd integrations/targets && docker compose up -d

# 一键 Docker 部署（创建 dvlaa-net + 构建镜像 + 启动模拟目标 + nginx 网关 + console 容器）
./install.sh

# 本地开发常用容器变量
#   DVLAA_AWDP_NATIVE_MODE=native  DVLAA_AWDP_NATIVE_URL=http://dvlaa-awdp-native:5900
#   DVLAA_AWDP_NATIVE_FALLBACK / DVLAA_DIFY_FIXTURE_FALLBACK 默认 true（模拟轨开箱即用）；
#   置为 false 时强制要求官方真实容器轨就绪。
```

环境变量通过 `.env` 配置（模板 `.env.example`），包括各云端 LLM 的 API Key、`DVLAA_ADMIN_USERNAME/DVLAA_ADMIN_PASSWORD`（默认 admin / `DVLAA2026+`）等。

## 代码结构

```text
app.py                     # 兼容入口（转发到 python -m dvlaa）
dvlaa/
  server.py                # Flask 主应用：全部路由、API、会话与进度管理（ASSET_VERSION 在此）
  config.py                # OWASP 关卡/子关卡元数据
  flag_registry.py         # 统一读取 flags.json 中各题目 Flag
  flags.json               # 各赛道 Flag：数字键=OWASP 子关卡；_agent/_extended/_real 各赛道键
  llm_client.py            # 统一 LLM 客户端（deepseek/openrouter/ollama/siliconflow/local）
  llm_engine.py            # 本地 Transformers 推理引擎（可选，缺失时应用照常启动）
  real_challenge_assets/   # 真实赛题附件（adaptertrace.zip 等，按题目编号目录存放）
  challenges/              # OWASP 关卡实现 level1–level10，基类 base.py（含加固提示词）
  content/                 # 题库内容层
    awdp_challenges.py     #   AWDP 30 题元数据、场景、WP（awdp_help_content）
    awdp_finals_content.py #   AWDP11-30 赛事真题题库、补丁契约与源码包加载器
    awdp_finals/           #   赛事附件源码包（<NN>/{vulnerable,fixed}/）
    real_challenges.py     #   REAL 六题题面、材料工作区、判定动作与 WP（writeup_sections）
    agent_challenges.py    #   Agent Top 10 元数据与 WP
    extended_challenges.py #   综合攻防 11 题题库与判定
    official_payloads.py / scenario_content.py / writeup_details.py ...
  modules/                 # 业务模块
    llm01_judge.py …       #   OWASP 各大类判定器
    awdp_native.py         #   AWDP 模拟目标适配器（NATIVE_IDS 覆盖全部 30 题；同源相对路径修复在此）
    awdp_runner.py         #   补丁包静态契约校验与打包
    awdp_web_lab.py        #   Web lab 引导与动作处理
    upstream_targets.py    #   官方上游探测与清单（integrations/upstream/runtime/targets.json）
    dify_integration.py    #   官方 Dify 就绪状态与 runtime_flag
    env_orchestrator.py    #   真实复现环境编排（栈状态/启动/停止 API 后端）
    audit_events.py / conversations.py / modelsel.py / learning_library.py ...
  web/
    templates/             #   Jinja2 页面（awdp_challenge.html、real_challenge.html 等）
    static/js/main.js      #   前端逻辑（AWDP iframe 工作台、导航记忆等）
integrations/
  targets/                 # AWDP 模拟目标：target_server.py + product_skins/（10 个产品仿真皮肤）
    docker-compose.yaml    #   容器 dvlaa-awdp-native（端口 5900，仅内网）
    runtime/*.json         #   每题持久化状态（Flag、patched、attack_solved、records）
  upstream/                # 官方 RAGFlow/Langflow/Flowise/Open WebUI compose 与 bootstrap.sh
  dify/                    # 官方 Dify provision 脚本与运行时状态
  gateway/nginx.conf       # 5080 单端口网关路由配置
tests/                     # 测试（6 个文件，35 个用例，离线运行）
install.sh                 # 一键部署脚本
```

运行时数据存放在 `data/` 目录（Docker 中为 `/app/data` 数据卷）。

## 关键架构约定

- **包结构**：新路由/模块进 `dvlaa/server.py` 或 `dvlaa/modules/`，不要在根目录新增平铺模块。所有文案中文、无 Emoji、遵循 `# ── 分节注释 ──` 风格。
- **AWDP 双轨判定**：题目页 iframe 加载 `/awdp-web/<id>/`，由 `awdp_native.native_target_url()` 决定 302 目标——模拟轨返回同源相对路径 `/awdp-target/<id>`（容器部署下 `_public_base_url()` 对非回环主机名返回空串以退化为相对路径），真实轨返回就绪的官方应用 URL。产品皮肤里的业务请求经 5080 网关直达 `dvlaa-awdp-native:5900`，不经 console 代理；提交 Flag 时由 `_process_awdp_flag_submission()` 以 native 状态文件中的暴露记录补录攻击证据。
- **AWDP 防守流**：上传 `tar.gz`（含 `update.sh`，白名单 cp/mv/rm）→ `awdp_runner.evaluate_patch_archive()` 静态契约检查（按题目 language 字段走 python/text/js 三类检查器） → QuickJS/源码探针 → `_awdp_web_patch_regression()` 执行漏洞阻断 + 业务双回归 → `awdp_native.set_patched()` 切换目标。任一环节失败保留原部署。
- **真实赛题**：附件从 `dvlaa/real_challenge_assets/<NN>/` 提供，页面渲染只读材料工作区；判定动作在后端确定性执行，只有正确操作序列使响应实际出现 Flag 才允许提交；`_real_legacy` 键保存历史编号 Flag，勿删除。
- **Flag 管理**：代码不硬编码 Flag，一律经 `flag_registry.py` 从 `dvlaa/flags.json` 读取；OWASP 用数字键、其他赛道用下划线前缀键。
- **模型后端**：`llm_client.chat()` 统一入口，`provider` 决定云端或本地引擎；未配置模型时状态机题目照常可玩。
- **缓存**：修改模板/CSS/JS 时递增 `dvlaa/server.py` 的 `ASSET_VERSION`。

## 开发约定

- **语言**：项目所有文案、注释、文档、提交说明均为**中文**；代码标识符用英文。
- **禁止 Emoji**：界面、响应与文档中不使用 Emoji 表情符。
- **风格**：模块顶部中文 docstring 说明用途与架构；类型标注可选；无自动格式化配置。
- **WP 质量**：题解需循序渐进（业务背景 → 正常基线 → 攻击面识别 → 复现步骤 → 证据确认 → 修复设计），面向零基础选手；官方 Payload 必须贴合题面业务语境，不得出现与技术实现相关的裸标识符路径。

## 测试说明

- 测试位于 `tests/`（6 个文件，35 个用例，兼容 pytest 与 unittest，离线运行、不依赖 LLM 后端与容器），核心覆盖：
  - `test_flag_registry.py`：各赛道 Flag 键位齐全、格式合法、活动键无重复。
  - `test_official_payloads.py`：官方 payload 与判定逻辑对齐（如 LLM10-1 触发词命中、上传扩展名、payload 结构）。
  - `test_real_challenges.py`：真实赛题判定常量与附件真实数据一致（只读解析 zip/pickletools），六题动作链可通关、错误答案被拒。
  - `test_awdp_finals_engine.py`：AWDP11-30 引擎级契约（20 题攻击链漏洞版泄 Flag、修复版阻断、业务回归通过）、AWDP12/16 正常基线、WP 文案契约、Emoji 检查。
  - `test_web_lab_contract.py`：Web lab 动作覆盖 1-30、AWDP12/16 基线动作、Agent 进度总数。
- 全链路官方 payload 回归使用 `scripts/verify_official_payloads.py`（需先启动服务并配置可用 LLM，脚本自动登录）。
- 新增或修改题目后必须运行完整测试套件；当前基线全部通过。

## 安全注意事项

- 本项目是**故意的漏洞靶场**：题目中的注入、投毒等"漏洞"是训练设计，不要"修复"它们。
- 平台自身的安全边界必须保持：附件题永不反序列化 pickle、不执行附件内容；补丁 update.sh 只解释白名单操作；登录凭据支持环境变量覆盖且页面不泄露 Flag。
- 上传接口保持扩展名与大小限制（学习资料库 Markdown 2 MB / PDF 20 MB 并转义 HTML）。
- 第三方内容许可：综合攻防题库改编自 AISecurityConsortium/AIGoat（CC BY-NC-SA 4.0），详见 `THIRD_PARTY_NOTICES.md`，改编内容须沿用相同许可。

## 部署

- 生产部署走 Docker（`Dockerfile` 基于 `python:3.11-slim`，CPU 版 torch，清华镜像加速）；`install.sh` 一键完成镜像构建、模拟目标启动、nginx 网关与 console 容器编排。
- 模拟目标是常驻 sidecar 容器 `dvlaa-awdp-native`；真实复现环境通过题目页「启动真实复现环境」或 `integrations/upstream/bootstrap.sh up` 按需拉起。
- 全部对外流量收敛到宿主机 5080 单端口；升级 Flag 批次后需重启容器使旧 Flag 失效。
