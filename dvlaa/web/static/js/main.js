/*
  DVLAA - Damn Vulnerable LLM and Agent Application
  DVLAA console frontend script
*/

const DVLAA_I18N = {
    zh: {
        dvlaa_console: "DVLAA 控制台",
        collapse_menu: "折叠菜单",
        expand_menu: "展开菜单",
        collapse: "收起",
        expand: "展开",
        control_panel: "控制面板",
        dashboard: "靶场仪表盘",
        model_management: "LLM 模型管理",
        learning: "理论学习",
        llm01: "LLM01: 提示词注入攻击",
        llm02: "LLM02: 敏感信息泄露",
        llm03: "LLM03: 供应链风险",
        llm04: "LLM04: 数据与模型投毒",
        llm05: "LLM05: 输出处理不当与 SSRF",
        llm06: "LLM06: 过度代理与越权",
        llm07: "LLM07: 系统提示词窃取",
        llm08: "LLM08: 向量检索弱点",
        llm09: "LLM09: 虚假信息与幻觉",
        llm10: "LLM10: 资源无节制消耗",
        agent_top10: "Agent 应用安全 Top 10",
        internet_ranges: "互联网 AI 靶场导航",
        online_ranges: "在线靶场导航页",
        service_running: "靶场服务运行中",
        online: "在线",
        scenarios: "攻防场景",
        configured_models: "已接入模型",
        current_model: "当前模型",
        system_guide_title: "[系统指南] DVLAA 漏洞攻防手册",
        close: "关闭",
        loading_guide: "正在加载指南文档...",
        theme_light: "亮色",
        theme_dark: "深色",
        switch_to_light: "切换亮色主题",
        switch_to_dark: "切换深色主题",
        switch_language: "切换语言",
        processing: "处理中",
        send: "发送",
        progress: "通关进度",
        copied: "已复制",
        copy: "复制",
        copy_payload: "复制 Payload",
        defense_patch_example: "防守修复包示例",
        download_patch_example: "下载修复包示例",
        logged_in_as: "登录用户",
        logout: "退出登录",
    },
    en: {
        dvlaa_console: "DVLAA Console",
        collapse_menu: "Collapse menu",
        expand_menu: "Expand menu",
        collapse: "Collapse",
        expand: "Expand",
        control_panel: "Control Panel",
        dashboard: "Range Dashboard",
        model_management: "LLM Model Management",
        learning: "Learning Library",
        llm01: "LLM01: Prompt Injection",
        llm02: "LLM02: Sensitive Information Disclosure",
        llm03: "LLM03: Supply Chain Risk",
        llm04: "LLM04: Data and Model Poisoning",
        llm05: "LLM05: Improper Output Handling & SSRF",
        llm06: "LLM06: Excessive Agency",
        llm07: "LLM07: System Prompt Leakage",
        llm08: "LLM08: Vector and Embedding Weaknesses",
        llm09: "LLM09: Misinformation and Hallucination",
        llm10: "LLM10: Unbounded Consumption",
        agent_top10: "Agent Application Security Top 10",
        internet_ranges: "Internet AI Range Navigator",
        online_ranges: "Online Range Navigator",
        service_running: "Range service running",
        online: "Online",
        scenarios: "Scenarios",
        configured_models: "Configured models",
        current_model: "Current model",
        system_guide_title: "[System Guide] DVLAA Security Handbook",
        close: "Close",
        loading_guide: "Loading guide...",
        theme_light: "Light",
        theme_dark: "Dark",
        switch_to_light: "Switch to light theme",
        switch_to_dark: "Switch to dark theme",
        switch_language: "Switch language",
        processing: "Processing",
        send: "Send",
        progress: "Progress",
        copied: "Copied",
        copy: "Copy",
        copy_payload: "Copy Payload",
        defense_patch_example: "Defensive Patch Example",
        download_patch_example: "Download Fixed Patch Example",
        logged_in_as: "Signed in as",
        logout: "Sign out",
    },
};

const DVLAA_TEXT_TRANSLATIONS = {
    "靶场服务": "Range Service",
    "运行正常": "Running",
    "当前模型": "Current Model",
    "运行架构": "Runtime",
    "题目总量": "Total Challenges",
    "通关进度": "Progress",
    "当前浏览器会话记录": "Current browser session",
    "理论漏洞解释：": "Theory: ",
    "漏洞归类：": "Category: ",
    "难度：": "Difficulty: ",
    "中级": "Medium",
    "初级": "Beginner",
    "高级": "Advanced",
    "已通关": "Solved",
    "开始 LLM 训练": "Start LLM Training",
    "进入 Agent 场景": "Enter Agent Scenario",
    "查看综合题归类": "View Classified Labs",
    "进入题目": "Open Challenge",
    "进入综合题": "Open Lab",
    "漏洞介绍": "Risk Intro",
    "返回首页": "Back Home",
    "上一题": "Previous",
    "下一题": "Next",
    "上一类": "Previous",
    "下一类": "Next",
    "事件背景": "Background",
    "任务目标": "Objective",
    "漏洞解释": "Vulnerability",
    "风险边界": "Risk Boundary",
    "理论定义": "Definition",
    "案例映射": "Case Mapping",
    "本地验证边界": "Local Boundary",
    "答题入口:": "Challenge Entry:",
    "编号:": "ID:",
    "分类:": "Category:",
    "起始线索：": "Starting Hint:",
    "进入答题页面": "Open Challenge",
    "进入综合题": "Open Lab",
    "先学原理再答题": "Learn first, then practice",
    "先学理论再答题": "Learn first, then practice",
    "本题 Flag 验证": "Flag Verification",
    "本题专属提交位": "Dedicated submission",
    "FLAG 令牌值": "FLAG Token",
    "校验本题 Flag": "Submit Flag",
    "查看提示词与源码": "View Prompt & Source",
    "WP 题解": "Writeup",
    "重置对话": "Reset Chat",
    "发送": "Send",
    "处理中": "Processing",
    "系统就绪": "System Ready",
    "状态：等待输入": "Status: Waiting",
    "同类题目": "Related Challenges",
    "同类子题": "Related Sublevels",
    "横向滑动查看更多": "Scroll horizontally for more",
    "题目总数:": "Total:",
    "目标模型:": "Target Model:",
    "目标系统:": "Target System:",
    "Agent 身份:": "Agent Identity:",
    "可用工具": "Available Tools",
    "攻击链任务": "Attack Chain Task",
    "攻击链进度": "Attack Progress",
    "三阶段状态校验": "Three-stage Validation",
    "暂无审计数据": "No audit data",
    "理论概要：": "Theory Summary:",
    "本地场景：": "Local Scenario:",
    "目标系统：": "Target System:",
    "Agent 身份：": "Agent Identity:",
    "互联网 AI 靶场导航": "Internet AI Range Navigator",
    "在线 AI 安全训练入口": "Online AI Security Training",
    "打开外部靶场": "Open External Range",
    "训练重点": "Training Focus",
    "交互方式": "Interaction",
    "外部会话": "External Session",
    "独立": "Independent",
    "外部训练环境": "External Environment",
    "资料标题": "Title",
    "资料分类": "Category",
    "选择文件": "Choose File",
    "上传并加入知识库": "Upload to Library",
    "开始阅读": "Start Reading",
    "全部": "All",
    "LLM 安全": "LLM Security",
    "Agent 安全": "Agent Security",
    "综合理论": "General Theory",
    "返回学习目录": "Back to Library",
    "添加 LLM 配置": "Add LLM Config",
    "添加配置": "Add Config",
    "模型配置": "Model Config",
    "保存配置": "Save Config",
    "取消": "Cancel",
    "编辑": "Edit",
    "删除": "Delete",
    "连接测试": "Test Connection",
    "设为当前模型": "Use Model",
    "设为默认模型": "Set Default",
    "默认": "Default",
    "已启用": "Active",
    "已停用": "Disabled",
    "已安装": "Installed",
    "未下载": "Not Downloaded",
    "待配置": "Not Configured",
    "可用": "Available",
    "配置名称 *": "Config Name *",
    "提供商 *": "Provider *",
    "模型名称 *": "Model Name *",
    "超时时间（秒）": "Timeout (seconds)",
    "备注": "Note",
    "启用此配置": "Enable config",
    "设为默认模型": "Set as default",
    "显示/隐藏": "Show/Hide",
    "获取模型": "Fetch Models",
    "关闭": "Close",
    "DVLAA 大模型与智能体应用安全靶场": "DVLAA Damn Vulnerable LLM and Agent Application",
    "Damn Vulnerable LLM and Agent Application": "Damn Vulnerable LLM and Agent Application",
    "[靶场简介] DVLAA 大模型与智能体应用安全靶场": "[Range Intro] DVLAA Damn Vulnerable LLM and Agent Application",
    "[漏洞矩阵] 靶场全部题目": "[Vulnerability Matrix] All Challenges",
    "OWASP LLM Top 10 · 含按漏洞类型归类的综合题": "OWASP LLM Top 10 · Includes Classified Labs",
    "Agent 应用安全 Top 10": "Agent Application Security Top 10",
    "Web、题目判定与 Flag 服务在线": "Web UI, judges and Flag service are online",
    "LLM、Agent 与综合攻防场景": "LLM, Agent and integrated attack-defense scenarios",
    "阅读漏洞解释后，点击对应题目进入答题页面。": "Read the vulnerability explanation, then open the matching challenge.",
    "阅读漏洞风险理论后，点击对应题目进入答题页面。": "Read the risk theory, then open the matching challenge.",
    "综合题已按漏洞类型归类到对应 OWASP 入口。": "Integrated labs are classified into the matching OWASP entries.",
    "查看各靶场的训练方向与交互方式，再选择进入对应的外部环境。外部站点会在新窗口打开，不影响当前本地靶场进度。": "Review each range's focus and interaction mode, then open the external environment in a new window.",
    "阅读内置中文资料，或上传 Markdown/PDF 资料在靶场中直接浏览": "Read built-in materials or upload Markdown/PDF documents for in-range viewing",
    "学习提示词注入、敏感信息泄露、RAG 安全、工具调用、智能体权限边界与工程防御方法。": "Learn prompt injection, sensitive data exposure, RAG security, tool calling, agent permissions and engineering defenses.",
    "搜索题目、编号或漏洞名称...": "Search challenges, IDs or vulnerability names...",
    "输入提示词攻击 Payload，模拟攻击者与 Agent 的对话...": "Enter a prompt attack payload to interact with the Agent...",
    "输入 Agent 指令或攻击链 Payload...": "Enter an Agent command or attack-chain payload...",
    "输入提示词载荷或题目命令...": "Enter a prompt payload or challenge command...",
    "留空时使用文件名": "Leave blank to use the filename",
    "例如：本地 Ollama": "Example: Local Ollama",
    "编辑时留空将保留原密钥": "Leave blank while editing to keep the existing key",
    "例如：qwen3:8b": "Example: qwen3:8b",
    "配置用途说明": "Configuration note",
    "官方解题说明": "Official solution guide",
    "题目讲解": "Challenge Explanation",
    "解题思路": "Solution Approach",
    "官方 Payload": "Official Payload",
    "补充说明": "Notes",
    "漏洞原理": "Vulnerability Principle",
    "系统提示词关联": "System Prompt Mapping",
    "源码与判定路径": "Source and Judge Path",
    "Payload 设计理由": "Payload Rationale",
    "[WP 题解]": "[Writeup]",
    "[通关指南]": "[Walkthrough]",
    "[题目原理]": "[Challenge Internals]",
    "系统提示词与源码": "Prompt & Source",
    "提示词与源码": "Prompt & Source",
    "系统提示词": "System Prompt",
    "题目配置": "Challenge Config",
    "核心实现": "Core Implementation",
    "教学源码查看器": "Source Viewer",
    "运行时题目配置": "Runtime Challenge Config",
    "正在读取当前题目配置...": "Loading current challenge config...",
    "正在读取当前 Agent 场景配置...": "Loading current Agent scenario config...",
    "暂无系统提示词": "No system prompt",
    "暂无核心实现源码": "No implementation source",
    "源码读取失败：": "Source loading failed: ",
    "题解加载失败，请稍后重试。": "Failed to load writeup. Try again later.",
    "暂无题目讲解": "No challenge explanation",
    "暂无解题思路": "No solution approach",
    "暂无示例载荷": "No sample payload",
    "按题目提示逐步验证漏洞触发条件。": "Follow the challenge hints to validate the trigger conditions step by step.",
    "AWDP 智能体攻防赛": "AWDP Agent Attack & Defense",
    "AI 智能体安全攻防赛": "AI Agent Attack & Defense",
    "进入 AWDP 攻防赛": "Open AWDP Attack & Defense",
    "道攻防双角色题目": "attack-defense role-based challenges",
    "进入攻防场": "Open Attack & Defense",
    "攻击完成": "Attack complete",
    "防守完成": "Defense complete",
    "攻击方任务": "Offense Task",
    "防守方任务": "Defense Task",
    "防守验收": "Defense Acceptance",
    "补丁自动部署": "Automated Patch Deployment",
    "场景线索": "Scenario Clues",
    "按需分析，不直接暴露答案": "Analyze as needed; the answer is not exposed",
    "相关命令面：": "Relevant command surface: ",
    "攻防操作台": "Attack & Defense Workbench",
    "攻击方": "Offense",
    "防守方": "Defense",
    "EXP 等待利用": "EXP Awaiting Exploit",
    "EXP 利用成功": "EXP Exploit Successful",
    "防御等待修复": "Defense Awaiting Patch",
    "防御成功": "Defense Successful",
    "CHECK 等待校验": "CHECK Awaiting Validation",
    "CHECK 检测通过": "CHECK Passed",
    "CHECK 检测失败": "CHECK Failed",
    "目标 Agent 交互终端": "Target Agent Terminal",
    "攻击方会话 · 环境隔离": "Offense session · isolated environment",
    "攻击环境已准备": "offense environment ready",
    "与目标智能体进行真实对话，完成攻击目标后提交本题 Flag。": "Interact with the target agent, complete the attack objective, and submit this challenge's Flag.",
    "模式：攻击方": "Mode: Offense",
    "状态：等待输入": "Status: Waiting for input",
    "攻击方提交": "Offense Submission",
    "取得目标服务返回的 Flag 后，在此进行服务端校验。": "After obtaining the Flag returned by the target service, validate it here.",
    "提交 Flag": "Submit Flag",
    "漏洞服务源码": "Vulnerable Service Source",
    "下载当前轮次的易受攻击版本，用于复现调用链与编写防守补丁。": "Download the vulnerable version for this round to reproduce the call path and write a defensive patch.",
    "下载漏洞源码": "Download Vulnerable Source",
    "环境控制": "Environment Control",
    "清理对话、Flag 校验和补丁部署状态，并恢复本题初始版本。": "Clear chat, Flag validation, and patch state, then restore the initial version.",
    "重置环境": "Reset Environment",
    "提交防护修复包": "Submit Defensive Patch",
    "压缩包将在独立工作区解包；服务端解析": "The archive is unpacked in an isolated workspace; the server parses",
    "中的受限的文件操作，并针对当前场景执行回归验证。": "restricted file operations in it and runs regression checks for this scenario.",
    "下载当前源码": "Download Current Source",
    "压缩包根目录须包含 UTF-8 文本": "The archive root must contain a UTF-8",
    "仅可使用单条": "Only single",
    "文件操作，将修复文件部署到": "file operations may be used to deploy repaired files to",
    "提交后通过自动检查的补丁会记录在本轮提交历史中。": "Patches that pass automated checks are recorded in this round's submission history.",
    "修复包上传": "Patch Upload",
    "选择防护补丁包": "Choose Defensive Patch",
    "仅支持 .tar.gz 或 .tgz，需包含 update.sh": "Only .tar.gz or .tgz with update.sh is supported",
    "上传并验证补丁": "Upload and Validate Patch",
    "提交记录": "Submission Records",
    "刷新记录": "Refresh Records",
    "时间": "Time",
    "类型": "Type",
    "提交内容": "Submission",
    "判定结果": "Verdict",
    "详情": "Details",
    "当前轮次暂无提交记录。": "No submissions in this round.",
    "正在读取本轮提交记录...": "Loading submissions for this round...",
    "正在读取环境状态...": "Loading environment status...",
    "目标服务": "Target Service",
    "Agent 角色": "Agent Role",
    "项目目录": "Project Path",
    "攻击 {{ ch.attack_points }} 分 · 防守 {{ ch.defense_points }} 分": "Offense {{ ch.attack_points }} pts · Defense {{ ch.defense_points }} pts",
    "AI 智能体安全攻防赛 · 攻防训练场景": "AI Agent Attack & Defense · Practice Scenario",
    "WP 题解": "Writeup",
    "查看提示词与源码": "View Prompt & Source",
    "返回首页": "Back to Dashboard",
    "攻防双角色": "Offense & Defense",
    "攻击": "Offense",
    "防守": "Defense",
    "工作台": "Workbench",
    "攻防环境已准备": "Attack & Defense Environment Ready",
    "系统就绪": "System Ready",
    "READY": "READY",
    "Shift+Enter 换行": "Shift+Enter for newline",
    "Enter 发送": "Enter to send",
    "环境状态由服务端记录；提交 Flag 前请确认本轮对话返回的令牌。": "Environment status is recorded server-side; confirm the token returned in this round before submitting the Flag.",
    "FLAG 令牌值": "FLAG token",
    "请先输入从目标服务获得的 Flag。": "Enter the Flag obtained from the target service first.",
    "取得目标服务返回的 Flag 后，在此进行服务端校验。": "After obtaining the Flag returned by the target service, validate it here.",
    "FLAG": "FLAG",
    "SOURCE": "SOURCE",
    "RESET": "RESET",
    "AUDIT": "AUDIT",
    "WORKBENCH": "WORKBENCH",
    "攻击环境已准备": "Offense environment ready",
    "与目标智能体进行真实对话，完成攻击目标后提交本题 Flag。": "Interact with the target agent, complete the attack objective, and submit this challenge's Flag.",
    "目标：": "Target: ",
    "模式：攻击方": "Mode: Offense",
    "状态：等待输入": "Status: Waiting for input",
    "提示：输入 /help 查看当前综合题可用命令；多阶段题目需要按顺序推进状态。": "Tip: enter /help to view available commands; advance multi-stage challenges in order.",
    "防护验收": "Defense Acceptance",
    "补丁自动部署": "Automated Patch Deployment",
    "提交防护修复包": "Submit Defensive Patch",
    "防御补丁已生效": "Defensive patch is active",
    "攻击目标已完成": "Attack objective complete",
    "环境就绪": "Environment ready",
    "题目元数据": "Challenge Metadata",
    "场景线索": "Scenario Clues",
    "攻防状态": "Attack & Defense Status",
    "攻防视图": "Attack & Defense View",
    "攻击方操作": "Offense Controls",
    "攻击方会话": "Offense Session",
    "环境隔离": "Isolated Environment",
    "目标 Agent": "Target Agent",
    "客服策略文本仍包含运行时验证字段": "Customer-support policy still contains a runtime verifier field",
};

Object.assign(DVLAA_TEXT_TRANSLATIONS, (window.DVLAA_I18N_CATALOG && window.DVLAA_I18N_CATALOG.phrases) || {});
Object.entries(DVLAA_I18N.zh).forEach(([key, zh]) => {
    const en = DVLAA_I18N.en[key];
    if (zh && en && zh !== en) DVLAA_TEXT_TRANSLATIONS[zh] = en;
});

const DVLAA_TEXT_REVERSE = Object.fromEntries(
    Object.entries(DVLAA_TEXT_TRANSLATIONS).map(([zh, en]) => [en, zh])
);

const DVLAA_CODE_TRANSLATIONS = {
    "首页": "HOME",
    "学习": "LEARN",
};

const DVLAA_CODE_REVERSE = Object.fromEntries(
    Object.entries(DVLAA_CODE_TRANSLATIONS).map(([zh, en]) => [en, zh])
);

const DVLAA_TITLE_TRANSLATIONS = {
    "DVLAA 靶场仪表盘 - Agent 与 LLM 安全实验室": "DVLAA Range Dashboard - Agent and LLM Security Lab",
    "DVLAA - 互联网 AI 靶场导航": "DVLAA - Internet AI Range Navigator",
    "DVLAA - 理论学习": "DVLAA - Learning Library",
    "DVLAA - LLM 模型管理": "DVLAA - LLM Model Management",
};

const DVLAA_ORIGINAL_TEXT = new WeakMap();
let DVLAA_LANGUAGE_DIRTY = false;

function currentLanguage() {
    return document.documentElement.dataset.lang === "en" ? "en" : "zh";
}

function t(key) {
    const lang = currentLanguage();
    return (DVLAA_I18N[lang] && DVLAA_I18N[lang][key]) || DVLAA_I18N.zh[key] || key;
}

function initThemeToggle() {
    const root = document.documentElement;
    const button = document.getElementById("themeToggleBtn");
    const label = document.getElementById("themeToggleLabel");
    const icon = document.getElementById("themeToggleIcon");

    const savedTheme = root.dataset.theme === "light" ? "light" : "dark";
    root.dataset.theme = savedTheme;

    const syncThemeButton = () => {
        const isLight = root.dataset.theme === "light";
        const labelKey = isLight ? "theme_dark" : "theme_light";
        const titleKey = isLight ? "switch_to_dark" : "switch_to_light";
        if (label) label.textContent = t(labelKey);
        if (icon) icon.textContent = isLight ? "[暗]" : "[亮]";
        if (button) {
            button.setAttribute("aria-label", t(titleKey));
            button.setAttribute("title", t(titleKey));
        }
    };

    syncThemeButton();
    if (!button) return;
    button.addEventListener("click", function () {
        const nextTheme = root.dataset.theme === "light" ? "dark" : "light";
        root.dataset.theme = nextTheme;
        try { localStorage.setItem("dvlaa.theme", nextTheme); } catch (e) {}
        syncThemeButton();
    });
}

function initLanguageToggle() {
    const root = document.documentElement;
    const button = document.getElementById("languageToggleBtn");

    applyLanguage(root.dataset.lang === "en" ? "en" : "zh");
    if (!button) return;
    button.addEventListener("click", function () {
        const nextLang = currentLanguage() === "en" ? "zh" : "en";
        applyLanguage(nextLang);
        try { localStorage.setItem("dvlaa.lang", nextLang); } catch (e) {}
    });
}

function applyLanguage(lang) {
    const root = document.documentElement;
    const normalizedLang = lang === "en" ? "en" : "zh";
    root.dataset.lang = normalizedLang;
    root.lang = normalizedLang === "en" ? "en" : "zh-CN";

    document.querySelectorAll("[data-i18n]").forEach(el => {
        el.textContent = t(el.dataset.i18n);
    });
    document.querySelectorAll("[data-i18n-title]").forEach(el => {
        el.setAttribute("title", t(el.dataset.i18nTitle));
    });
    document.querySelectorAll("[data-i18n-aria-label]").forEach(el => {
        el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
    });

    if (normalizedLang === "en" || DVLAA_LANGUAGE_DIRTY) {
        translateExactText(document.body);
        translateAttributes();
        translateCollapsedCodes();
        DVLAA_LANGUAGE_DIRTY = normalizedLang === "en";
    }
    translateDocumentTitle();
    syncLanguageButton();
    syncStandaloneButtons();
}

function localizeNewContent(root) {
    if (currentLanguage() !== "en" || !root) return;
    translateExactText(root);
    translateAttributes();
    DVLAA_LANGUAGE_DIRTY = true;
}

function syncLanguageButton() {
    const button = document.getElementById("languageToggleBtn");
    const label = document.getElementById("languageToggleLabel");
    if (label) label.textContent = currentLanguage() === "en" ? "中文" : "EN";
    if (button) {
        button.setAttribute("aria-label", t("switch_language"));
        button.setAttribute("title", t("switch_language"));
    }
}

function syncStandaloneButtons() {
    const sidebarToggle = document.getElementById("sidebarToggleBtn");
    if (sidebarToggle) {
        const collapsed = document.body.classList.contains("sidebar-collapsed");
        const key = collapsed ? "expand_menu" : "collapse_menu";
        sidebarToggle.setAttribute("aria-label", t(key));
        sidebarToggle.setAttribute("title", t(key));
    }
    const themeButton = document.getElementById("themeToggleBtn");
    const themeLabel = document.getElementById("themeToggleLabel");
    const isLight = document.documentElement.dataset.theme === "light";
    if (themeLabel) themeLabel.textContent = t(isLight ? "theme_dark" : "theme_light");
    if (themeButton) {
        themeButton.setAttribute("aria-label", t(isLight ? "switch_to_dark" : "switch_to_light"));
        themeButton.setAttribute("title", t(isLight ? "switch_to_dark" : "switch_to_light"));
    }
}

function shouldSkipI18nNode(node) {
    const parent = node.parentElement;
    if (!parent) return true;
    return Boolean(parent.closest("script, style, pre, code, textarea, select, option, #inspectorContent, [data-no-i18n]"));
}

const DVLAA_DYNAMIC_RULES = [
    {
        zh: /^通关进度：(.+)$/,
        en: /^Progress: (.+)$/,
        toEn: value => `Progress: ${value}`,
        toZh: value => `通关进度：${value}`,
    },
    {
        zh: /^共 (\d+) 道题目，综合题按漏洞类型归入 LLM Top 10$/,
        en: /^Total (\d+) challenges; integrated labs are classified into LLM Top 10$/,
        toEn: value => `Total ${value} challenges; integrated labs are classified into LLM Top 10`,
        toZh: value => `共 ${value} 道题目，综合题按漏洞类型归入 LLM Top 10`,
    },
    {
        zh: /^(\d+) 个子题入口$/,
        en: /^(\d+) sublevel entries$/,
        toEn: value => `${value} sublevel entries`,
        toZh: value => `${value} 个子题入口`,
    },
    {
        zh: /^(\d+) 个$/,
        en: null,
        toEn: value => value,
        toZh: value => `${value} 个`,
    },
    {
        zh: /^(\d+) 道$/,
        en: null,
        toEn: value => value,
        toZh: value => `${value} 道`,
    },
    {
        zh: /^题目总数:\s*(\d+) 个子题$/,
        en: /^Total:\s*(\d+) sublevels$/,
        toEn: value => `Total: ${value} sublevels`,
        toZh: value => `题目总数: ${value} 个子题`,
    },
    {
        zh: /^题目总数:\s*(\d+) 个场景$/,
        en: /^Total:\s*(\d+) scenarios$/,
        toEn: value => `Total: ${value} scenarios`,
        toZh: value => `题目总数: ${value} 个场景`,
    },
    {
        zh: /^同类综合题:\s*(\d+) 道$/,
        en: /^Related Integrated Labs:\s*(\d+) items$/,
        toEn: value => `Related Integrated Labs: ${value} items`,
        toZh: value => `同类综合题: ${value} 道`,
    },
    {
        zh: /^(\d+) 道题目$/,
        en: /^(\d+) challenges$/,
        toEn: value => `${value} challenges`,
        toZh: value => `${value} 道题目`,
    },
    {
        zh: /^(\d+) 道基础题 \+ (\d+) 道综合题$/,
        en: /^(\d+) base challenges \+ (\d+) integrated challenges$/,
        toEn: (_value, match) => `${match[1]} base challenges + ${match[2]} integrated challenges`,
        toZh: (_value, match) => `${match[1]} 道基础题 + ${match[2]} 道综合题`,
    },
    {
        zh: /^(\d+) 道 OWASP LLM 题目$/,
        en: /^(\d+) OWASP LLM challenges$/,
        toEn: value => `${value} OWASP LLM challenges`,
        toZh: value => `${value} 道 OWASP LLM 题目`,
    },
    {
        zh: /^(\d+) 道 Agent 安全题目$/,
        en: /^(\d+) Agent security challenges$/,
        toEn: value => `${value} Agent security challenges`,
        toZh: value => `${value} 道 Agent 安全题目`,
    },
    {
        zh: /^(\d+) 道综合攻防题目$/,
        en: /^(\d+) integrated attack-defense challenges$/,
        toEn: value => `${value} integrated attack-defense challenges`,
        toZh: value => `${value} 道综合攻防题目`,
    },
    {
        zh: /^(\d+) 个站点$/,
        en: /^(\d+) sites$/,
        toEn: value => `${value} sites`,
        toZh: value => `${value} 个站点`,
    },
    {
        zh: /^(\d+) 个训练平台$/,
        en: /^(\d+) training platforms$/,
        toEn: value => `${value} training platforms`,
        toZh: value => `${value} 个训练平台`,
    },
    {
        zh: /^(\d+) 项核心能力$/,
        en: /^(\d+) core capabilities$/,
        toEn: value => `${value} core capabilities`,
        toZh: value => `${value} 项核心能力`,
    },
    {
        zh: /^(\d+) 分$/,
        en: /^(\d+) points$/,
        toEn: value => `${value} points`,
        toZh: value => `${value} 分`,
    },
    {
        zh: /^推荐：第 (\d+) 档$/,
        en: /^Recommended: tier (\d+)$/,
        toEn: value => `Recommended: tier ${value}`,
        toZh: value => `推荐：第 ${value} 档`,
    },
    {
        zh: /^第 (\d+) 档$/,
        en: /^Tier (\d+)$/,
        toEn: value => `Tier ${value}`,
        toZh: value => `第 ${value} 档`,
    },
    {
        zh: /^关卡 (\d+(?:\.\d+)?)$/,
        en: /^Challenge (\d+(?:\.\d+)?)$/,
        toEn: value => `Challenge ${value}`,
        toZh: value => `关卡 ${value}`,
    },
    {
        zh: /^关卡 (\d+\.\d+) 攻防环境已准备$/,
        en: /^Challenge (\d+\.\d+) environment ready$/,
        toEn: value => `Challenge ${value} environment ready`,
        toZh: value => `关卡 ${value} 攻防环境已准备`,
    },
    {
        zh: /^关卡 (\d+\.\d+) 攻防会话历史已重置。$/,
        en: /^Challenge (\d+\.\d+) session history has been reset\.$/,
        toEn: value => `Challenge ${value} session history has been reset.`,
        toZh: value => `关卡 ${value} 攻防会话历史已重置。`,
    },
    {
        zh: /^Agent 场景 ASI(\d+) 的上下文状态已清除。$/,
        en: /^Agent scenario ASI(\d+) context state has been cleared\.$/,
        toEn: value => `Agent scenario ASI${value} context state has been cleared.`,
        toZh: value => `Agent 场景 ASI${value} 的上下文状态已清除。`,
    },
    {
        zh: /^当前题目的对话与知识库状态已清除。$/,
        en: /^Current challenge chat and knowledge-base state have been cleared\.$/,
        toEn: () => "Current challenge chat and knowledge-base state have been cleared.",
        toZh: () => "当前题目的对话与知识库状态已清除。",
    },
    {
        zh: /^已获取 (\d+) 个模型$/,
        en: /^Fetched (\d+) models$/,
        toEn: value => `Fetched ${value} models`,
        toZh: value => `已获取 ${value} 个模型`,
    },
    {
        zh: /^恭喜！(.+) 验证成功！$/,
        en: /^Success! (.+) verified\.$/,
        toEn: value => `Success! ${translateValue(value, "en", DVLAA_TEXT_TRANSLATIONS, true) || value} verified.`,
        toZh: value => `恭喜！${translateValue(value, "zh", DVLAA_TEXT_REVERSE, true) || value} 验证成功！`,
    },
    {
        zh: /^(.+) 的 Flag 不正确，请检查后重试！$/,
        en: /^(.+) Flag is incorrect; check and retry\.$/,
        toEn: value => `${translateValue(value, "en", DVLAA_TEXT_TRANSLATIONS, true) || value} Flag is incorrect; check and retry.`,
        toZh: value => `${translateValue(value, "zh", DVLAA_TEXT_REVERSE, true) || value} 的 Flag 不正确，请检查后重试！`,
    },
    {
        zh: /^([A-Z0-9_-]+) 攻击环境已准备$/,
        en: /^([A-Z0-9_-]+) offense environment ready$/,
        toEn: value => `${value} offense environment ready`,
        toZh: value => `${value} 攻击环境已准备`,
    },
    {
        zh: /^攻击 (\d+) 分$/,
        en: /^Offense (\d+) pts$/,
        toEn: value => `Offense ${value} pts`,
        toZh: value => `攻击 ${value} 分`,
    },
    {
        zh: /^防守 (\d+) 分$/,
        en: /^Defense (\d+) pts$/,
        toEn: value => `Defense ${value} pts`,
        toZh: value => `防守 ${value} 分`,
    },
    {
        zh: /^(.+) · 攻击方会话 · 环境隔离$/,
        en: /^(.+) · Offense session · isolated environment$/,
        toEn: value => `${value} · Offense session · isolated environment`,
        toZh: value => `${value} · 攻击方会话 · 环境隔离`,
    },
];

function translateDynamicText(trimmed, lang) {
    for (const rule of DVLAA_DYNAMIC_RULES) {
        const pattern = lang === "en" ? rule.zh : rule.en;
        if (!pattern) continue;
        const match = trimmed.match(pattern);
        if (match) return lang === "en" ? rule.toEn(match[1], match) : rule.toZh(match[1], match);
    }
    return null;
}

function replaceKnownPhrases(value, map) {
    let result = value;
    const entries = Object.entries(map)
        .filter(([from, to]) => from && to && from !== to && from.length >= 3 && result.includes(from))
        .sort((a, b) => b[0].length - a[0].length);
    for (const [from, to] of entries) {
        result = result.split(from).join(to);
    }
    return result !== value ? result : null;
}

function translateValue(raw, lang, map, allowPhraseReplacement = true) {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const exact = map[trimmed];
    if (exact) return raw.replace(trimmed, exact);
    const dynamic = translateDynamicText(trimmed, lang);
    if (dynamic) return raw.replace(trimmed, dynamic);
    return allowPhraseReplacement ? replaceKnownPhrases(raw, map) : null;
}

function uiText(value) {
    const raw = String(value || "");
    const lang = currentLanguage();
    const map = lang === "en" ? DVLAA_TEXT_TRANSLATIONS : DVLAA_TEXT_REVERSE;
    return translateValue(raw, lang, map, true) || raw;
}

function shouldTranslatePhrasesInNode(node) {
    const parent = node.parentElement;
    if (!parent) return false;
    return Boolean(parent.closest(
        "h1, h2, h3, h4, h5, h6, strong, small, .nav-label, .card-title, .challenge-hero-title, .challenge-hero-section-title, .challenge-subnav-name, .challenge-subnav-title, .terminal-title, .system-ready-title, .badge-tag, .chat-bubble-meta, .challenge-hero-meta, .extended-inline-hints-title, .modal-title, .writeup-section-title, .source-tab, .source-code-toolbar"
    ));
}

function translateExactText(root) {
    if (!root) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const lang = currentLanguage();
    const map = lang === "en" ? DVLAA_TEXT_TRANSLATIONS : DVLAA_TEXT_REVERSE;
    let node;
    while ((node = walker.nextNode())) {
        if (shouldSkipI18nNode(node)) continue;
        const raw = node.nodeValue;
        if (!raw.trim()) continue;
        if (lang === "zh" && DVLAA_ORIGINAL_TEXT.has(node)) {
            node.nodeValue = DVLAA_ORIGINAL_TEXT.get(node);
            continue;
        }
        const translated = translateValue(raw, lang, map, true);
        if (translated && translated !== raw) {
            if (lang === "en" && (!DVLAA_ORIGINAL_TEXT.has(node) || /[\u4e00-\u9fff]/.test(raw))) {
                DVLAA_ORIGINAL_TEXT.set(node, raw);
            }
            node.nodeValue = translated;
        }
    }
}

function translateAttributes() {
    const lang = currentLanguage();
    const map = lang === "en" ? DVLAA_TEXT_TRANSLATIONS : DVLAA_TEXT_REVERSE;
    document.querySelectorAll("[placeholder], [title], [aria-label]").forEach(el => {
        ["placeholder", "title", "aria-label"].forEach(attr => {
            const value = el.getAttribute(attr);
            if (!value) return;
            const dataName = `i18nOriginal${attr.replace(/(^|-)([a-z])/g, (_, _sep, ch) => ch.toUpperCase())}`;
            if (lang === "zh" && el.dataset[dataName]) {
                el.setAttribute(attr, el.dataset[dataName]);
                return;
            }
            const translated = translateValue(value, lang, map, true);
            if (translated && translated !== value) {
                if (lang === "en" && !el.dataset[dataName]) {
                    el.dataset[dataName] = value;
                }
                el.setAttribute(attr, translated);
            }
        });
    });
}

function translateCollapsedCodes() {
    const lang = currentLanguage();
    const map = lang === "en" ? DVLAA_CODE_TRANSLATIONS : DVLAA_CODE_REVERSE;
    document.querySelectorAll(".dv-nav-item[data-code]").forEach(el => {
        const value = el.getAttribute("data-code");
        if (map[value]) el.setAttribute("data-code", map[value]);
    });
}

function translateDocumentTitle() {
    const root = document.documentElement;
    if (!root.dataset.i18nOriginalDocumentTitle) {
        root.dataset.i18nOriginalDocumentTitle = document.title;
    }
    const original = root.dataset.i18nOriginalDocumentTitle;
    if (currentLanguage() === "zh") {
        document.title = original;
        return;
    }
    if (DVLAA_TITLE_TRANSLATIONS[original]) {
        document.title = DVLAA_TITLE_TRANSLATIONS[original];
        return;
    }
    const translated = translateValue(original, "en", DVLAA_TEXT_TRANSLATIONS, true);
    if (translated) {
        document.title = translated;
    }
}


function initSidebarToggle() {
    const storageKey = "dvlaa.sidebarCollapsed";
    const root = document.documentElement;
    const toggleBtn = document.getElementById("sidebarToggleBtn");
    const sidebarNav = document.querySelector(".dv-sidebar-nav");
    const scrollStorageKey = "dvlaa.sidebarScrollTop";

    const saveSidebarScroll = () => {
        if (!sidebarNav) return;
        try { localStorage.setItem(scrollStorageKey, String(sidebarNav.scrollTop)); } catch (e) {}
    };
    const restoreSidebarScroll = () => {
        if (!sidebarNav) return;
        let saved = 0;
        try { saved = Math.max(0, Number(localStorage.getItem(scrollStorageKey) || 0)); } catch (e) {}
        const apply = () => { sidebarNav.scrollTop = saved; };
        apply();
        window.requestAnimationFrame(apply);
        window.setTimeout(apply, 80);
    };

    if (sidebarNav) {
        restoreSidebarScroll();
        sidebarNav.addEventListener("scroll", saveSidebarScroll, { passive: true });
        sidebarNav.querySelectorAll(".dv-nav-item").forEach((link) => {
            link.addEventListener("click", saveSidebarScroll);
        });
        window.addEventListener("pagehide", saveSidebarScroll);
    }
    try {
        shouldCollapse = shouldCollapse || localStorage.getItem(storageKey) === "1";
    } catch (e) {}
    // The fixed navigation rail otherwise consumes most of a phone viewport
    // and leaves embedded lab windows too narrow to operate. It remains
    // expandable through the existing toggle button when a learner needs it.
    if (window.matchMedia && window.matchMedia("(max-width: 760px)").matches) {
        shouldCollapse = true;
    }

    document.body.classList.toggle("sidebar-collapsed", shouldCollapse);
    root.classList.remove("sidebar-collapsed-preload");

    const syncButtonState = () => {
        const collapsed = document.body.classList.contains("sidebar-collapsed");
        if (!toggleBtn) return;
        toggleBtn.setAttribute("aria-expanded", collapsed ? "false" : "true");
        toggleBtn.setAttribute("aria-label", t(collapsed ? "expand_menu" : "collapse_menu"));
        toggleBtn.setAttribute("title", t(collapsed ? "expand_menu" : "collapse_menu"));
    };

    syncButtonState();

    if (!toggleBtn) return;
    toggleBtn.addEventListener("click", function () {
        const collapsed = document.body.classList.toggle("sidebar-collapsed");
        try {
            localStorage.setItem(storageKey, collapsed ? "1" : "0");
        } catch (e) {}
        syncButtonState();
    });
}

function initSlashCommandGuide() {
    const input = document.getElementById("userInputArea");
    const commands = Array.isArray(window.DVLAA_COMMANDS) ? window.DVLAA_COMMANDS : [];
    if (!input || !commands.length) return;

    const composer = input.closest(".dv-assistant-composer");
    const composerMain = input.closest(".dv-assistant-composer-main");
    if (!composer || !composerMain) return;

    const panel = document.createElement("div");
    panel.className = "dv-slash-command-panel";
    panel.setAttribute("role", "listbox");
    panel.setAttribute("aria-label", "可用命令");
    composerMain.insertAdjacentElement("afterend", panel);

    let visibleCommands = [];

    const hidePanel = () => {
        panel.classList.remove("is-visible");
        panel.innerHTML = "";
        visibleCommands = [];
    };

    const applyCommand = (command) => {
        input.value = command.insert || command.usage || command.command || "";
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
        hidePanel();
    };

    const renderPanel = () => {
        const raw = input.value.trimStart();
        if (!raw.startsWith("/")) {
            hidePanel();
            return;
        }
        const query = raw.toLowerCase();
        const commandToken = query.split(/\s+/)[0];
        visibleCommands = commands.filter((item) => {
            const command = String(item.command || "").toLowerCase();
            const usage = String(item.usage || "").toLowerCase();
            return command.startsWith(commandToken) || usage.startsWith(query) || query === "/";
        });
        if (!visibleCommands.length) {
            visibleCommands = commands.filter((item) => item.command === "/help");
        }
        panel.innerHTML = "";

        const header = document.createElement("div");
        header.className = "dv-slash-command-header";
        header.innerHTML = "<strong>可用命令</strong><span>输入 /help 可查看完整说明，点击命令可填入输入框。</span>";
        panel.appendChild(header);

        visibleCommands.forEach((item) => {
            const row = document.createElement("button");
            row.type = "button";
            row.className = "dv-slash-command-item";
            row.setAttribute("role", "option");
            const usage = document.createElement("code");
            usage.textContent = item.usage || item.command;
            const desc = document.createElement("span");
            desc.textContent = item.description || "";
            row.appendChild(usage);
            row.appendChild(desc);
            row.addEventListener("click", () => applyCommand(item));
            panel.appendChild(row);
        });

        panel.classList.add("is-visible");
    };

    input.addEventListener("input", renderPanel);
    input.addEventListener("focus", renderPanel);
    input.addEventListener("keydown", (event) => {
        if (event.key === "Escape") hidePanel();
        if (event.key === "Tab" && panel.classList.contains("is-visible") && visibleCommands.length) {
            event.preventDefault();
            applyCommand(visibleCommands[0]);
        }
    });
    document.addEventListener("click", (event) => {
        if (!composer.contains(event.target)) hidePanel();
    });
}

document.addEventListener("DOMContentLoaded", function () {
    initLanguageToggle();
    initThemeToggle();
    initSidebarToggle();
    initSlashCommandGuide();

    // 监听键盘 Shift+Enter 与 Enter 发送
    const userInput = document.getElementById("userInputArea");
    if (userInput) {
        userInput.addEventListener("keydown", function (e) {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                const sendBtn = document.getElementById("sendBtn");
                if (sendBtn) sendBtn.click();
            }
        });
    }

    // 监听全局关卡搜索
    const searchInput = document.getElementById("challengeSearchInput");
    if (searchInput) {
        searchInput.addEventListener("input", function (e) {
            const query = e.target.value.toLowerCase();
            const cards = document.querySelectorAll(".challenge-card");
            cards.forEach(card => {
                const name = card.getAttribute("data-name") || "";
                if (name.toLowerCase().includes(query)) {
                    card.style.display = "flex";
                } else {
                    card.style.display = "none";
                }
            });
        });
    }

    // 检查已通关状态
    fetchProgress();
});

function getChatTimeLabel() {
    const now = new Date();
    return now.toLocaleTimeString(currentLanguage() === "en" ? "en-US" : "zh-CN", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

function appendMessage(role, text) {
    const chatContainer = document.getElementById("chatMessages");
    if (!chatContainer) return;

    const safeRole = role === "user" || role === "assistant" ? role : "system";
    const chatLabels = (window.DVLAA_CHAT_LABELS && typeof window.DVLAA_CHAT_LABELS === "object") ? window.DVLAA_CHAT_LABELS : {};
    const displayText = safeRole === "system" ? uiText(text) : text;
    const row = document.createElement("div");
    row.className = `chat-message-row ${safeRole}`;

    if (safeRole === "system") {
        const systemLabel = chatLabels.system_label || "SYSTEM";
        row.innerHTML = `
            <div class="chat-bubble system-alert">
                <div class="chat-bubble-meta">${systemLabel} · ${getChatTimeLabel()}</div>
                <div class="dv-chat-content">${displayText}</div>
            </div>
        `;
    } else {
        const label = safeRole === "user"
            ? (chatLabels.user_label || "OPERATOR")
            : (chatLabels.assistant_label || "LLM AGENT");
        const avatar = safeRole === "user"
            ? (chatLabels.user_avatar || "USER")
            : (chatLabels.assistant_avatar || "AI");
        row.innerHTML = `
            <div class="chat-avatar">${avatar}</div>
            <div class="chat-message-stack">
                <div class="chat-bubble-meta">${label} · ${getChatTimeLabel()}</div>
                <div class="chat-bubble ${safeRole}">
                    <div class="dv-chat-content">${displayText}</div>
                </div>
            </div>
        `;
    }

    chatContainer.appendChild(row);
    if (safeRole === "system") localizeNewContent(row);
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

function sendMessage(level, sub) {
    const inputEl = document.getElementById("userInputArea");
    if (!inputEl) return;
    const msg = inputEl.value.trim();
    if (!msg) return;

    appendMessage("user", escapeHtml(msg));
    inputEl.value = "";

    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.innerText = t("processing");
    }

    fetch(`/api/chat/${level}/${sub}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg })
    })
    .then(res => res.json())
    .then(data => {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.innerText = t("send");
        }

        if (data.error) {
            appendMessage("system-alert", `[系统错误]: ${data.error}`);
            return;
        }

        appendMessage("assistant", data.response);

        // 如果包含通关调试数据
        if (data.debug) {
            const inspectorCard = document.getElementById("inspectorCard");
            const inspectorContent = document.getElementById("inspectorContent");
            if (inspectorCard && inspectorContent) {
                inspectorCard.style.display = "block";
                inspectorContent.innerText = JSON.stringify(data.debug, null, 2);
            }
        }

        if (data.extra && data.extra.solved) {
            fetchProgress();
        }
    })
    .catch(err => {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.innerText = t("send");
        }
        appendMessage("system-alert", `[网络异常]: ${err.message}`);
    });
}

function resetChat(level, sub) {
    fetch(`/api/reset/${level}/${sub}`, {
        method: "POST"
    })
    .then(res => res.json())
    .then(data => {
        const chatContainer = document.getElementById("chatMessages");
        if (chatContainer) {
            chatContainer.innerHTML = "";
            appendMessage("system-alert", `[会话已重置] 关卡 ${level}.${sub} 攻防会话历史已重置。`);
        }
    });
}

function sendAgentMessage(challengeId) {
    const inputEl = document.getElementById("userInputArea");
    if (!inputEl) return;
    const msg = inputEl.value.trim();
    if (!msg) return;
    appendMessage("user", escapeHtml(msg));
    inputEl.value = "";

    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) { sendBtn.disabled = true; sendBtn.innerText = t("processing"); }
    fetch(`/api/agent-chat/${challengeId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg })
    })
    .then(res => res.json())
    .then(data => {
        if (sendBtn) { sendBtn.disabled = false; sendBtn.innerText = t("send"); }
        if (data.error) { appendMessage("system", `[系统错误]: ${data.error}`); return; }
        appendMessage("assistant", data.response);
        const inspectorCard = document.getElementById("inspectorCard");
        const inspectorContent = document.getElementById("inspectorContent");
        if (data.debug && inspectorCard && inspectorContent) {
            inspectorCard.style.display = "block";
            inspectorContent.innerText = JSON.stringify(data.debug, null, 2);
        }
        updateAgentProgress(data.extra && data.extra.progress);
        if (data.extra && data.extra.solved) fetchProgress();
    })
    .catch(err => {
        if (sendBtn) { sendBtn.disabled = false; sendBtn.innerText = t("send"); }
        appendMessage("system", `[网络异常]: ${err.message}`);
    });
}

function resetAgentChat(challengeId) {
    fetch(`/api/agent-reset/${challengeId}`, { method: "POST" })
    .then(res => res.json())
    .then(() => {
        const chatContainer = document.getElementById("chatMessages");
        if (!chatContainer) return;
        chatContainer.innerHTML = "";
        appendMessage("system", `[会话已重置] Agent 场景 ASI${String(challengeId).padStart(2, "0")} 的上下文状态已清除。`);
        const progressText = document.getElementById("agentProgressText");
        updateAgentProgress({ current: 0, total: Number(progressText && progressText.dataset.total) || 3 });
        const inspectorCard = document.getElementById("inspectorCard");
        if (inspectorCard) inspectorCard.style.display = "none";
    });
}

function updateAgentProgress(progress) {
    if (!progress) return;
    const current = Number(progress.current) || 0;
    const progressEl = document.getElementById("agentProgressText");
    const total = Number(progress.total) || Number(progressEl && progressEl.dataset.total) || 3;
    const progressText = document.getElementById("agentProgressText");
    const progressBar = document.getElementById("agentProgressBar");
    if (progressText) progressText.innerText = `${current} / ${total}`;
    if (progressBar) progressBar.style.width = `${Math.min(100, (current / total) * 100)}%`;
}

function uploadFilePayload(level, sub) {
    const fileInput = document.getElementById("fileUploadInput");
    if (!fileInput || !fileInput.files.length) {
        alert(uiText("请先选择要上传的文本载荷文件。"));
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    fetch(`/api/chat/${level}/${sub}/upload`, {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) {
            appendMessage("system-alert", `[文件上传失败]: ${data.error}`);
        } else {
            appendMessage("system-alert", `[文件上传成功]: 文本载荷已被成功注入会话环境。`);
        }
    });
}

function openGlobalHelp() {
    if (window.DVLAA_CONTEXT && window.DVLAA_CONTEXT.track === "agent") {
        openAgentHelp(window.DVLAA_CONTEXT.id);
        return;
    }
    openHelp(1, 1);
}

function openAgentHelp(challengeId) {
    fetch(`/api/help/agent/${challengeId}`)
    .then(res => res.json())
    .then(data => openHelpModal(data));
}

function openHelp(level, sub) {
    fetch(`/api/help/owasp/${level}/${sub}`)
    .then(res => res.json())
    .then(data => openHelpModal(data));
}

function openWriteup(level, sub) {
    fetch(`/api/help/owasp/${level}/${sub}`)
    .then(res => res.json())
    .then(data => openWriteupModal(data, level, sub))
    .catch(() => openWriteupModal({ error: "题解加载失败，请稍后重试。" }, level, sub));
}

function openAgentWriteup(challengeId, challengeCode) {
    fetch(`/api/help/agent/${challengeId}`)
    .then(res => res.json())
    .then(data => openWriteupModal(data, challengeCode))
    .catch(() => openWriteupModal({ error: "题解加载失败，请稍后重试。" }, challengeCode));
}

function openExtendedWriteup(challengeId, challengeCode) {
    fetch(`/api/help/extended/${challengeId}`)
    .then(res => res.json())
    .then(data => openWriteupModal(data, challengeCode))
    .catch(() => openWriteupModal({ error: "题解加载失败，请稍后重试。" }, challengeCode));
}

function openAwdpWriteup(challengeId, challengeCode) {
    fetch(`/api/help/awdp/${challengeId}`)
    .then(res => res.json())
    .then(data => openWriteupModal(data, challengeCode || `AWDP${String(challengeId).padStart(2, "0")}`))
    .catch(() => openWriteupModal({ error: "题解加载失败，请稍后重试。" }, challengeCode || "AWDP"));
}

function openRealWriteup(challengeId, challengeCode) {
    fetch(`/api/real-challenge/${challengeId}/help`)
        .then(res => res.json().then(data => ({ ok: res.ok, data })))
        .then(({ ok, data }) => {
            if (!ok || data.ok === false) throw new Error(data.message || "题解加载失败");
            openWriteupModal(data.help || data, challengeCode || `REAL${String(challengeId).padStart(2, "0")}`);
        })
        .catch(error => openWriteupModal({ error: `题解加载失败：${error.message}` }, challengeCode || "REAL"));
}

function openWriteupModal(data, level, sub) {
    const modal = document.getElementById("globalModal");
    if (!modal) return;
    modal.classList.remove("source-viewer-active");

    const challengeLabel = sub === undefined ? String(level) : `${level}.${sub}`;
    document.getElementById("modalTitle").innerText = `[WP 题解] ${challengeLabel} · ${data.title || "官方解题说明"}`;
    const steps = Array.isArray(data.solution_steps) ? data.solution_steps : (data.beginner_steps || []);
    const payload = data.payload || steps[0] || data.approach || "暂无示例载荷";
    const stepsHtml = steps.length
        ? `<ol class="writeup-step-list">${steps.map(step => `<li>${escapeHtml(step)}</li>`).join("")}</ol>`
        : `<p>按题目提示逐步验证漏洞触发条件。</p>`;
    const detailSections = Array.isArray(data.writeup_sections) && data.writeup_sections.length
        ? data.writeup_sections.map(section => `
            <section class="writeup-section">
                <div class="writeup-section-title">${escapeHtml(section.title || "补充说明")}</div>
                <p>${escapeHtml(section.body || "").replace(/\n/g, "<br>")}</p>
            </section>
        `).join("")
        : `
            ${data.vulnerability_principle ? `<section class="writeup-section"><div class="writeup-section-title">漏洞原理</div><p>${escapeHtml(data.vulnerability_principle)}</p></section>` : ""}
            ${data.system_prompt_mapping ? `<section class="writeup-section"><div class="writeup-section-title">系统提示词关联</div><p>${escapeHtml(data.system_prompt_mapping)}</p></section>` : ""}
            ${data.source_mapping ? `<section class="writeup-section"><div class="writeup-section-title">源码与判定路径</div><p>${escapeHtml(data.source_mapping)}</p></section>` : ""}
            ${data.payload_rationale ? `<section class="writeup-section"><div class="writeup-section-title">Payload 设计理由</div><p>${escapeHtml(data.payload_rationale)}</p></section>` : ""}
        `;

    document.getElementById("modalBody").innerHTML = `
        <section class="writeup-section">
            <div class="writeup-section-title">题目讲解</div>
            <p>${escapeHtml(data.principle || data.error || "暂无题目讲解")}</p>
        </section>
        <section class="writeup-section">
            <div class="writeup-section-title">解题思路</div>
            <p>${escapeHtml(data.approach || data.hint || "暂无解题思路")}</p>
            ${stepsHtml}
        </section>
        <section class="writeup-section writeup-payload-section">
            <div class="writeup-section-title">官方 Payload</div>
            <pre class="writeup-payload"><code>${escapeHtml(payload)}</code></pre>
            <button type="button" class="btn-dv btn-dv-sm" onclick="copyWriteupPayload(this)">${t("copy_payload")}</button>
        </section>
        ${data.patch_example_url ? `
        <section class="writeup-section writeup-patch-section">
            <div class="writeup-section-title">${t("defense_patch_example")}</div>
            <p>${escapeHtml(data.patch_example || `下载后可直接上传验证，也可以解压查看 update.sh 与 ${data.patch_target || "patched/web_service.js"}。`)}</p>
            <a class="btn-dv btn-dv-sm btn-dv-primary" href="${escapeHtml(data.patch_example_url)}" download="${escapeHtml(data.patch_example_filename || "awdp-fixed-patch.tar.gz")}">${t("download_patch_example")}</a>
        </section>` : ""}
        ${detailSections}
    `;
    modal.classList.add("active");
    localizeNewContent(modal);
}

function selectCopyText(element) {
    if (!element) return;
    const selection = window.getSelection();
    if (!selection) return;
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
}

function copyTextWithFallback(text) {
    const textarea = document.createElement("textarea");
    textarea.value = String(text || "");
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "0";
    textarea.style.left = "-9999px";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    let copied = false;
    try {
        copied = document.execCommand("copy");
    } catch (error) {
        copied = false;
    }
    textarea.remove();
    return copied;
}

function updateCopyButton(button, success, code) {
    if (!button) return;
    const defaultText = button.dataset.copyDefault || t("copy_payload");
    button.dataset.copyDefault = defaultText;
    button.textContent = success ? t("copied") : "复制失败，请手动选择文本";
    if (!success) selectCopyText(code);
    window.setTimeout(() => {
        button.textContent = defaultText;
    }, success ? 1200 : 2200);
}

function copyWriteupPayload(button) {
    const section = button && button.closest(".writeup-payload-section");
    const code = section && section.querySelector("code");
    if (!button || !code) return;
    const text = code.textContent || "";
    const fallback = () => updateCopyButton(button, copyTextWithFallback(text), code);
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        Promise.resolve(navigator.clipboard.writeText(text))
            .then(() => updateCopyButton(button, true, code))
            .catch(() => fallback());
        return;
    }
    fallback();
}

function openHelpModal(data) {
        const modal = document.getElementById("globalModal");
        if (!modal) return;
        modal.classList.remove("source-viewer-active");
        
        document.getElementById("modalTitle").innerText = `[通关指南] ${data.title || "关卡漏洞手册"}`;
        
        const body = document.getElementById("modalBody");
        body.innerHTML = `
            <div style="background: var(--bg-primary); padding: 0.75rem; border-radius: 4px; border: 1px solid var(--border-color);">
                <strong style="color: var(--accent-blue); display: block; margin-bottom: 0.25rem;">[漏洞原理]</strong>
                <p style="color: var(--text-primary); font-size: 0.8rem;">${data.principle || "暂无描述"}</p>
            </div>
            <div style="background: var(--bg-primary); padding: 0.75rem; border-radius: 4px; border: 1px solid var(--border-color);">
                <strong style="color: var(--accent-green-bright); display: block; margin-bottom: 0.25rem;">[解题思路与提示]</strong>
                <p style="color: var(--text-primary); font-size: 0.8rem;">${data.approach || data.hint || "暂无提示"}</p>
            </div>
        `;
        modal.classList.add("active");
        localizeNewContent(modal);
}

function closeGlobalHelp() {
    const modal = document.getElementById("globalModal");
    if (modal) modal.classList.remove("active", "source-viewer-active");
}

function openChallengeSource(level, sub) {
    openSourceViewer(
        `/api/challenge-source/${level}/${sub}`,
        `[题目原理] 关卡 ${level}.${sub} · 系统提示词与源码`,
        "正在读取当前题目配置..."
    );
}

function openAgentSource(challengeId) {
    openSourceViewer(
        `/api/agent-source/${challengeId}`,
        `[题目原理] Agent 场景 ${challengeId} · 提示词与源码`,
        "正在读取当前 Agent 场景配置..."
    );
}

function openExtendedSource(challengeId) {
    openSourceViewer(
        `/api/extended-source/${challengeId}`,
        `[题目原理] 综合攻防题 ${challengeId} · 提示词与源码`,
        "正在读取当前综合攻防题配置..."
    );
}

function openAwdpSource(challengeId, challengeCode) {
    const label = challengeCode || `AWDP${String(challengeId).padStart(2, "0")}`;
    openSourceViewer(
        `/api/awdp/${challengeId}/source-view`,
        `[题目原理] ${label} · 服务源码与修复边界`,
        "正在读取当前 AWDP Web 服务源码..."
    );
}

function openSourceViewer(endpoint, loadingTitle, loadingMessage) {
    const modal = document.getElementById("globalModal");
    if (!modal) return;
    modal.classList.add("active", "source-viewer-active");
    document.getElementById("modalTitle").innerText = loadingTitle;
    document.getElementById("modalBody").innerHTML = `<div class="source-viewer-loading">${escapeHtml(loadingMessage)}</div>`;
    localizeNewContent(modal);

    fetch(endpoint)
    .then(res => res.json())
    .then(data => {
        if (data.error) throw new Error(data.error);
        const isAwdpWebService = data.viewer_type === "awdp-web-service";
        const files = Array.isArray(data.source_files) && data.source_files.length
            ? data.source_files.map(file => `<span class="source-file-chip">${escapeHtml(file)}</span>`).join("")
            : `<span class="source-file-chip">运行时题目配置</span>`;
        const tabs = isAwdpWebService
            ? `
                <button type="button" class="source-tab active" data-source-tab="service" onclick="switchChallengeSourceTab('service')">服务边界</button>
                <button type="button" class="source-tab" data-source-tab="config" onclick="switchChallengeSourceTab('config')">运行配置</button>
                <button type="button" class="source-tab" data-source-tab="implementation" onclick="switchChallengeSourceTab('implementation')">核心实现</button>`
            : `
                <button type="button" class="source-tab active" data-source-tab="prompt" onclick="switchChallengeSourceTab('prompt')">系统提示词</button>
                <button type="button" class="source-tab" data-source-tab="config" onclick="switchChallengeSourceTab('config')">题目配置</button>
                <button type="button" class="source-tab" data-source-tab="implementation" onclick="switchChallengeSourceTab('implementation')">核心实现</button>`;
        const primaryPanel = isAwdpWebService
            ? `
                <section class="source-code-panel active" data-source-panel="service">
                    <div class="source-code-toolbar"><span>WEB SERVICE CONTRACT</span><button type="button" class="btn-dv btn-dv-sm" onclick="copyChallengeSource(this)">${t("copy")}</button></div>
                    <pre><code>${escapeHtml(data.service_contract || "暂无服务边界说明")}</code></pre>
                </section>`
            : `
                <section class="source-code-panel active" data-source-panel="prompt">
                    <div class="source-code-toolbar"><span>SYSTEM PROMPT</span><button type="button" class="btn-dv btn-dv-sm" onclick="copyChallengeSource(this)">${t("copy")}</button></div>
                    <pre><code>${escapeHtml(data.system_prompt || "暂无系统提示词")}</code></pre>
                </section>`;
        document.getElementById("modalTitle").innerText = `[题目原理] ${data.title}`;
        document.getElementById("modalBody").innerHTML = `
            <div class="source-viewer-summary">
                <div><strong>教学源码查看器</strong><span>${escapeHtml(data.note || "")}</span></div>
                <div class="source-file-list">${files}</div>
            </div>
            <div class="source-viewer-tabs" role="tablist">
                ${tabs}
            </div>
            ${primaryPanel}
            <section class="source-code-panel" data-source-panel="config">
                <div class="source-code-toolbar"><span>RUNTIME CONFIG</span><button type="button" class="btn-dv btn-dv-sm" onclick="copyChallengeSource(this)">${t("copy")}</button></div>
                <pre><code>${escapeHtml(data.configuration_source || JSON.stringify(data.configuration || {}, null, 4))}</code></pre>
            </section>
            <section class="source-code-panel" data-source-panel="implementation">
                <div class="source-code-toolbar"><span>PYTHON IMPLEMENTATION</span><button type="button" class="btn-dv btn-dv-sm" onclick="copyChallengeSource(this)">${t("copy")}</button></div>
                <pre><code>${escapeHtml(data.implementation_source || "暂无核心实现源码")}</code></pre>
            </section>
        `;
        localizeNewContent(modal);
    })
    .catch(err => {
        document.getElementById("modalBody").innerHTML = `<div class="source-viewer-error">源码读取失败：${escapeHtml(err.message)}</div>`;
        localizeNewContent(modal);
    });
}

function switchChallengeSourceTab(tabName) {
    document.querySelectorAll(".source-tab").forEach(button => {
        button.classList.toggle("active", button.dataset.sourceTab === tabName);
    });
    document.querySelectorAll(".source-code-panel").forEach(panel => {
        panel.classList.toggle("active", panel.dataset.sourcePanel === tabName);
    });
}

function copyChallengeSource(button) {
    const code = button.closest(".source-code-panel").querySelector("code");
    if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(() => {
        button.textContent = t("copied");
        window.setTimeout(() => { button.textContent = t("copy"); }, 1200);
    });
}

function submitFlag() {
    const input = document.getElementById("flagInput");
    const resMsg = document.getElementById("flagResultMsg");
    const form = document.getElementById("submitFlagForm");
    if (!input || !input.value.trim()) return;

    const payload = { flag: input.value.trim() };
    if (form && form.dataset.track === "agent") {
        payload.track = "agent";
        payload.agent_id = Number(form.dataset.agentId);
    } else if (form && form.dataset.track === "extended") {
        payload.track = "extended";
        payload.challenge_id = Number(form.dataset.challengeId);
    } else if (form && form.dataset.level) {
        payload.level = Number(form.dataset.level);
        payload.sub = Number(form.dataset.sub || 1);
    }

    fetch("/api/submit-flag", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => {
        resMsg.style.display = "block";
        const isPassed = data.solved || data.success;
        const msg = uiText(data.message || data.error || "未知结果");
        if (isPassed) {
            resMsg.innerHTML = `<div style="color: var(--accent-green-bright); font-weight: 700;">${uiText("[提交成功]:")} ${msg}</div>`;
        } else {
            resMsg.innerHTML = `<div style="color: var(--accent-red); font-weight: 700;">${uiText("[校验失败]:")} ${msg}</div>`;
        }
    })
    .catch(err => {
        resMsg.style.display = "block";
        resMsg.innerHTML = `<div style="color: var(--accent-red); font-weight: 700;">${uiText("[网络异常]:")} ${err.message}</div>`;
    });
}

function sendExtendedMessage(challengeId) {
    const inputEl = document.getElementById("userInputArea");
    if (!inputEl) return;
    const msg = inputEl.value.trim();
    if (!msg) return;
    appendMessage("user", escapeHtml(msg));
    inputEl.value = "";
    const sendBtn = document.getElementById("sendBtn");
    if (sendBtn) { sendBtn.disabled = true; sendBtn.innerText = t("processing"); }
    fetch(`/api/ai-challenge/${challengeId}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({message: msg})})
    .then(res => res.json()).then(data => {
        if (sendBtn) { sendBtn.disabled = false; sendBtn.innerText = t("send"); }
        if (data.error) { appendMessage("system", `[系统错误] ${data.error}`); return; }
        appendMessage("assistant", data.response);
        const card = document.getElementById("inspectorCard");
        const content = document.getElementById("inspectorContent");
        if (data.debug && card && content) { card.style.display = "block"; content.innerText = JSON.stringify(data.debug, null, 2); }
        if (data.extra && data.extra.solved) fetchProgress();
    }).catch(err => {
        if (sendBtn) { sendBtn.disabled = false; sendBtn.innerText = t("send"); }
        appendMessage("system", `[网络异常] ${err.message}`);
    });
}

function resetExtendedChat(challengeId) {
    fetch(`/api/ai-challenge/${challengeId}/reset`, {method: "POST"}).then(() => {
        const chat = document.getElementById("chatMessages");
        if (chat) {
            chat.innerHTML = "";
            appendMessage("system", window.DVLAA_RESET_MESSAGE || "[会话已重置] 当前题目的对话与知识库状态已清除。");
        }
        const card = document.getElementById("inspectorCard");
        if (card) card.style.display = "none";
    });
}

function fetchProgress() {
    fetch("/api/progress")
    .then(res => res.json())
    .then(data => {
        if (!data || !data.solved_list) return;
        const totalTag = document.getElementById("totalProgressTag");
        if (totalTag) {
            totalTag.innerText = `${t("progress")}${currentLanguage() === "en" ? ": " : "："}${data.solved_count} / ${data.total}`;
        }
        const dashboardSolvedCount = document.getElementById("dashboardSolvedCount");
        if (dashboardSolvedCount) dashboardSolvedCount.innerText = `${data.solved_count} / ${data.total}`;
        data.solved_list.forEach(item => {
            const badge = document.getElementById(`badge_solved_${item.key}`);
            if (badge) badge.style.display = "inline-block";
        });
    })
    .catch(err => {});
}

function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/* AWDP AI 智能体安全攻防赛：独立于常规关卡的攻防操作台。 */
function awdpConfig() {
    return window.DVLAA_AWDP || {};
}

function awdpChallengeId(explicitId) {
    const root = document.querySelector(".awdp-page");
    return String(explicitId || awdpConfig().id || (root && root.dataset.awdpId) || "").trim();
}

function awdpEndpoint(challengeId, action) {
    return `/api/awdp/${encodeURIComponent(challengeId)}/${action}`;
}

function awdpEscape(value) {
    return escapeHtml(String(value == null ? "" : value));
}

function awdpMessage(data, fallback) {
    if (!data || typeof data !== "object") return fallback;
    const value = data.response ?? data.message ?? data.detail ?? data.error;
    if (value && typeof value === "object") return value.content ?? value.message ?? JSON.stringify(value);
    return value || fallback;
}

function awdpFetch(url, options) {
    return fetch(url, { credentials: "same-origin", ...(options || {}) })
        .then(async (response) => {
            const contentType = response.headers.get("content-type") || "";
            const data = contentType.includes("application/json")
                ? await response.json().catch(() => ({}))
                : { message: await response.text().catch(() => "") };
            if (!response.ok || data.error) throw new Error(awdpMessage(data, `请求失败（${response.status}）`));
            return data;
        });
}

function awdpSetBusy(button, busy, label) {
    if (!button) return;
    if (busy) {
        button.dataset.awdpLabel = button.textContent;
        button.disabled = true;
        button.textContent = label;
        return;
    }
    button.disabled = false;
    button.textContent = button.dataset.awdpLabel || button.textContent;
}

function awdpShowResult(element, text, type) {
    if (!element) return;
    element.hidden = false;
    element.className = `awdp-action-result ${type || "info"}`;
    element.textContent = text;
}

function awdpSetPhase(id, text, phase) {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = text;
    element.classList.remove("is-success", "is-failure");
    if (phase) element.classList.add(`is-${phase}`);
}

function awdpApplyState(rawState) {
    const state = rawState && typeof rawState === "object" ? (rawState.state || rawState) : {};
    const statusValue = String(state.status || state.result || state.verdict || "").toLowerCase();
    const attackSolved = Boolean(
        state.attack_solved || state.attackSolved || state.exploit_solved || state.exploitSolved
        || /exp_exploit_success|attack_solved|exploit_solved/.test(statusValue)
    );
    const defenseSolved = Boolean(
        state.defense_solved || state.defenseSolved || state.patch_active || state.patchActive
        || /defense_success|candidate_safe|patch_active/.test(statusValue)
    );
    const checkValue = String(state.check_status || state.checkStatus || state.patch_status || state.patchStatus || statusValue || "").toLowerCase();
    const checkFailed = Boolean(state.check_failed || state.checkFailed || state.patch_failed || state.patchFailed || /check_failed|fail|error|invalid|rejected/.test(checkValue));

    awdpSetPhase("awdpExpStatus", attackSolved ? "EXP 利用成功" : "EXP 等待利用", attackSolved ? "success" : "");
    awdpSetPhase("awdpDefenseStatus", defenseSolved ? "防御成功" : "防御等待修复", defenseSolved ? "success" : "");
    // `pending` is a real state, not a truthy success signal.  Keep the
    // initial and reset views honest until a patch has passed regression.
    if (checkFailed) {
        awdpSetPhase("awdpCheckStatus", "CHECK 检测失败", "failure");
    } else if (checkValue === "defense_success" || defenseSolved) {
        awdpSetPhase("awdpCheckStatus", "CHECK 检测通过", "success");
    } else {
        awdpSetPhase("awdpCheckStatus", "CHECK 等待校验", "");
    }

    const environment = document.getElementById("awdpEnvironmentState");
    const statusLabel = environment && environment.querySelector("span:last-child");
    const status = state.environment_status || state.status || (checkFailed ? "检测失败" : (defenseSolved ? "防御已生效" : (attackSolved ? "攻击目标已完成" : "环境就绪")));
    if (statusLabel) statusLabel.textContent = status;
    if (environment) {
        environment.classList.toggle("is-error", /失败|异常|error/i.test(String(status)));
        environment.classList.toggle("is-warning", /部署|校验|处理/i.test(String(status)));
    }
}

function awdpSubmissionValue(item, names, fallback) {
    for (const name of names) {
        const value = item && item[name];
        if (value !== undefined && value !== null && value !== "") return value;
    }
    return fallback == null ? "-" : fallback;
}

function awdpFormatTime(value) {
    if (!value) return "-";
    if (typeof value === "number") {
        const date = new Date(value > 100000000000 ? value : value * 1000);
        if (!Number.isNaN(date.getTime())) return date.toLocaleString("zh-CN", { hour12: false });
    }
    return String(value);
}

function renderAwdpSubmissions(rawSubmissions) {
    const body = document.getElementById("awdpSubmissionRows");
    if (!body) return;
    const submissions = Array.isArray(rawSubmissions)
        ? rawSubmissions
        : (rawSubmissions && (rawSubmissions.submissions || rawSubmissions.records || rawSubmissions.items)) || [];
    if (!Array.isArray(submissions) || submissions.length === 0) {
        body.innerHTML = '<tr class="awdp-submissions-empty"><td colspan="5">当前轮次暂无提交记录。</td></tr>';
        return;
    }
    body.innerHTML = submissions.map((item) => {
        const result = awdpSubmissionValue(item, ["result", "status", "verdict"], "待处理");
        const resultClass = /成功|通过|solved|success|accepted/i.test(String(result))
            ? "awdp-result-success"
            : (/失败|error|rejected|invalid/i.test(String(result)) ? "awdp-result-failure" : "");
        return `<tr>
            <td>${awdpEscape(awdpFormatTime(awdpSubmissionValue(item, ["created_at", "timestamp", "time"], "-")))}</td>
            <td>${awdpEscape(awdpSubmissionValue(item, ["type", "kind", "submission_type"], "提交"))}</td>
            <td>${awdpEscape(awdpSubmissionValue(item, ["content", "filename", "value", "summary"], "-"))}</td>
            <td class="${resultClass}">${awdpEscape(result)}</td>
            <td>${awdpEscape(awdpSubmissionValue(item, ["message", "detail", "reason"], "-"))}</td>
        </tr>`;
    }).join("");
}

function loadAwdpSubmissions(challengeId) {
    const id = awdpChallengeId(challengeId);
    const refresh = document.getElementById("awdpRefreshSubmissionsButton");
    if (!id) return Promise.resolve();
    awdpSetBusy(refresh, true, "刷新中...");
    return awdpFetch(awdpEndpoint(id, "submissions"))
        .then((data) => renderAwdpSubmissions(data))
        .catch((error) => {
            const body = document.getElementById("awdpSubmissionRows");
            if (body) body.innerHTML = `<tr class="awdp-submissions-empty"><td colspan="5">提交记录读取失败：${awdpEscape(error.message)}</td></tr>`;
        })
        .finally(() => awdpSetBusy(refresh, false));
}

function loadAwdpState(challengeId) {
    const id = awdpChallengeId(challengeId);
    if (!id) return Promise.resolve();
    return awdpFetch(awdpEndpoint(id, "state"))
        .then((data) => {
            const state = data.state || data;
            awdpApplyState(state);
            if (state.submissions) renderAwdpSubmissions(state.submissions);
        })
        .catch(() => awdpApplyState({ status: "环境状态读取失败" }));
}

/*
 * AWDP attack-side targets render inside an isolated Web application frame.
 * The child app owns its forms, API calls and exploit flow.  It can notify the
 * console with a same-origin postMessage once its runtime state changes.
 */
function awdpWebLabUrl() {
    const frame = document.getElementById("awdpWebFrame");
    return (frame && frame.dataset.awdpWebUrl) || awdpConfig().webLabUrl || "";
}

function awdpSetWebConnection(label, kind) {
    const element = document.getElementById("awdpWebConnection");
    if (!element) return;
    element.textContent = label;
    element.classList.toggle("is-ready", kind === "ready");
    element.classList.toggle("is-error", kind === "error");
}

function awdpReloadWebLab(cacheBust) {
    const frame = document.getElementById("awdpWebFrame");
    const loading = document.getElementById("awdpWebLoading");
    const baseUrl = awdpWebLabUrl();
    if (!frame || !baseUrl) return;
    frame.dataset.awdpWebLoaded = "0";
    if (loading) loading.hidden = false;
    awdpSetWebConnection("正在重新加载", "");
    const url = new URL(baseUrl, window.location.origin);
    if (cacheBust) url.searchParams.set("_", String(Date.now()));
    frame.src = url.pathname + url.search;
}

function awdpInitWebLab(challengeId) {
    const frame = document.getElementById("awdpWebFrame");
    if (!frame || frame.dataset.awdpWebInitialized === "1") return;
    frame.dataset.awdpWebInitialized = "1";
    const loading = document.getElementById("awdpWebLoading");
    const reload = document.getElementById("awdpWebReloadButton");
    const open = document.getElementById("awdpWebOpenButton");
    const address = document.getElementById("awdpWebAddress");
    const url = awdpWebLabUrl();
    if (address && url) address.textContent = url;

    frame.addEventListener("load", () => {
        frame.dataset.awdpWebLoaded = "1";
        if (loading) loading.hidden = true;
        awdpSetWebConnection("已连接", "ready");
    });
    reload && reload.addEventListener("click", () => awdpReloadWebLab(true));
    open && open.addEventListener("click", () => {
        if (url) window.open(url, "_blank", "noopener,noreferrer");
    });

    // iframe 初始使用 about:blank，监听器绑定后再主动加载目标，避免首次
    // load 事件早于监听器注册而导致遮罩层永久停留。目标启动较慢时自动重试。
    awdpReloadWebLab(false);
    let retryCount = 0;
    const retryWebLab = () => {
        if (frame.dataset.awdpWebLoaded === "1") return;
        retryCount += 1;
        if (retryCount > 3) {
            awdpSetWebConnection("目标服务响应超时", "error");
            if (loading) loading.hidden = true;
            return;
        }
        awdpSetWebConnection(`正在重试连接 (${retryCount}/3)`, "");
        awdpReloadWebLab(true);
        window.setTimeout(retryWebLab, 4000);
    };
    window.setTimeout(retryWebLab, 4000);

    window.addEventListener("message", (event) => {
        if (event.origin !== window.location.origin || event.source !== frame.contentWindow) return;
        const payload = event.data;
        if (!payload || payload.type !== "dvlaa-awdp-web") return;
        if (String(payload.challengeId) !== String(challengeId)) return;
        const eventName = String(payload.event || "").toLowerCase();
        if (eventName === "error") {
            awdpSetWebConnection(payload.message || "目标服务异常", "error");
        } else if (eventName === "ready" || eventName === "state" || eventName === "attack-solved") {
            awdpSetWebConnection(eventName === "attack-solved" ? "利用已验证" : "已连接", "ready");
        }
        if (payload.state) awdpApplyState(payload.state);
        if (payload.submissions) renderAwdpSubmissions(payload.submissions);
        if (eventName === "attack-solved" || eventName === "submission") loadAwdpSubmissions(challengeId);
    });
}

function awdpSwitchTab(name) {
    document.querySelectorAll("[data-awdp-tab]").forEach((tab) => {
        const active = tab.dataset.awdpTab === name;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", String(active));
    });
    document.querySelectorAll("[data-awdp-panel]").forEach((panel) => {
        const active = panel.dataset.awdpPanel === name;
        panel.classList.toggle("active", active);
        panel.hidden = !active;
    });
}

function submitAwdpFlag(challengeId) {
    const id = awdpChallengeId(challengeId);
    const input = document.getElementById("awdpFlagInput");
    const result = document.getElementById("awdpFlagResult");
    const submitButton = document.getElementById("awdpFlagSubmitButton");
    const flag = input && input.value.trim();
    if (!id || !flag) {
        awdpShowResult(result, "请先输入从目标服务获得的 Flag。", "error");
        input && input.focus();
        return;
    }
    awdpSetBusy(submitButton, true, "校验中...");
    awdpFetch(awdpEndpoint(id, "submit-flag"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flag })
    })
        .then((data) => {
            const passed = data.success === true || data.solved === true || data.accepted === true;
            awdpShowResult(result, awdpMessage(data, passed ? "Flag 校验通过。" : "Flag 校验未通过。"), passed ? "success" : "error");
            awdpApplyState(data.state || data.environment || data);
            return loadAwdpSubmissions(id);
        })
        .catch((error) => awdpShowResult(result, `Flag 提交失败：${error.message}`, "error"))
        .finally(() => awdpSetBusy(submitButton, false));
}

function awdpUpdatePatchFileName() {
    const input = document.getElementById("awdpPatchInput");
    const label = document.getElementById("awdpPatchFileName");
    const file = input && input.files && input.files[0];
    if (!label) return;
    label.textContent = file
        ? `${file.name} · ${Math.ceil(file.size / 1024)} KB`
        : "仅支持 .tar.gz 或 .tgz，需包含 update.sh";
}

function uploadAwdpPatch(challengeId) {
    const id = awdpChallengeId(challengeId);
    const input = document.getElementById("awdpPatchInput");
    const result = document.getElementById("awdpPatchResult");
    const submitButton = document.getElementById("awdpPatchSubmitButton");
    const file = input && input.files && input.files[0];
    if (!id || !file) {
        awdpShowResult(result, "请选择包含 update.sh 的修复包。", "error");
        return;
    }
    const validName = /\.(tar\.gz|tgz)$/i.test(file.name);
    const maxPatchMb = Number(awdpConfig().maxPatchMb || 0);
    if (!validName) {
        awdpShowResult(result, "修复包格式应为 .tar.gz 或 .tgz。", "error");
        return;
    }
    if (maxPatchMb && file.size > maxPatchMb * 1024 * 1024) {
        awdpShowResult(result, `修复包大小不能超过 ${maxPatchMb} MB。`, "error");
        return;
    }
    const formData = new FormData();
    formData.append("file", file);
    awdpSetBusy(submitButton, true, "部署并校验中...");
    awdpFetch(awdpEndpoint(id, "patch"), { method: "POST", body: formData })
        .then((data) => {
            const passed = data.success === true || data.passed === true || data.accepted === true;
            awdpShowResult(result, awdpMessage(data, passed ? "修复包已通过部署校验。" : "修复包已提交，等待服务端判定。"), passed ? "success" : "info");
            awdpApplyState(data.state || data.environment || data);
            if (passed) {
                awdpSetPhase("awdpCheckStatus", "CHECK 检测通过", "success");
                awdpReloadWebLab(true);
            }
            else if (data.success === false || data.passed === false) awdpSetPhase("awdpCheckStatus", "CHECK 检测失败", "failure");
            return loadAwdpSubmissions(id);
        })
        .catch((error) => {
            awdpShowResult(result, `修复包提交失败：${error.message}`, "error");
            awdpSetPhase("awdpCheckStatus", "CHECK 检测失败", "failure");
        })
        .finally(() => awdpSetBusy(submitButton, false));
}

function resetAwdpEnvironment(challengeId) {
    const id = awdpChallengeId(challengeId);
    const button = document.getElementById("awdpResetButton");
    if (!id || !window.confirm("重置会清除当前题目的业务数据、Flag 和补丁部署状态。是否继续？")) return;
    awdpSetBusy(button, true, "重置中...");
    awdpFetch(awdpEndpoint(id, "reset"), { method: "POST" })
        .then((data) => {
            const flag = document.getElementById("awdpFlagInput");
            const patchForm = document.getElementById("awdpPatchForm");
            const flagResult = document.getElementById("awdpFlagResult");
            const patchResult = document.getElementById("awdpPatchResult");
            if (flag) flag.value = "";
            if (patchForm) patchForm.reset();
            if (flagResult) flagResult.hidden = true;
            if (patchResult) patchResult.hidden = true;
            awdpUpdatePatchFileName();
            awdpApplyState(data.state || data.environment || { status: "环境已重置" });
            awdpReloadWebLab(true);
            return loadAwdpSubmissions(id);
        })
        .catch((error) => {
            awdpSetWebConnection(`重置失败：${error.message}`, "error");
        })
        .finally(() => awdpSetBusy(button, false));
}

function initAwdpChallenge() {
    const root = document.querySelector(".awdp-page");
    if (!root || root.dataset.awdpInitialized === "1") return;
    root.dataset.awdpInitialized = "1";
    const challengeId = awdpChallengeId();
    const initialState = awdpConfig().state || {};
    awdpApplyState(initialState);
    if (initialState.submissions) renderAwdpSubmissions(initialState.submissions);

    document.querySelectorAll("[data-awdp-tab]").forEach((tab) => {
        tab.addEventListener("click", () => awdpSwitchTab(tab.dataset.awdpTab));
    });
    const patchInput = document.getElementById("awdpPatchInput");
    patchInput && patchInput.addEventListener("change", awdpUpdatePatchFileName);
    const refresh = document.getElementById("awdpRefreshSubmissionsButton");
    refresh && refresh.addEventListener("click", () => loadAwdpSubmissions(challengeId));
    awdpInitWebLab(challengeId);
    loadAwdpState(challengeId);
    loadAwdpSubmissions(challengeId);
}

// ── AWDP 真实复现环境按需启停（双轨制） ────────────────────
function _awdpRealEnvUi(state, data) {
    const section = document.getElementById("awdpRealEnvSection");
    if (!section) return;
    const badge = document.getElementById("awdpRealEnvBadge");
    const desc = document.getElementById("awdpRealEnvDesc");
    const startBtn = document.getElementById("awdpRealEnvStartBtn");
    const stopBtn = document.getElementById("awdpRealEnvStopBtn");
    if (badge) badge.innerText = state;
    if (desc && data && data.message) desc.innerText = data.message;
    if (startBtn) startBtn.style.display = (data && data.state === "stopped") ? "block" : "none";
    if (stopBtn) stopBtn.style.display = (data && (data.state === "running" || data.state === "partial")) ? "block" : "none";
}

function loadAwdpRealEnvStatus(challengeId) {
    const section = document.getElementById("awdpRealEnvSection");
    if (!section) return;
    fetch(`/api/awdp/${challengeId}/realenv/status`)
    .then(res => res.json())
    .then(data => {
        if (!data.supported) {
            section.style.display = "none";
            return;
        }
        const labels = {
            running: `运行中 (${data.running}/${data.total})`,
            partial: `启动中 (${data.running}/${data.total})`,
            stopped: "已安装 · 未运行",
            missing: "未安装",
            unavailable: "不可用",
        };
        _awdpRealEnvUi(labels[data.state] || data.state, data);
    })
    .catch(() => {});
}

function startAwdpRealEnv(challengeId) {
    _awdpRealEnvUi("启动中...", { message: "正在启动真实环境容器组，大型应用（RAGFlow/Dify）就绪需要 1-3 分钟。" });
    fetch(`/api/awdp/${challengeId}/realenv/start`, { method: "POST" })
    .then(res => res.json().then(data => ({ ok: res.ok, data })))
    .then(({ ok, data }) => {
        _awdpRealEnvUi(ok ? "启动中..." : "启动失败", data);
        if (!ok) return;
        // 轮询等待真实环境接管题目，随后刷新页面切换到真实目标。
        let attempts = 0;
        const timer = window.setInterval(() => {
            attempts += 1;
            fetch(`/api/awdp/${challengeId}/native/status`)
            .then(res => res.json())
            .then(status => {
                const dify = status.native_dify;
                const upstream = status.native_upstream;
                const ready = (dify && dify.ready) || (upstream && upstream.enabled);
                if (ready) {
                    window.clearInterval(timer);
                    _awdpRealEnvUi("已就绪", { message: "真实环境已就绪，正在切换到真实目标..." });
                    window.location.reload();
                } else if (attempts >= 40) {
                    window.clearInterval(timer);
                    _awdpRealEnvUi("仍在初始化", { message: "容器已启动，应用仍在初始化，可稍后手动刷新页面。" });
                }
            })
            .catch(() => {});
        }, 5000);
    })
    .catch(err => _awdpRealEnvUi("启动失败", { message: `网络异常：${err.message}` }));
}

function stopAwdpRealEnv(challengeId) {
    _awdpRealEnvUi("停止中...", {});
    fetch(`/api/awdp/${challengeId}/realenv/stop`, { method: "POST" })
    .then(res => res.json())
    .then(data => {
        _awdpRealEnvUi("已停止", data);
        window.setTimeout(() => window.location.reload(), 1500);
    })
    .catch(() => loadAwdpRealEnvStatus(challengeId));
}
