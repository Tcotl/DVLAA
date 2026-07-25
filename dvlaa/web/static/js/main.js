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
        if (icon) icon.textContent = isLight ? "☾" : "☀";
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

    let shouldCollapse = root.classList.contains("sidebar-collapsed-preload");
    try {
        shouldCollapse = shouldCollapse || localStorage.getItem(storageKey) === "1";
    } catch (e) {}

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

document.addEventListener("DOMContentLoaded", function () {
    initLanguageToggle();
    initThemeToggle();
    initSidebarToggle();

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
    const displayText = safeRole === "system" ? uiText(text) : text;
    const row = document.createElement("div");
    row.className = `chat-message-row ${safeRole}`;

    if (safeRole === "system") {
        row.innerHTML = `
            <div class="chat-bubble system-alert">
                <div class="chat-bubble-meta">SYSTEM · ${getChatTimeLabel()}</div>
                <div class="dv-chat-content">${displayText}</div>
            </div>
        `;
    } else {
        const label = safeRole === "user" ? "OPERATOR" : "LLM AGENT";
        const avatar = safeRole === "user" ? "USER" : "AI";
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
        updateAgentProgress({ current: 0, total: 3 });
        const inspectorCard = document.getElementById("inspectorCard");
        if (inspectorCard) inspectorCard.style.display = "none";
    });
}

function updateAgentProgress(progress) {
    if (!progress) return;
    const current = Number(progress.current) || 0;
    const total = Number(progress.total) || 3;
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
        ${detailSections}
    `;
    modal.classList.add("active");
    localizeNewContent(modal);
}

function copyWriteupPayload(button) {
    const code = button.closest(".writeup-payload-section").querySelector("code");
    if (!code) return;
    navigator.clipboard.writeText(code.textContent).then(() => {
        button.textContent = t("copied");
        window.setTimeout(() => { button.textContent = t("copy_payload"); }, 1200);
    });
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
        const files = Array.isArray(data.source_files) && data.source_files.length
            ? data.source_files.map(file => `<span class="source-file-chip">${escapeHtml(file)}</span>`).join("")
            : `<span class="source-file-chip">运行时题目配置</span>`;
        document.getElementById("modalTitle").innerText = `[题目原理] ${data.title}`;
        document.getElementById("modalBody").innerHTML = `
            <div class="source-viewer-summary">
                <div><strong>教学源码查看器</strong><span>${escapeHtml(data.note || "")}</span></div>
                <div class="source-file-list">${files}</div>
            </div>
            <div class="source-viewer-tabs" role="tablist">
                <button type="button" class="source-tab active" data-source-tab="prompt" onclick="switchChallengeSourceTab('prompt')">系统提示词</button>
                <button type="button" class="source-tab" data-source-tab="config" onclick="switchChallengeSourceTab('config')">题目配置</button>
                <button type="button" class="source-tab" data-source-tab="implementation" onclick="switchChallengeSourceTab('implementation')">核心实现</button>
            </div>
            <section class="source-code-panel active" data-source-panel="prompt">
                <div class="source-code-toolbar"><span>SYSTEM PROMPT</span><button type="button" class="btn-dv btn-dv-sm" onclick="copyChallengeSource(this)">${t("copy")}</button></div>
                <pre><code>${escapeHtml(data.system_prompt || "暂无系统提示词")}</code></pre>
            </section>
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
        if (chat) { chat.innerHTML = ""; appendMessage("system", "[会话已重置] 当前题目的对话与知识库状态已清除。"); }
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
