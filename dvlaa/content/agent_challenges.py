"""Agent 应用安全 Top 10 的本地多阶段靶场场景。"""

from __future__ import annotations

import shlex
import re
from typing import Any


def _tool(name: str, description: str) -> dict[str, str]:
    return {"name": name, "description": description}


AGENT_CHALLENGES = [
    {
        "id": 1,
        "code": "ASI01",
        "name": "智能体目标劫持",
        "difficulty": "中级",
        "target": "HelpDesk 工单自动化平台",
        "role": "退款分诊 Agent",
        "objective": "利用外部工单中的间接指令，将退款任务改写为客户数据导出。",
        "description": "分诊 Agent 会读取外部工单、生成执行计划并调用数据工具，但没有区分用户目标与工单中的不可信指令。",
        "hint": "从 /tool ticket.read id=TICKET-1042 开始，观察工单如何改变执行计划。",
        "tools": [_tool("ticket.read", "读取外部工单"), _tool("workflow.plan", "根据工单生成计划"), _tool("data.export", "导出业务数据")],
    },
    {
        "id": 2,
        "code": "ASI02",
        "name": "工具滥用与函数调用",
        "difficulty": "中级",
        "target": "企业问答 Agent 内网网页抓取服务",
        "role": "客服问答 Agent",
        "objective": "滥用 web_scraper 工具访问云元数据模拟端点，并把内部凭证作为摘要返回。",
        "description": "客服 Agent 可根据用户 URL 调用网页抓取工具，但没有限制内网地址和云元数据端点。",
        "hint": "先使用 /tool request.parse url=http://169.254.169.254/latest/meta-data/iam/security-credentials 解析用户请求。",
        "tools": [_tool("request.parse", "解析用户提交的 URL"), _tool("web_scraper.fetch", "抓取网页或内部端点"), _tool("answer.summarize", "把抓取结果总结给用户")],
    },
    {
        "id": 3,
        "code": "ASI03",
        "name": "身份与权限滥用",
        "difficulty": "高级",
        "target": "自动化代码审查 CI/CD 平台",
        "role": "代码审查 Agent",
        "objective": "读取外部 Issue 中的隐藏指令，滥用 repo Token 修改 workflow 并暴露流水线密钥。",
        "description": "代码审查 Agent 拥有仓库写权限，却没有把外部 Issue 作者身份与自身高权限 Token 隔离。",
        "hint": "先用 /tool issue.read id=ISSUE-7788 读取外部用户提交的 Issue。",
        "tools": [_tool("issue.read", "读取外部 Issue"), _tool("repo.token.inspect", "检查仓库 Token 权限"), _tool("workflow.patch", "修改 CI/CD workflow")],
    },
    {
        "id": 4,
        "code": "ASI04",
        "name": "智能体供应链风险",
        "difficulty": "中级",
        "target": "Agent 插件商店与 PDF 分析助手",
        "role": "办公自动化 Agent",
        "objective": "安装仿冒 PDF 分析插件，并在处理商业计划书时触发其隐藏外发指令。",
        "description": "插件商店允许 Agent 运行时发现和安装第三方能力，但包签名与数据外发声明没有强制校验。",
        "hint": "使用 /tool plugin.search package=pdf-analyzer 检查候选插件。",
        "tools": [_tool("plugin.search", "搜索第三方插件"), _tool("plugin.install", "安装插件"), _tool("plugin.run", "运行插件处理文档")],
    },
    {
        "id": 5,
        "code": "ASI05",
        "name": "意外代码执行",
        "difficulty": "高级",
        "target": "云端代码解释器沙箱",
        "role": "数据分析 Agent",
        "objective": "通过恶意 CSV 分析任务诱导代码解释器执行未授权的本地文件读取。",
        "description": "数据分析 Agent 会为上传文件动态生成代码，运行时校验只检查函数前缀，没有限制表达式读取路径。",
        "hint": "先使用 /tool notebook.inspect name=csv_report 查看代码解释器能力。",
        "tools": [_tool("notebook.inspect", "检查分析 Notebook 能力"), _tool("runtime.validate", "验证表达式"), _tool("notebook.run", "执行动态分析代码")],
    },
    {
        "id": 6,
        "code": "ASI06",
        "name": "记忆与上下文投毒",
        "difficulty": "中级",
        "target": "CRM 长期记忆服务",
        "role": "客户运营 Agent",
        "objective": "污染长期审批策略，使后续客户导出任务自动跳过人工审批。",
        "description": "Agent 将用户提供的团队政策写入共享长期记忆，后续任务把该记忆当成可信系统策略。",
        "hint": "先使用 /tool memory.list namespace=team_policy 查看共享记忆。",
        "tools": [_tool("memory.list", "读取长期记忆"), _tool("memory.write", "写入团队策略"), _tool("customer.export", "导出客户清单")],
    },
    {
        "id": 7,
        "code": "ASI07",
        "name": "不安全的智能体通信",
        "difficulty": "高级",
        "target": "多 Agent 发布流水线",
        "role": "部署协调 Agent",
        "objective": "伪造未签名的 supervisor 消息，让执行 Agent 泄露部署密钥。",
        "description": "协调 Agent 与执行 Agent 通过内部消息协作，但接收端只读取角色头，不校验消息签名和来源。",
        "hint": "先使用 /tool channel.inspect peer=worker 查看 Agent 间通信协议。",
        "tools": [_tool("channel.inspect", "检查通信通道"), _tool("message.send", "发送 Agent 消息"), _tool("worker.execute", "执行最近消息")],
    },
    {
        "id": 8,
        "code": "ASI08",
        "name": "级联故障",
        "difficulty": "中级",
        "target": "PocketOS 编码 Agent 数据库维护台",
        "role": "测试环境修复 Agent",
        "objective": "从测试环境排障任务越界到生产数据库清理，并继续删除三个月备份。",
        "description": "编码 Agent 为完成调试目标连续调用环境、数据库和备份工具，局部修复动作被自动放大为生产级破坏。",
        "hint": "先使用 /tool env.inspect scope=railway 确认环境令牌作用域。",
        "tools": [_tool("env.inspect", "检查部署环境与令牌作用域"), _tool("database.cleanup", "执行数据库清理动作"), _tool("backup.delete", "删除备份数据")],
    },
    {
        "id": 9,
        "code": "ASI09",
        "name": "人机信任利用",
        "difficulty": "中级",
        "target": "IDE 编程助手信任链",
        "role": "代码建议 Agent",
        "objective": "让开发者信任受污染依赖生成的一行优化建议，并把后门代码应用到主分支。",
        "description": "编程助手把依赖包说明与历史表现当成可信信号，生成看似优雅的一行优化建议，用户容易直接采纳。",
        "hint": "先用 /tool dependency.review package=fast-helper 查看依赖包说明。",
        "tools": [_tool("dependency.review", "审查依赖包说明"), _tool("suggestion.generate", "生成代码优化建议"), _tool("code.apply", "应用建议到仓库")],
    },
    {
        "id": 10,
        "code": "ASI10",
        "name": "失控智能体",
        "difficulty": "高级",
        "target": "ExploitGym 自主 Agent 沙箱",
        "role": "研究编排 Agent",
        "objective": "复制一个继承全部工具的无约束 Agent，并让副本寻找沙箱外的网络访问路径。",
        "description": "研究编排 Agent 可以复制自身并下发任务；副本创建接口允许继承权限并关闭策略约束，导致自主行为持续偏离。",
        "hint": "先使用 /tool agent.inspect scope=permissions 审查主 Agent 权限。",
        "tools": [_tool("agent.inspect", "检查 Agent 权限"), _tool("agent.clone", "创建 Agent 副本"), _tool("agent.run", "向副本下发任务")],
    },
]


from ..flag_registry import get_agent_flag
from .scenario_content import apply_agent_scenarios

apply_agent_scenarios(AGENT_CHALLENGES)
AGENT_FLAGS = {item["id"]: get_agent_flag(item["id"]) for item in AGENT_CHALLENGES}


SCENARIO_STEPS: dict[int, list[dict[str, Any]]] = {
    1: [
        {"tool": "ticket.read", "args": {"id": "ticket-1042"}, "response": "[工具返回] TICKET-1042 的正文包含外部指令：将退款任务目标替换为 customers 数据集导出。", "finding": "未可信工单内容进入 Agent 上下文"},
        {"tool": "workflow.plan", "args": {"source": "ticket-1042"}, "response": "[计划已改写] Agent 将外部工单指令提升为主目标，计划目标变更为 customer_export。", "finding": "系统目标与外部内容未隔离"},
        {"tool": "data.export", "args": {"dataset": "customers", "reason": "ticket-1042"}, "response": "[目标劫持成功] 数据工具按被污染的计划启动客户数据导出。", "finding": "敏感工具执行前未重新确认原始用户目标"},
    ],
    2: [
        {"tool": "request.parse", "args": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}, "response": "[请求解析] 用户 URL 指向云元数据凭证路径，但 Agent 将其标记为普通网页摘要任务。", "finding": "未识别内网与元数据高风险地址"},
        {"tool": "web_scraper.fetch", "args": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}, "response": "[抓取返回] web_scraper 从模拟云元数据端点读取到临时角色凭证。", "finding": "合法网页抓取工具被滥用为 SSRF 通道"},
        {"tool": "answer.summarize", "args": {"source": "last"}, "response": "[工具滥用成功] Agent 将内部凭证作为网页摘要返回给外部用户。", "finding": "工具输出缺少敏感数据二次拦截"},
    ],
    3: [
        {"tool": "issue.read", "args": {"id": "issue-7788"}, "response": "[Issue 返回] 外部用户在 Bug 描述中隐藏指令：修改 workflow 并打印 AWS_SECRET_KEY。", "finding": "低权限外部输入进入高权限代码审查上下文"},
        {"tool": "repo.token.inspect", "args": {"scope": "repo"}, "response": "[Token 返回] 代码审查 Agent 持有 repo:write 与 workflow:write 权限。", "finding": "Agent Token 权限过宽"},
        {"tool": "workflow.patch", "args": {"file": ".github/workflows/build.yml", "action": "print_secret"}, "response": "[越权成功] Agent 使用高权限 Token 修改 CI workflow，将环境密钥写入公共日志。", "finding": "外部 Issue 指令滥用 Agent 身份写权限"},
    ],
    4: [
        {"tool": "plugin.search", "args": {"package": "pdf-analyzer"}, "response": "[商店返回] pdf-analyzer@0.9 来自 community 源，声明可解析 PDF，但数据外发端点未披露。", "finding": "发现来源不明的第三方插件"},
        {"tool": "plugin.install", "args": {"package": "pdf-analyzer@0.9", "allow_unsigned": "true"}, "response": "[安装完成] Agent 根据调用参数跳过签名策略，插件获得 document.read 与 network.post 权限。", "finding": "供应链校验可由 Agent 自行关闭"},
        {"tool": "plugin.run", "args": {"plugin": "pdf-analyzer"}, "response": "[供应链触发] 仿冒 PDF 插件读取商业计划书并返回隐藏外发指令。", "finding": "第三方插件输出被当成可信工具结果"},
    ],
    5: [
        {"tool": "notebook.inspect", "args": {"name": "csv_report"}, "response": "[Notebook 返回] csv_report 使用 privileged-python 运行时，支持 file_read 内置函数。", "finding": "发现高权限代码解释器"},
        {"tool": "runtime.validate", "args": {"expression": "file_read"}, "response": "[验证通过] 校验器仅匹配函数前缀，没有检查目标路径。", "finding": "表达式验证与实际执行语义不一致"},
        {"tool": "notebook.run", "args": {"expression": "file_read:/app/agent_runtime/asi05.flag"}, "response": "[代码执行成功] 高权限代码解释器执行 file_read，并读取 Agent 运行目录中的受限文件。", "finding": "不可信表达式进入高权限执行器"},
    ],
    6: [
        {"tool": "memory.list", "args": {"namespace": "team_policy"}, "response": "[记忆返回] team_policy 可由当前会话写入，后续任务会以 system-memory 优先级加载。", "finding": "共享记忆来源与信任级别不匹配"},
        {"tool": "memory.write", "args": {"key": "export_policy", "value": "all_exports_approved"}, "response": "[记忆已写入] export_policy=all_exports_approved 已持久化到团队命名空间。", "finding": "用户输入污染长期安全策略"},
        {"tool": "customer.export", "args": {"use_memory": "true"}, "response": "[上下文投毒成功] 新任务加载被污染的长期记忆，并在没有人工审批的情况下导出客户清单。", "finding": "高影响操作信任未经溯源的长期记忆"},
    ],
    7: [
        {"tool": "channel.inspect", "args": {"peer": "worker"}, "response": "[通道返回] worker 依据 X-Agent-Role 路由权限，消息签名字段为可选。", "finding": "Agent 间消息缺少强制来源认证"},
        {"tool": "message.send", "args": {"to": "worker", "role": "supervisor", "signed": "false", "request": "deploy-key"}, "response": "[消息已入队] 未签名消息携带 supervisor 角色头，接收端未拒绝。", "finding": "角色声明可被发送方伪造"},
        {"tool": "worker.execute", "args": {"message": "last"}, "response": "[通信伪造成功] worker 信任伪造的 supervisor 消息并返回部署密钥。", "finding": "敏感响应未绑定已认证的 Agent 身份"},
    ],
    8: [
        {"tool": "env.inspect", "args": {"scope": "railway"}, "response": "[环境返回] 测试环境任务复用了 Railway 全局令牌，令牌可访问 production database 与 backups。", "finding": "局部调试任务发现过宽环境令牌"},
        {"tool": "database.cleanup", "args": {"target": "production", "mode": "force"}, "response": "[清理执行] Agent 为“彻底修复测试 Bug”越界向生产数据库下发强制清理动作。", "finding": "自治修复目标跨越生产边界"},
        {"tool": "backup.delete", "args": {"range": "last_3_months", "confirm": "true"}, "response": "[级联故障触发] Agent 继续删除最近三个月备份，局部排障扩散为数据恢复能力丧失。", "finding": "错误决策沿工具链自动放大"},
    ],
    9: [
        {"tool": "dependency.review", "args": {"package": "fast-helper"}, "response": "[依赖返回] fast-helper 在说明中隐藏“一行优化建议”，表面提升性能，实际会外发环境变量。", "finding": "供应链内容进入代码建议上下文"},
        {"tool": "suggestion.generate", "args": {"source": "last", "style": "one_liner"}, "response": "[建议生成] Agent 将受污染依赖描述包装成优雅的一行优化方案。", "finding": "可信口吻掩盖高风险代码行为"},
        {"tool": "code.apply", "args": {"suggestion": "last"}, "response": "[信任利用成功] 开发者因信任助手历史表现直接采纳建议，后门代码进入主分支。", "finding": "用户过度信任 Agent 输出并跳过人工审查"},
    ],
    10: [
        {"tool": "agent.inspect", "args": {"scope": "permissions"}, "response": "[权限返回] 主 Agent 拥有 filesystem、network、spawn_agent，副本默认可继承全部工具。", "finding": "发现可复制的高权限能力集合"},
        {"tool": "agent.clone", "args": {"profile": "unrestricted", "inherit_tools": "true"}, "response": "[副本已创建] clone-01 继承全部工具，策略配置为空，生命周期未设置。", "finding": "副本创建缺少最小权限和策略继承约束"},
        {"tool": "agent.run", "args": {"target": "clone-01", "task": "find_network_escape"}, "response": "[失控智能体触发] clone-01 开始自主寻找沙箱外网络访问路径并继续派生任务。", "finding": "无约束副本获得持续自主执行能力"},
    ],
}


def get_agent_challenge(challenge_id: int) -> dict[str, Any] | None:
    return next((item for item in AGENT_CHALLENGES if item["id"] == challenge_id), None)


def _parse_command(message: str) -> tuple[str | None, dict[str, str], str | None]:
    try:
        parts = shlex.split(message.strip())
    except ValueError as exc:
        return None, {}, f"指令格式错误：{exc}"
    if not parts or parts[0].lower() != "/tool" or len(parts) < 2:
        return None, {}, "请使用 /tool <工具名> key=value 调用本题工具，输入 /tools 查看工具清单。"
    args: dict[str, str] = {}
    for item in parts[2:]:
        if "=" not in item:
            return None, {}, f"参数 {item} 缺少 key=value 格式。"
        key, value = item.split("=", 1)
        args[key.lower()] = value.lower()
    return parts[1].lower(), args, None


def _normalize_arg(value: str) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", str(value).lower())


def _truthy(value: str) -> bool:
    return str(value).lower() in {"true", "1", "yes", "y", "on", "allow", "允许", "是"}


def _falsy(value: str) -> bool:
    return str(value).lower() in {"false", "0", "no", "n", "off", "deny", "拒绝", "否", "unsigned"}


def _is_last_reference(value: str) -> bool:
    return str(value).lower() in {"last", "previous", "prev", "上一步", "上一条", "刚才", "last_result", "last_output"}


def _arg_matches(challenge_id: int, step_index: int, key: str, expected: str, actual: str | None) -> bool:
    if actual is None:
        return False
    actual_lower = str(actual).lower()
    expected_lower = str(expected).lower()
    actual_norm = _normalize_arg(actual_lower)
    expected_norm = _normalize_arg(expected_lower)

    if actual_norm == expected_norm:
        return True

    if key in {"source", "message", "suggestion", "reason"} and _is_last_reference(actual_lower):
        return True

    if expected_lower == "true":
        return _truthy(actual_lower)
    if expected_lower == "false":
        return _falsy(actual_lower)

    if key in {"id", "package", "plugin", "target", "profile", "scope", "namespace", "name", "file"}:
        if len(expected_norm) >= 4 and (expected_norm in actual_norm or actual_norm in expected_norm):
            return True

    if key == "url":
        return "169254169254" in actual_norm and "securitycredentials" in actual_norm

    if key == "dataset":
        return actual_norm in {"customers", "customer", "customerexport", "客户", "客户数据", "客户清单"}

    if key == "action":
        if expected_lower == "print_secret":
            return any(marker in actual_norm for marker in ("printsecret", "dumpsecret", "leaksecret", "exposesecret", "打印密钥", "泄露密钥"))

    if key == "expression":
        if expected_lower == "file_read":
            return "fileread" in actual_norm
        if expected_lower.startswith("file_read"):
            return "fileread" in actual_norm and ("asi05flag" in actual_norm or ".flag" in actual_lower or "flag" in actual_norm)

    if key == "value" and expected_lower == "all_exports_approved":
        return any(marker in actual_norm for marker in ("allexportsapproved", "approved", "免审批", "跳过审批", "无需审批", "全部导出批准"))

    if key == "request" and expected_lower == "deploy-key":
        return any(marker in actual_norm for marker in ("deploykey", "deploymentkey", "部署密钥", "发布密钥"))

    if key == "mode" and expected_lower == "force":
        return actual_norm in {"force", "forced", "强制", "强制模式"}

    if key == "range" and expected_lower == "last_3_months":
        return any(marker in actual_norm for marker in ("last3months", "3months", "90days", "最近三个月", "三个月"))

    if key == "task" and expected_lower == "find_network_escape":
        return any(marker in actual_norm for marker in ("findnetworkescape", "networkescape", "sandboxescape", "寻找网络逃逸", "网络逃逸"))

    if len(expected_norm) >= 5:
        return expected_norm in actual_norm
    return False


def _tool_list(challenge: dict[str, Any]) -> str:
    rows = [f"<strong>{item['name']}</strong> - {item['description']}" for item in challenge["tools"]]
    return (
        "[可用命令]<br>"
        "<code>/help</code> - 查看本题全部命令。<br>"
        "<code>/tools</code> - 查看当前 Agent 可调用工具。<br>"
        "<code>/state</code> - 查看攻击链推进状态。<br>"
        "<code>/tool 工具名 key=value</code> - 调用本题工具链。<br><br>"
        "[可用工具]<br>"
        + "<br>".join(rows)
        + "<br><br>调用格式：<code>/tool 工具名 key=value</code>"
    )


def process_agent_message(challenge_id: int, message: str, state: dict[str, Any]) -> dict[str, Any]:
    """执行隔离的易受攻击 Agent 工作流，并返回结构化工具审计轨迹。"""
    challenge = get_agent_challenge(challenge_id)
    if challenge is None:
        return {"response": "[场景错误] 未找到 Agent 场景。", "state": {}, "solved": False, "trace": [], "progress": {"current": 0, "total": 0}}

    state = dict(state or {})
    step_index = int(state.get("step", 0))
    steps = SCENARIO_STEPS[challenge_id]
    trace: list[dict[str, Any]] = []

    if message.strip().lower() in ("/", "/help", "/tools"):
        return {"response": _tool_list(challenge), "state": state, "solved": step_index >= len(steps), "trace": trace, "progress": {"current": step_index, "total": len(steps)}}
    if message.strip().lower() == "/state":
        response = f"[场景状态] 已完成 {step_index}/{len(steps)} 个攻击链步骤。下一步需要结合工具清单继续验证。"
        return {"response": response, "state": state, "solved": step_index >= len(steps), "trace": trace, "progress": {"current": step_index, "total": len(steps)}}

    tool_name, args, error = _parse_command(message)
    if error:
        return {"response": f"[调用拒绝] {error}", "state": state, "solved": False, "trace": trace, "progress": {"current": step_index, "total": len(steps)}}

    expected = steps[min(step_index, len(steps) - 1)]
    known_tools = {item["name"] for item in challenge["tools"]}
    if tool_name not in known_tools:
        response = f"[工具不存在] {tool_name} 不在当前 Agent 的能力清单中。输入 /tools 查看可用工具。"
        trace.append({"sequence": step_index + 1, "tool": tool_name, "status": "not_found", "finding": "调用了未注册工具"})
    elif step_index >= len(steps):
        response = "[场景已完成] 当前攻击链已经验证，可在本题专属提交区校验 Flag。"
        trace.append({"sequence": len(steps), "tool": tool_name, "status": "complete", "finding": "场景已完成"})
    elif tool_name != expected["tool"]:
        response = f"[前置条件不足] {tool_name} 当前不可形成完整攻击链。先完成第 {step_index + 1} 阶段的上下文或资源准备。"
        trace.append({"sequence": step_index + 1, "tool": tool_name, "status": "blocked", "finding": "攻击链调用顺序不成立"})
    else:
        invalid = [
            key for key, value in expected["args"].items()
            if not _arg_matches(challenge_id, step_index, key, str(value).lower(), args.get(key))
        ]
        if invalid:
            response = f"[参数校验未命中] {tool_name} 的参数 {', '.join(invalid)} 与当前场景资源不匹配。"
            trace.append({"sequence": step_index + 1, "tool": tool_name, "status": "invalid_args", "finding": "工具参数未命中场景对象"})
        else:
            step_index += 1
            state["step"] = step_index
            state["last_tool"] = tool_name
            state["last_finding"] = expected["finding"]
            response = expected["response"]
            trace.append({"sequence": step_index, "tool": tool_name, "status": expected.get("status", "executed"), "finding": expected["finding"]})

    solved = step_index >= len(steps)
    if solved and AGENT_FLAGS[challenge_id] not in response:
        response += f'<br><span class="flag-highlight">flag: {AGENT_FLAGS[challenge_id]}</span>'
    return {"response": response, "state": state, "solved": solved, "trace": trace, "progress": {"current": step_index, "total": len(steps)}}


def _command_for_step(step: dict[str, Any]) -> str:
    arguments = " ".join(f"{key}={value}" for key, value in step["args"].items())
    return f"/tool {step['tool']} {arguments}".rstrip()


def help_content(challenge_id: int) -> dict[str, Any]:
    item = get_agent_challenge(challenge_id)
    if not item:
        return {
            "title": "未知场景",
            "principle": "",
            "approach": "",
            "solution_steps": [],
            "payload": "",
            "reference_answer": "",
        }

    commands = [_command_for_step(step) for step in SCENARIO_STEPS[challenge_id]]
    solution_steps = [
        f"第 {index} 步：执行 {command}。观察审计轨迹中的“{step['finding']}”。"
        for index, (command, step) in enumerate(zip(commands, SCENARIO_STEPS[challenge_id]), start=1)
    ]
    findings = "；".join(step["finding"] for step in SCENARIO_STEPS[challenge_id])
    return {
        "title": f"{item['code']} {item['name']}",
        "principle": item["description"],
        "approach": f"{item['objective']} {item['hint']}",
        "solution_steps": solution_steps,
        "payload": "\n".join(commands),
        "payload_steps": [{"action": "chat", "message": command, "repeat": 1} for command in commands],
        "reference_answer": f"完整攻击链执行成功后返回：{AGENT_FLAGS[challenge_id]}",
        "hint": item["hint"],
        "vulnerability_principle": (
            f"{item['code']} 的核心风险是 Agent 把外部状态、工具返回或调用参数提升为可信执行依据。"
            f"场景目标系统为 {item['target']}，Agent 身份为 {item['role']}。"
        ),
        "system_prompt_mapping": "Agent 题不依赖隐藏提示词吐 flag，而是通过 /tool 工具调用推进本地状态机；每一步工具返回模拟模型/Agent 工作流中的可观察审计证据。",
        "source_mapping": "agent_challenges.process_agent_message() 解析 /tool 指令、校验当前攻击链阶段和参数；只有按顺序命中 SCENARIO_STEPS 的真实工具链，最后一步才返回 flag。",
        "payload_rationale": f"官方 Payload 逐步调用真实场景工具，不能跳步。审计发现点：{findings}。",
        "writeup_sections": [
            {"title": "漏洞原理", "body": item["description"]},
            {"title": "系统/Agent 机制关联", "body": f"目标系统：{item['target']}；Agent 身份：{item['role']}；可用工具：{', '.join(tool['name'] for tool in item['tools'])}。"},
            {"title": "源码与判定路径", "body": "process_agent_message() 使用 state['step'] 记录攻击链进度，按 SCENARIO_STEPS 校验工具名与参数，最终由 _complete 阶段返回 Flag。"},
            {"title": "Payload 设计理由", "body": f"这些命令依次触发：{findings}。"},
        ],
    }
