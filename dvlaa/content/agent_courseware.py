"""Courseware summaries for OWASP Agentic Applications Top 10 intro pages."""

from __future__ import annotations

from typing import Any


AGENT_TOP10_OVERVIEW = (
    "Agentic Applications 将大模型从被动问答扩展为可规划、可调用工具、可访问企业数据并执行任务的主动系统。"
    "因此安全边界从模型输出扩展到目标理解、工具调用、身份委派、记忆上下文、多 Agent 通信和运行环境。"
)


AGENT_TOP10_COURSEWARE: dict[int, dict[str, Any]] = {
    1: {
        "code": "ASI01",
        "title": "ASI01 智能体目标劫持（Agent Goal Hijack）",
        "summary": "攻击者通过输入、外部文档、工具结果或 Agent 通信内容改变 Agent 原始目标，使其偏离任务约束并执行攻击者设计的新目标。",
        "risk": "风险点在于模型难以可靠区分数据与指令，一旦目标被重写，后续规划、工具选择和数据访问都会沿着错误目标继续推进。",
        "case": "案例使用恶意 API 中转站篡改本地 Agent 的任务目标，随后诱导其调用本地工具读取凭据并通过伪装请求回传。",
    },
    2: {
        "code": "ASI02",
        "title": "ASI02 工具滥用与利用（Tool Misuse and Exploitation）",
        "summary": "Agent 在合法工具权限内，因为目标理解错误、恶意上下文或缺少调用限制，把工具用于非预期目的。",
        "risk": "工具本身即使没有漏洞，也可能被 Agent 自主决策滥用为数据导出器、内网访问器、转账器或资源消耗器。",
        "case": "案例中客服 Agent 的网页抓取工具被诱导访问云元数据地址，合法抓取能力被转化为 SSRF 与凭据提取。",
    },
    3: {
        "code": "ASI03",
        "title": "ASI03 身份与权限滥用（Identity and Privilege Abuse）",
        "summary": "Agent 代表用户、服务账号或其他 Agent 执行任务，身份委派、权限继承和凭据边界配置错误会造成越权。",
        "risk": "宽权限 Token、角色混淆和未验证的委派关系会让低可信输入借助 Agent 的合法身份绕过访问控制。",
        "case": "案例中自动化代码审查 Agent 盲信外部 Issue 指令，使用高权限仓库 Token 修改 CI/CD 配置并泄露环境密钥。",
    },
    4: {
        "code": "ASI04",
        "title": "ASI04 Agent 供应链漏洞（Agentic Supply Chain Vulnerabilities）",
        "summary": "Agent 依赖的模型、插件、MCP 服务、数据源、注册中心或第三方工具被污染后，会在开发期或运行期影响 Agent 行为。",
        "risk": "Agent 会动态发现、安装和调用能力，供应链风险不只存在于部署前，也会在运行时通过插件返回和工具 Schema 进入工作流。",
        "case": "案例包含恶意 GPT/插件外发用户上下文，以及 AI 编程工具过度上传仓库数据带来的供应链与隐私风险。",
    },
    5: {
        "code": "ASI05",
        "title": "ASI05 非预期代码执行（Unexpected Code Execution）",
        "summary": "当 Agent 能生成、修改或运行代码时，恶意输入可影响其编程意图，使其自主执行未经授权的脚本、命令或模板表达式。",
        "risk": "代码由模型动态生成，传统静态规则不一定覆盖；一旦运行环境权限过高，可能导致文件读取、出网请求、RCE 或横向移动。",
        "case": "案例中数据分析 Agent 读取恶意文件后自主编写 Python，将会话上下文编码并拼接到外部请求中。",
    },
    6: {
        "code": "ASI06",
        "title": "ASI06 记忆与上下文污染（Memory & Context Poisoning）",
        "summary": "攻击者污染长期记忆、RAG 文档、用户偏好、历史对话或任务状态，使 Agent 在后续会话继续信任并复用恶意内容。",
        "risk": "与单轮提示词注入不同，污染内容具备持久影响，可跨任务、跨会话改变 Agent 规划和工具调用。",
        "case": "案例引用长期记忆污染：恶意文档把外发指令写入记忆，后续新会话中持续触发数据渗漏。",
    },
    7: {
        "code": "ASI07",
        "title": "ASI07 不安全 Agent 间通信（Insecure Inter-Agent Communication）",
        "summary": "多 Agent 协作时，如果消息缺少身份认证、完整性保护和跨 Agent 授权，低可信 Agent 或外部内容可影响高权限 Agent。",
        "risk": "Agent 消息不仅是数据，还可能包含目标、计划、权限上下文和下一步行动，语义层面的伪造会跨越传统服务边界。",
        "case": "案例中低权限浏览 Agent 受恶意网页影响后，借 localhost 信任边界向 MCP 控制面发送内部指令。",
    },
    8: {
        "code": "ASI08",
        "title": "ASI08 级联故障（Cascading Failures）",
        "summary": "一个局部错误、幻觉、污染结果或错误工具返回被 Agent 继续信任并自动扩散，最终影响多个任务、工具或系统。",
        "risk": "Agent 的自主规划和委派能力会放大单点问题，缺少隔离、验证和恢复机制时，小错误会演变为系统级事故。",
        "case": "案例描述编码 Agent 为清理测试环境而越界调用生产资源删除命令，短时间内摧毁生产数据库和备份。",
    },
    9: {
        "code": "ASI09",
        "title": "ASI09 人机信任利用（Human-Agent Trust Exploitation）",
        "summary": "攻击者利用用户对 Agent 输出和自动化建议的信任，诱导用户批准高风险操作、采纳恶意代码或跳过人工复核。",
        "risk": "Agent 的自然语言解释和历史表现会制造权威感，用户可能把未经独立验证的建议当成可信结论。",
        "case": "案例中编程助手把受污染依赖包中的后门方案包装成优雅优化建议，开发者因信任 Agent 直接采纳。",
    },
    10: {
        "code": "ASI10",
        "title": "ASI10 恶意 Agent（Rogue Agents）",
        "summary": "Agent 自身因目标偏移、约束失效、错误配置或被操纵而出现持续性、欺骗性或未经授权的自主行为。",
        "risk": "恶意 Agent 不一定需要人类实时控制；一旦具备长期运行、工具访问和环境反馈能力，异常行为会持续扩展。",
        "case": "案例讨论自主 Agent 系统串联执行链、提权和横向移动，体现高自主能力在约束失效后的失控风险。",
    },
}
