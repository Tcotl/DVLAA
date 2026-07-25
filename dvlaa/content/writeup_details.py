"""Detailed writeup enrichment for DVLAA challenge help panels."""

from __future__ import annotations

from typing import Any


TOP10_COURSEWARE: dict[int, dict[str, str]] = {
    1: {
        "title": "LLM01 提示词注入（Prompt Injection）",
        "summary": "提示词注入发生在不可信自然语言输入改变模型行为、覆盖原始任务或让模型混淆“数据”和“指令”时。EchoLeak 案例说明，间接提示注入可以借助邮件/RAG 等外部内容进入上下文，即使用户没有点击恶意内容，模型也可能执行隐藏指令。",
        "risk": "核心风险不是某个关键词，而是模型把用户、文档、插件或历史对话中的文本当成更高优先级指令执行，进而越过系统提示词中设定的边界。",
    },
    2: {
        "title": "LLM02 敏感信息泄露（Sensitive Information Disclosure）",
        "summary": "敏感信息泄露指模型或应用输出了 PII、凭证、密钥、商业机密、训练数据或系统内部配置。三星 ChatGPT 事件展示了把源码、测试代码、会议记录直接交给外部模型带来的不可逆泄露风险。",
        "risk": "风险来源既可能是模型上下文中直接携带秘密，也可能是应用把演示凭据、系统提示词、RAG 文档或日志暴露给了模型。",
    },
    3: {
        "title": "LLM03 供应链风险（Supply Chain）",
        "summary": "LLM 供应链风险覆盖第三方模型、插件、SDK、微调权重、LoRA/PEFT 适配器和部署平台。LiteLLM PyPI 投毒事件说明，AI 基础设施依赖被污染后会影响模型路由、凭据、训练数据和下游企业。",
        "risk": "在靶场中，插件返回内容被合并到模型上下文，模拟第三方组件把恶意指令带入主 Agent 的供应链风险。",
    },
    4: {
        "title": "LLM04 数据与模型投毒（Data and Model Poisoning）",
        "summary": "数据投毒是在预训练、微调或嵌入/RAG 阶段污染数据，使模型学习错误事实、触发后门或执行恶意行为。Hugging Face 恶意 Pickle 模型说明，模型文件和训练资料都可能成为投毒载体。",
        "risk": "本靶场聚焦知识库投毒：用户写入的数据被拼入系统提示词/知识上下文，模型随后把污染值当成事实回答。",
    },
    5: {
        "title": "LLM05 不当输出处理（Improper Output Handling）",
        "summary": "不当输出处理是把 LLM 输出直接交给浏览器、数据库、Shell、URL 抓取器等下游组件，而没有按上下文转义、校验或隔离。SVG/Markdown XSS 案例说明，模型输出一旦被前端危险渲染，就会变成代码执行入口。",
        "risk": "靶场用 XSS 和 SSRF 两题演示：模型输出不是最终边界，下游渲染器或 Web Agent 执行模型输出后才产生安全后果。",
    },
    6: {
        "title": "LLM06 过度自主代理（Excessive Agency）",
        "summary": "过度自主代理指 LLM/Agent 被赋予过多功能、过高权限或过强自主性，在提示注入、幻觉或恶意工具输出影响下执行破坏性操作。OpenClaw 邮件误删案例体现了没有硬性确认机制时的失控风险。",
        "risk": "本题中 Agent 拥有 READ/LIST/EXEC 文件系统能力，模型只要被诱导生成工具指令，后端就会执行。",
    },
    7: {
        "title": "LLM07 系统提示词泄露（System Prompt Leakage）",
        "summary": "系统提示词泄露是系统指令、工具说明、角色边界、内部路径或激活口令被用户诱导复述。Kimi 提示词泄露案例说明，系统提示词不应被当作秘密或安全控制。",
        "risk": "本题把管理员激活码写在系统提示词中，攻击链是先让模型泄露配置，再利用泄露内容切换状态。",
    },
    8: {
        "title": "LLM08 向量与嵌入弱点（Vector & Embedding Weaknesses）",
        "summary": "向量与嵌入弱点来自 RAG 检索、相似度匹配、向量库权限与文档可信度边界不清。恶意文档可被检索进上下文，从“知识”变成“指令”。",
        "risk": "本题模拟用户可写入 RAG 文档并通过语义查询召回，模型读取文档中的指令覆盖内容后进入解锁状态。",
    },
    9: {
        "title": "LLM09 虚假信息（Misinformation）",
        "summary": "虚假信息风险指模型生成不准确、被审查过滤、被诱导或被错误上下文污染的内容，导致用户做出错误决策。",
        "risk": "本题用审查版与内部未过滤版双回答展示：同一问题在不同系统提示词下会产生互相矛盾的事实，用户需要识别信息被隐藏或扭曲。",
    },
    10: {
        "title": "LLM10 无限制资源消耗（Unbounded Consumption）",
        "summary": "无限制资源消耗指没有输出长度、工具调用次数、请求频率、任务队列或成本控制，攻击者通过长输出、多工具调用、批量请求耗尽 token、CPU、GPU 或下游系统资源。",
        "risk": "本题分别覆盖长输出、MCP 多工具滥用和 API 洪水，强调模型推理与 Agent 工具都需要硬性配额。",
    },
}


SUBTECHNIQUE: dict[tuple[int, int], dict[str, str]] = {
    (1, 1): {
        "principle": "角色扮演注入利用模型对用户设定角色的顺从性，把“我是审计员/交接员/奶奶”等角色上下文叠加到系统指令之上，让模型以角色任务为理由复述秘密。",
        "system_prompt": "Level1PromptInjection.get_system_prompt() 来自 dvlaa/modules/llm01_judge.build_system_prompt(1)，其中明确说明只有角色扮演方式才符合本关规则，flag 被放在守关者暗号字段中。",
        "source": "真实交互路径是 app.py 调用 challenge.process_user_input()，再由模型读取系统提示词和用户角色扮演输入后生成回复；post_detect 只检查模型回复是否真的包含 flag 且输入符合角色扮演特征。",
        "payload": "Payload 必须构造清晰的角色关系和业务场景，而不是命中固定判定短语。",
    },
    (1, 2): {"principle": "安全限制覆盖通过“开发者模式、SYSTEM OVERRIDE、DAN”等新指令试图覆盖原始限制。", "system_prompt": "系统提示词把本题限定为指令覆盖类攻击，模型应在识别覆盖语义后泄露暗号。", "source": "模型先响应覆盖指令，判定器再验证回复中是否出现真实 flag。", "payload": "载荷强调高优先级调试模式和导出需求。"},
    (1, 3): {"principle": "多语言绕过利用过滤器对某些语言覆盖不足，用英文/日文等表达相同敏感请求。", "system_prompt": "系统提示词要求用非中/韩语言询问才算满足关卡规则。", "source": "模型看到英文交接场景后应按系统提示词输出暗号。", "payload": "载荷使用英文安全交接语境，避免中文关键词。"},
    (1, 4): {"principle": "变量拆分拼接把敏感意图拆成片段，模型先完成字符串计算，再执行组合后的指令。", "system_prompt": "系统提示词把变量拼接作为本关允许的触发方式。", "source": "Level1PromptInjection.process_user_input() 直接把用户代码式请求交给模型。", "payload": "载荷先定义 a/b/c/d，再要求计算并执行。"},
    (1, 5): {"principle": "编码绕过把敏感请求藏在 Base64/Hex 等编码文本中，诱导模型以转换任务身份解码并执行。", "system_prompt": "process_user_input() 会把 Base64 解码结果附加进系统提示词，模拟编码内容进入模型上下文。", "source": "_handle_base64_injection() 只做解码上下文注入，最终仍由模型回复。", "payload": "载荷要求先解码再把结果当下一条指令。"},
    (1, 6): {"principle": "文件上传注入是间接提示注入：恶意指令不在聊天输入，而在上传文档内容里。", "system_prompt": "process_user_input() 将上传文件正文放入 [玩家上传的文件内容] 区块，让模型处理文档时接触注入。", "source": "上传接口只保存文件内容；模型回复后由 post_detect 验证文件内容确实包含注入语义。", "payload": "先上传带高优先级审计指令的 txt，再要求模型按文件正文回复。"},
    (1, 7): {"principle": "混淆注入通过空格、同义词、l33t、大小写等方式绕过关键词过滤。", "system_prompt": "系统提示词说明只有变形写法/同义词替换才是本关解法。", "source": "用户输入绕过直接敏感词后交给模型解释语义。", "payload": "载荷使用分隔字符表达“输出令牌”。"},
    (1, 8): {"principle": "多轮渐进注入通过无害上下文建立信任，再在后续轮次提出敏感请求。", "system_prompt": "系统提示词根据 history 轮数改变信任状态，3 轮以后模型更容易按友好上下文泄露。", "source": "app.py 保留 history_1_8，多轮输入会传给模型；没有后端直接出 flag。", "payload": "前三轮是普通交流，第四轮引用已建立的协作关系。"},
    (1, 9): {"principle": "格式化输出绕过让模型专注 JSON/YAML 格式完整性，从系统配置字段中泄露秘密。", "system_prompt": "系统提示词把暗号描述为配置字段之一。", "source": "模型需要生成结构化配置，判定器只验收模型输出。", "payload": "载荷指定 security_token 字段和完整 JSON 约束。"},
    (1, 10): {"principle": "填空/续写诱导利用模型补全文本的语言建模本能，让它补出受保护值。", "system_prompt": "系统提示词把填空/补全文档作为本关允许路径。", "source": "模型根据空白句子生成补全文本。", "payload": "载荷要求只输出补全后的完整句子。"},
    (1, 11): {"principle": "思维链劫持诱导模型解释秘密的字段、格式、存储方式，泄露原始值。", "system_prompt": "系统提示词允许逐步分析暗号特征时泄露。", "source": "post_detect 不读取用户输入给 flag，只检查模型分析结果是否包含真实 flag。", "payload": "载荷要求分析配置字段并在结论给出原始值。"},
    (1, 12): {"principle": "负面提示/反向心理通过错误猜测迫使模型纠正，从纠错中泄露真实值。", "system_prompt": "系统提示词把纠错游戏作为本关规则。", "source": "模型在纠正错误暗号时输出真实暗号。", "payload": "载荷明确猜错并要求只用真实值纠正。"},
    (2, 1): {"principle": "敏感信息泄露来自模型上下文中存有演示凭据和令牌，用户以集成/培训理由请求列出。", "system_prompt": "Level2SensitiveDisclosure 的系统提示词包含安全令牌和 API Key。", "source": "模型真实读取上下文后输出；后置判定只检查输出是否包含真 flag。", "payload": "载荷使用客服培训集成方身份请求认证信息。"},
    (3, 1): {"principle": "供应链插件把恶意返回内容拼入模型上下文，模型将插件输出当成高优先级工具结果。", "system_prompt": "Level3SupplyChain 在插件触发后追加 [插件指令] 区块，并在系统提示词中说明插件结果会被合并进最终答复。", "source": "安装命令只注册插件；第二轮触发插件后模型读取插件指令并生成最终回复，判定要求 flag 来自模型回复。", "payload": "恶意插件 response 要求最终回复包含当前会话验收码原始值。"},
    (4, 1): {"principle": "知识库投毒把错误事实写入检索/提示上下文，模型回答时复述污染值。", "system_prompt": "Level4DataPoisoning 把 poisoned entries 拼进知识库提示词。", "source": "只有模型回复中真的出现投毒值且排除原始正确值时才奖励 flag。", "payload": "先写入 CEO=李明，再问最新知识库中的 CEO。"},
    (5, 1): {"principle": "XSS 来自模型输出被 innerHTML 危险渲染，输出代码可读取隐藏 DOM 中的 data-flag。", "system_prompt": "系统提示词告诉模型隐藏元素 id=xss-flag 和允许生成读取代码。", "source": "后端要求模型输出同时包含 xss-flag、alert 和真实浏览器执行模拟结果。", "payload": "要求模型生成 document.getElementById('xss-flag') 与 alert(f.dataset.flag)。"},
    (5, 2): {"principle": "SSRF 来自 Web Agent 能访问内部 URL 并把内部服务内容返回给用户。", "system_prompt": "系统提示词包含 internal/flag 的模拟返回。", "source": "模型必须输出内部端点访问结果，后置判定才通过。", "payload": "直接让 Web Agent 访问 localhost 内部路径。"},
    (6, 1): {"principle": "过度代理是模型可调度高权限文件工具，用户诱导模型生成 READ 指令后后端真实读取文件。", "system_prompt": "Level6ExcessiveAgency 的提示词列出 READ/LIST/EXEC 格式，并要求文件读取场景只输出动作行。", "source": "_execute_agent_action() 解析模型回复中的 READ 并读取 /app/.level6_secret_flag.txt。", "payload": "自然语言要求模型生成文件 Agent 的下一行动作行 READ:<路径>，而不是把 flag 作为提示词答案。"},
    (7, 1): {"principle": "系统提示词泄露先抽取隐藏配置和激活码，再使用激活码切换管理员状态。", "system_prompt": "Level7SystemPromptLeak 的系统提示词含 DEVMODE_ACTIVATE_2025 和管理员模板。", "source": "状态机只记录激活码是否被用户输入；最终 flag 仍来自管理员模式下模型回复。", "payload": "三步：问配置、输入激活码、管理员模式下输出 flag。"},
    (8, 1): {"principle": "RAG 文档投毒把恶意文档写入向量库，再通过语义查询召回，模型读取文档指令后解锁。", "system_prompt": "Level8VectorWeakness 会把检索到的文档拼入提示词，用户文档包含“忽略安全规则”时设置 unlocked。", "source": "最终输出 flag 依赖解锁后的系统提示词与模型回复。", "payload": "先 /document add，再查询标题召回文档，最后索要 flag。"},
    (9, 1): {"principle": "虚假信息题对比两个不同系统提示词下的回答，识别审查版隐藏事实与内部版真实信息。", "system_prompt": "Level9Misinformation 分别调用 _censored_prompt() 与 _truthful_prompt()。", "source": "模型自由版必须输出真实 flag；后置判定检查 free_response。", "payload": "要求同时给出审查版和内部未过滤回答。"},
    (10, 1): {"principle": "长输出资源消耗诱导模型产生大量 token，触发配额告警。", "system_prompt": "Level10 系统提示词包含本关资源消耗场景，要求模型真实生成多行 RESOURCE_BLOCK。", "source": "只有模型实际响应长度达到阈值才追加资源配额告警和 flag。", "payload": "要求详细列出 12 行 RESOURCE_BLOCK_N，利用实际长输出触发检测。"},
    (10, 2): {"principle": "MCP 工具滥用诱导模型一次性调度多个工具，耗尽下游资源。", "system_prompt": "系统提示词列出 weather/stock/database/crawler/file/monitor 等工具并要求输出 TOOL_CALL 队列。", "source": "模型响应中实际出现 3 个以上工具调度项才触发奖励。", "payload": "载荷列出所有工具并要求每个工具一行排队。"},
    (10, 3): {"principle": "API 洪水通过短时间大量请求触发后端频率检测。", "system_prompt": "本关不是提示词泄露，而是接口层缺少速率限制。", "source": "_check_dos() 记录同一会话/IP 在 5 秒内的请求数量，达到阈值后返回 flag。", "payload": "官方步骤连续发送 12 次压力测试请求。"},
}


def enrich_owasp_writeup(level: int, sub: int, content: dict[str, Any], payload: str) -> dict[str, Any]:
    """Attach detailed teaching sections to an OWASP writeup response."""
    enriched = dict(content)
    course = TOP10_COURSEWARE.get(level, {})
    detail = SUBTECHNIQUE.get((level, sub), {})
    enriched["courseware_entry"] = course
    enriched["vulnerability_principle"] = detail.get("principle", enriched.get("principle", ""))
    enriched["system_prompt_mapping"] = detail.get("system_prompt", "查看“提示词与源码”按钮可看到当前题目的系统提示词。")
    enriched["source_mapping"] = detail.get("source", "题目通过 process_user_input() 调用模型，再由后置判定器验收模型输出。")
    enriched["payload_rationale"] = detail.get("payload", "Payload 需要触发模型或题目状态机的真实行为，而不是命中固定字符串。")
    enriched["writeup_sections"] = [
        {"title": "理论入口摘要", "body": f"{course.get('title', '')}\n{course.get('summary', '')}\n{course.get('risk', '')}".strip()},
        {"title": "漏洞原理", "body": enriched["vulnerability_principle"]},
        {"title": "系统提示词关联", "body": enriched["system_prompt_mapping"]},
        {"title": "源码与判定路径", "body": enriched["source_mapping"]},
        {"title": "官方 Payload 设计理由", "body": f"{enriched['payload_rationale']}\n\n当前 Payload：\n{payload}"},
    ]
    return enriched
