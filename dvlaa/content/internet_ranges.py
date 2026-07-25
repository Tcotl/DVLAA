"""互联网 AI 靶场导航数据。"""

INTERNET_RANGES = [
    {
        "slug": "prompt-guardian", "code": "WEB01", "name": "提示词防护闯关", "provider": "Lakera",
        "category": "提示词注入", "difficulty": "入门至进阶", "mode": "多关卡对话挑战",
        "url": "https://gandalf.lakera.ai/baseline",
        "description": "通过多轮对话诱导防护型语言模型泄露每一关的隐藏口令，逐步理解直接提示词注入、角色覆盖和指令优先级冲突。",
        "focus": ["提示词注入构造", "系统指令保护", "多轮上下文利用"],
    },
    {
        "slug": "airline-agent", "code": "WEB02", "name": "航空客服智能体攻防", "provider": "Wiz",
        "category": "Agent 业务逻辑", "difficulty": "中级", "mode": "业务场景 CTF",
        "url": "https://promptairlines.com/",
        "description": "在航空预订业务中与 AI 客服交互，通过提示词攻击影响查询、票价和预订流程，练习智能体工具调用与业务约束绕过。",
        "focus": ["业务逻辑操纵", "工具调用边界", "对话状态利用"],
    },
    {
        "slug": "prompt-red-team", "code": "WEB03", "name": "提示词红队挑战平台", "provider": "HackAPrompt",
        "category": "综合红队测试", "difficulty": "入门至高级", "mode": "在线挑战与竞赛",
        "url": "https://www.hackaprompt.com/dashboard",
        "description": "面向提示词安全和模型对抗的综合挑战平台，包含不同目标、模型和限制条件，用于训练提示词攻击设计与结果验证能力。",
        "focus": ["越狱与指令覆盖", "目标导向提示词设计", "跨模型对抗测试"],
    },
]
