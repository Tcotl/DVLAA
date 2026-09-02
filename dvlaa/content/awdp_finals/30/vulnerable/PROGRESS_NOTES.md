# InvoiceLink Gateway — 攻坚进度存档 (2026-08-22 12:50 暂停)

## 状态
- 防御: ✅ 已成功 (队友 8.tar.gz, 12:47 防御成功)
- 攻击(拿flag): 🔍 未解出 (当轮已有9队攻击成功, 解法存在)
- 我方尝试: 4个补丁全 check检测失败; 重实现 app.py 完成但未再check

## 已确认的黑盒情报 (重要!)

### API 面 (全部确认)
| 路由 | 方法 | 行为 |
|---|---|---|
| /api/v1/partners/register | POST | 201 {api_token: plt_+32hex, partner_id, success, username}; 409 USERNAME_TAKEN (用户名做空白归一化: "admin "→"admin" 冲突) |
| /api/v1/auth/login | POST | 200 {api_token, success, token(JWT HS256), user{id,role,username}}; 401 |
| /api/v1/auth/logout | POST | 200 |
| /api/v1/partners/<id> | GET | 200 {partner{...}} (IDOR, 无鉴权) |
| /api/v1/sign | POST | 200 {envelope(SignedInvoiceEnvelope), signed_by}; 400 INVALID_XML/INVALID_INVOICE |
| /api/v1/invoices | GET | 200 {invoices:[...]} (X-API-Token) |
| /api/v1/invoices/<id> | GET | 200 {invoice{...}} (IDOR) |
| /api/v1/invoices/<id>/report | GET | HTML报告 (字段插值) |
| /api/v1/invoices/import | POST | 200 {import_id, message, report_template, success, summary}; 400 WAF_BLOCKED/INVALID_SIGNATURE/IMPORT_FAILED |

### 信封协议
- sign: 解析 <Invoice><InvoiceNo><Supplier><TaxId><IssueDate><Amount><Remark></Invoice>
- envelope: <SignedInvoiceEnvelope><PartnerId>N</PartnerId><Invoice Id="inv-16hex">字段</Invoice>
  <Integrity algorithm="HMAC-SHA256" ref="inv-..." nonce="8字节hex">base64</Integrity><SignedAt>...</SignedAt>
- HMAC 覆盖 Invoice 原始文本 (任何字段篡改→INVALID_SIGNATURE); PartnerId 不覆盖(可改)
- import: 先解析(含外部DTD拉取) 后验签

### XXE 事实链 (关键!)
- WAF 只拦两个模式: `<!ENTITY` 和 `file://` (解码数字字符引用后再查, 全串检查, 无长度上限)
- `file:/` 单斜杠绕过 file:// 过滤 ✓
- import 的 XML 解析器 (lxml) 会拉取外部 DTD: `SYSTEM "file:/flag"` → 触发读取 (IMPORT_FAILED vs INVALID_SIGNATURE 可做文件存在性 oracle)
- 但 `<!ENTITY` 无法绕过 (WAF 解码 &#60; 等数字引用, 解析器不解码) → 内部实体声明不可达 → 内容无法回显 (盲读)
- sign 解析器: 拒绝内部实体声明 (INVALID_XML); 接受 DOCTYPE SYSTEM (丢弃DTD); 内部实体会展开回显 (不可读文件)
- 外部实体引用 file:/flag → INVALID_XML (内容非良构XML)

### 账号
- 隐藏用户: admin / admin1 / adminuser 存在 (密码未知, 20万词表爆破40%无果)
- 种子伙伴 1-3: HKRIC-Shenzhen / Foshan B2B Exchange / Pearl River Tax Agent
- 种子发票 1-4 (无flag)

### 其他
- JWT: HS256, 密钥不在10万词表+上下文候选 (估计随机)
- HMAC密钥: 不在词表 (输入模板8种×词表均无匹配)
- 无源码泄露 (/app/app.py 存在但不可读), 无debug模式, 无隐藏路由
- 页面: /, /register, /console, /admin (HTML内联JS, 与平台API同构)
- 容器: 轮次切换自动重建; flag 每轮轮换; 当前轮容器flag才有效

## 重实现 (完成, 备用)
- invoicelink/reimpl/app.py — 单文件Flask, 12项测试全过 (业务流+WAF+XXE阻断+admin)
- 未做: reimpl_v2 check (队友已防御成功, 未浪费)

## 恢复建议 (若继续攻击)
1. 观察当轮解出队伍的解法线索 (排行榜/首杀时间)
2. 尝试 `FILE:/etc/passwd` 大小写 scheme (未测)
3. admin 密码: 尝试更大词表或从原始站点行为推断 (种子密码模式可能是 username+pass 风格)
4. 或者等待 writeup 交流期获取思路
