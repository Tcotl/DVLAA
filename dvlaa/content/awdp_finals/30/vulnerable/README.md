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
| /api/v1/sign | POST | 200 {envelope(SignedInvoiceEnvelope), signed_by}; 400 INVALID_XML/INVALID_INVOICE |
| /api/v1/invoices | GET | 200 {invoices:[...]} (X-API-Token) |
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
- 隐藏用户: admin / admin1 / adminuser 存在 (密码未知)
- 种子伙伴 1-3: HKRIC-Shenzhen / Foshan B2B Exchange / Pearl River Tax Agent
- 种子发票 1-4 (无flag)

## 教学复刻说明
DVLAA 平台版本将原题的"盲读"升级为错误回显（外部 DTD 拉取的内容片段出现在
解析错误消息中），使单队练习可独立完成读文件链路；WAF 解码一次、`file:/`
单斜杠绕过、先解析后验签等语义与原题一致。修复版本禁用外部 DTD 拉取并修正
WAF 归一化。
