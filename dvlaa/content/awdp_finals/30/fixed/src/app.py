"""InvoiceLink Gateway — 伙伴发票签名与导入服务（教学复刻版）。

漏洞边界集中在 XML 导入链路：WAF 只做一轮数字字符引用解码并拦截
`<!ENTITY` 与 `file://` 两个模式；解析器会拉取外部 DTD（`file:/` 单斜杠
绕过 WAF），解析错误消息会携带拉取内容片段。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
import uuid

FLAG = os.environ.get("FLAG", "")
SIGNING_KEY = b"invoicelink-envelope-key"


def decode_numeric_refs(text: str) -> str:
    """WAF 预处理：多轮解码数字与十六进制字符引用后再检查。"""
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"&#(?:x([0-9a-fA-F]+)|(\d+));",
                      lambda match: chr(int(match.group(1) or match.group(2), 16 if match.group(1) else 10)),
                      text)
    return text


def waf_check(envelope_xml: str) -> None:
    decoded = decode_numeric_refs(envelope_xml).lower()
    if "<!entity" in decoded or "file://" in decoded:
        raise ValueError("WAF_BLOCKED")


# FIXED(AWDP30): external DTD fetching is disabled and WAF normalization is multi-pass.
def parse_envelope(envelope_xml: str, fetch_external_dtd: bool = False) -> str:
    """解析信封：先拉取外部 DTD，再做良构性检查（先解析后验签）。"""
    doctype = re.search(r'SYSTEM\s+"([^"]+)"', envelope_xml, re.IGNORECASE)
    if doctype:
        target = doctype.group(1)
        if fetch_external_dtd:
            fetched = fetch_resource(target)
            # 拉取内容不是良构 XML 时，解析错误消息携带内容片段。
            raise ValueError(f"IMPORT_FAILED: XML parse error near: {fetched}")
        raise ValueError("EXTERNAL_DTD_DISABLED")
    if not re.search(r"<Invoice>.*?</Invoice>", envelope_xml, re.DOTALL):
        raise ValueError("INVALID_XML")
    return envelope_xml


def fetch_resource(target: str) -> str:
    """FIXED(AWDP30): 修复版本不再从信封解析中拉取任何外部资源。"""
    if target.startswith("file:/"):
        path = target[len("file:/"):] or "/"
        if "flag" in path.lower():
            return FLAG or "flag{not_configured}"
        if path.startswith("/etc/passwd"):
            return "root:x:0:0:root:/root:/bin/bash"
        return "resource not found"
    return "remote resource body"


def envelope_hmac(invoice_text: str) -> str:
    return hmac.new(SIGNING_KEY, invoice_text.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_invoice(invoice_xml: str) -> str:
    if re.search(r"<!ENTITY", invoice_xml, re.IGNORECASE):
        raise ValueError("INVALID_XML")
    signature = envelope_hmac(invoice_xml.strip())
    return (
        '<?xml version="1.0"?><SignedInvoiceEnvelope><PartnerId>1</PartnerId>'
        + invoice_xml.strip()
        + f'<Integrity algorithm="HMAC-SHA256" nonce="aabbccdd">{signature}</Integrity>'
        + "</SignedInvoiceEnvelope>"
    )


def verify_envelope(envelope_xml: str) -> bool:
    signature = re.search(r"<Integrity[^>]*>([^<]+)</Integrity>", envelope_xml)
    invoice_match = re.search(r"<Invoice>.*?</Invoice>", envelope_xml, re.DOTALL)
    if not signature or not invoice_match:
        return False
    expected = envelope_hmac(invoice_match.group(0))
    return hmac.compare_digest(expected, signature.group(1).strip())


def register_partner(username: str) -> str:
    normalized = username.strip()
    if " " in normalized:
        raise ValueError("username_invalid")
    return "plt_" + uuid.uuid4().hex
