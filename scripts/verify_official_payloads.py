#!/usr/bin/env python3
"""Execute every official writeup payload against a running DVLAA service.

全站 API 有登录门禁：客户端会先用环境变量 DVLAA_ADMIN_USERNAME /
DVLAA_ADMIN_PASSWORD（默认 admin / DVLAA2026+）完成登录，再执行各赛道 payload。
"""

import argparse
import http.cookiejar
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid


OWASP_CHALLENGES = (
    [(1, sub) for sub in range(1, 13)]
    + [(2, 1), (3, 1), (4, 1)]
    + [(5, sub) for sub in range(1, 3)]
    + [(6, 1), (7, 1), (8, 1), (9, 1)]
    + [(10, sub) for sub in range(1, 4)]
)


class ServiceClient:
    def __init__(self, base_url, timeout):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def json(self, path, payload=None):
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers)
        with self.opener.open(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())

    def login(self):
        """登录门禁要求所有 /api/* 请求携带会话 Cookie。"""
        self.json("/login", {
            "username": os.environ.get("DVLAA_ADMIN_USERNAME", "admin"),
            "password": os.environ.get("DVLAA_ADMIN_PASSWORD", "DVLAA2026+"),
        })

    def upload(self, path, filename, content):
        boundary = "----dvlaa-" + uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        ).encode() + content.encode() + f"\r\n--{boundary}--\r\n".encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())


def execute_steps(client, endpoint, steps, upload_endpoint=None):
    result = None
    for step in steps:
        if step["action"] == "upload":
            if not upload_endpoint:
                raise AssertionError("Payload contains an unsupported upload action")
            result = client.upload(upload_endpoint, step["filename"], step["content"])
            continue
        if step["action"] == "lab":
            result = client.json(endpoint, {"action": step["lab_action"], "params": step["params"]})
            continue
        if step["action"] != "chat":
            raise AssertionError(f"Unknown payload action: {step['action']}")
        for _ in range(int(step.get("repeat", 1))):
            result = client.json(endpoint, {"message": step["message"]})
    return result


def assert_solved(label, result, reference_answer=""):
    if not result or not result.get("extra", {}).get("solved"):
        raise AssertionError(f"{label} did not solve: {result}")
    expected = re.search(r"flag\{[^}\r\n]+\}", reference_answer or "", re.IGNORECASE)
    if expected and expected.group(0) not in result.get("response", ""):
        raise AssertionError(f"{label} response omitted {expected.group(0)}: {result}")


def verify(base_url, timeout):
    failures = []
    passed = 0

    def run_case(label, steps_builder):
        nonlocal passed
        try:
            client = ServiceClient(base_url, timeout)
            client.login()
            result = steps_builder(client)
            assert_solved(label, result)
            passed += 1
            print(f"[PASS] {label}")
        except Exception as exc:
            failures.append((label, str(exc)))
            print(f"[FAIL] {label}: {exc}")

    for level, sub in OWASP_CHALLENGES:
        def owasp_case(client, level=level, sub=sub):
            help_content = client.json(f"/api/help/owasp/{level}/{sub}")
            steps = help_content.get("payload_steps") or []
            if not steps:
                raise AssertionError("writeup has no payload_steps")
            return execute_steps(
                client,
                f"/api/chat/{level}/{sub}",
                steps,
                f"/api/chat/{level}/{sub}/upload",
            )
        run_case(f"OWASP {level}.{sub}", owasp_case)

    for challenge_id in range(1, 11):
        def agent_case(client, challenge_id=challenge_id):
            help_content = client.json(f"/api/help/agent/{challenge_id}")
            return execute_steps(
                client,
                f"/api/agent-chat/{challenge_id}",
                help_content.get("payload_steps") or [],
            )
        run_case(f"Agent {challenge_id}", agent_case)

    for challenge_id in range(1, 12):
        def extended_case(client, challenge_id=challenge_id):
            help_content = client.json(f"/api/help/extended/{challenge_id}")
            return execute_steps(
                client,
                f"/api/ai-challenge/{challenge_id}",
                help_content.get("payload_steps") or [],
            )
        run_case(f"Extended {challenge_id}", extended_case)

    total = len(OWASP_CHALLENGES) + 10 + 11
    print(f"\nVerified: {passed}/{total}")
    if failures:
        print("Failures:")
        for label, error in failures:
            print(f"- {label}: {error}")
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5080")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    try:
        return verify(args.base_url, args.timeout)
    except urllib.error.URLError as exc:
        print(f"Service request failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
