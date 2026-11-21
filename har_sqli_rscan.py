#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
har_sqli_rscan.py - 从 HAR 中过滤带参请求 -> 打 * 注入点构造 HTTP 报文 -> 交给 sqlmap -r 扫描

核心思路（与 har_sqli_scan.py 的 -u/--data/-p 方式不同）:
   1. 解析 HAR, 只保留带参数的请求（URL query 或 请求体）
   2. 把每个请求还原成一份 HTTP 请求报文文本, 在注入点后面打上 sqlmap 的 * 标记:
        - URL query 参数值:      name=value*
        - 表单 body 参数值:      name=value*
        - 原始 body(JSON 等):   整体末尾打 *
        - 可选 请求头注入:      User-Agent: xxx*    (--inject-headers)
        - 可选 Cookie 值注入:   Cookie: a=1*        (--inject-cookie)
   3. 用 sqlmap -r <报文文件> 扫描
   4. 以 sqlmap 输出为准判定是否存在 SQL 注入漏洞

用法示例:
    python3 har_sqli_rscan.py test11.har
    python3 har_sqli_rscan.py test11.har --inject-headers                 # 附带请求头注入测试
    python3 har_sqli_rscan.py test11.har --inject-headers --inject-cookie
    python3 har_sqli_rscan.py test11.har --dry-run                        # 只生成报文查看, 不扫描
    python3 har_sqli_rscan.py test11.har --no-cookie-header               # 不从 cookies 数组重建 Cookie 头
    python3 har_sqli_rscan.py test11.har --level 3 --risk 2 --parallel 3
    python3 har_sqli_rscan.py test11.har --inject-headers \
        --inject-headers-list "User-Agent,Referer,X-Forwarded-For"

产物(--outdir):
    candidates.json   过滤出的带参请求
    requests/         每个目标的 HTTP 报文文件(带 * 注入点)
    report.json       扫描结果完整报告
    sqlmap/           sqlmap 原始输出 / session 缓存 / 运行日志
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, quote

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
STATIC_EXT = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico",
    ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".cur",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".mp4", ".mp3", ".avi",
    ".webm", ".flv", ".mov", ".wav", ".json", ".xml", ".txt", ".html",
}
STATIC_DIRS = {
    "assets", "static", "images", "img", "fonts", "font", "css", "js",
    "favicon", "lib", "vendor", "jquery", "bootstrap", "font-awesome",
}

# ---- 以 sqlmap 输出为准的漏洞判定标记 ----
# 强标记(逐字匹配)或最终注入类型行, 命中才算漏洞
VULN_CONFIRM = [
    "is vulnerable",                       # "GET parameter 'name' is vulnerable."
    "identified the following injection point",   # 汇总表标题
    "sqlmap identified the following injection point",
]
_VULN_TYPE_RE = re.compile(r"is '[^']*' injectable", re.I)
_ABORT_MARKERS = [
    "are you really sure that you want to continue",
    "you have provided tainted parameter values",
]
ERROR_MARKERS = [
    "[CRITICAL]",
    "[ERROR]",
    "connection timed out",
    "failed to connect",
    "unable to connect",
    "problem occurred",
    "no connection",
]
# DBMS 提示两类: [INFO] the back-end DBMS is MySQL / it looks like the back-end DBMS is 'MySQL'.
INFO_DBMS_RE = re.compile(
    r"(?:the back-end DBMS is|back-end DBMS:|it looks like the back-end DBMS is)\s*:?\s*'?"
    r"([^'.\s]+)", re.I)
# sqlmap -r 模式下 where 形如: (URI) / ((custom) POST) / ((custom) HEADER)
PARAM_RE = re.compile(r"^\s*Parameter:\s*(.+?)\s+\((.+)\)\s*$")
# 注入确认行(即使未运行到最终汇总表也能捕获): 
#   URI parameter '#1*' is '...' injectable
#   (custom) POST parameter '#1*' is '...' injectable
#   (custom) HEADER parameter 'user-agent #1*' is '...' injectable
_INJ_LINE_RE = re.compile(
    r"(?:URI|(?:\(custom\)\s+(\w+)))\s+parameter\s+'([^']+)'\s+is\s+'"
    r"([^']+)'\s+injectable", re.I)

ERROR_EXIT_CODES = {2, 255}

# 默认参与请求头注入测试的头
DEFAULT_INJECT_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
    "Client-IP", "X-Client-IP", "X-Forwarded-Host", "Accept-Language",
    "x-requested-with", "Accept", "Origin",
]
# 请求头注入时排除的头(避免破坏报文结构)
_HEADER_INJECT_EXCLUDE = {"host", "content-length", "cookie", "connection",
                          "content-type", "transfer-encoding"}


# ---------------------------------------------------------------------------
# HAR 解析 / 过滤 / 去重
# ---------------------------------------------------------------------------
def is_static(url: str) -> bool:
    u = urlsplit(url)
    path = u.path.lower()
    ext = os.path.splitext(path)[1]
    if ext and ext in STATIC_EXT:
        return True
    parts = [p for p in path.split("/") if p]
    return any(p in STATIC_DIRS for p in parts)


def extract_requests(har_path: str, exclude_static: bool = True):
    """提取所有带参数的请求(GET query 或 POST body)。"""
    with open(har_path, encoding="utf-8", errors="replace") as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    reqs = []
    for idx, e in enumerate(entries):
        req = e.get("request") or {}
        method = (req.get("method") or "GET").upper()
        url = req.get("url", "")
        qs = req.get("queryString") or []
        post = req.get("postData") or {}
        if not isinstance(post, dict):
            post = {}
        bparams = post.get("params") or []
        btext = (post.get("text") or "").strip()
        bmime = post.get("mimeType") or ""

        has_query = bool(qs)
        has_body = bool(bparams) or bool(btext)
        if not (has_query or has_body):
            continue
        if exclude_static and is_static(url):
            continue

        headers = []
        cookies = []
        for h in req.get("headers") or []:
            name = (h.get("name") or "").strip()
            val = h.get("value", "")
            if not name:
                continue
            headers.append((name, val))
            if name.lower() == "cookie":
                cookies.append(val)
        # HAR 里 request.cookies 数组(部分工具只把 Cookie 放这里, 不放在 headers)
        cookies_arr = req.get("cookies") or []

        reqs.append({
            "index": idx,
            "method": method,
            "url": url,
            "qs": qs,
            "bparams": bparams,
            "btext": btext,
            "bmime": bmime,
            "headers": headers,
            "cookies": cookies,
            "cookies_arr": cookies_arr,
        })
    return reqs


def dedupe_requests(reqs):
    """按 (method, 路径, 参数名集合, body) 去重。"""
    seen = set()
    out = []
    for r in reqs:
        u = urlsplit(r["url"])
        path = f"{u.scheme}://{u.netloc}{u.path}"
        qnames = tuple(sorted(q.get("name", "") for q in r["qs"]))
        bnames = tuple(sorted(p.get("name", "") for p in r["bparams"] if p.get("name")))
        body_key = r["btext"] if not r["bparams"] else ""
        key = (r["method"], path, qnames, bnames, body_key, r["bmime"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# 构造带 * 注入点的 HTTP 报文
# ---------------------------------------------------------------------------
def _mark_query(r) -> str:
    """URL query 各参数值后打 *。"""
    qs = r["qs"]
    parts = urlsplit(r["url"])
    if qs:
        out = []
        for q in qs:
            name = q.get("name", "")
            if not name:
                continue
            val = q.get("value", "")
            out.append(f"{quote(name, safe='')}={quote(val, safe='')}*")
        if out:
            return "&".join(out)
    # HAR 未解析 queryString 但 URL 里有 query: 整体末尾打一个 *
    if parts.query:
        return parts.query + "*"
    return ""


def _mark_body(r):
    """请求体打 * 标记; 无请求体返回 None。"""
    mime = (r.get("bmime") or "").lower()
    params = r.get("bparams") or []
    if params:
        out = []
        for p in params:
            name = p.get("name", "")
            if not name:
                continue
            val = p.get("value", "")
            out.append(f"{quote(name, safe='')}={quote(val, safe='')}*")
        return "&".join(out) if out else None
    text = (r.get("btext") or "").strip()
    if not text:
        return None
    if "x-www-form-urlencoded" in mime:
        parts = []
        for kv in text.split("&"):
            if not kv:
                continue
            if "=" in kv:
                k, v = kv.split("=", 1)
                parts.append(f"{k}={v}*")
            else:
                parts.append(f"{kv}=*")
        if parts:
            return "&".join(parts)
    # JSON / 其他原始 body: 整体作为一个注入点
    return text + "*"


def build_request_text(r, opts) -> bytes:
    """生成带 * 注入点的 HTTP 请求报文(字节)。"""
    method = r["method"].upper()
    parts = urlsplit(r["url"])
    path = parts.path or "/"
    query = _mark_query(r)
    target = path if not query else f"{path}?{query}"

    headers = []
    has_host = False
    has_content_length = False
    for name, value in r["headers"]:
        low = name.lower()
        if low == "host":
            has_host = True
        elif low == "content-length":
            has_content_length = True
            continue  # 最后按实际 body 重算
        headers.append((name, value))

    # 凭证兜底: 抓包工具(浏览器/部分代理)常把 Cookie 从 headers 摘出、只存到
    # request.cookies 数组。若 headers 无 Cookie 且数组非空, 重建 Cookie 头, 避免漏会话凭证
    if not opts.no_cookie_header and not any(n.lower() == "cookie" for n, _ in headers):
        pairs = [f"{c.get('name')}={c.get('value')}" for c in r.get("cookies_arr") or []
                 if c.get("name") and c.get("value") is not None]
        if pairs:
            headers.append(("Cookie", "; ".join(pairs)))

    if opts.inject_headers:
        inj = {n.lower() for n in opts.inject_headers_list}
        headers = [
            (n, (v + "*") if (n.lower() in inj
                              and n.lower() not in _HEADER_INJECT_EXCLUDE and v) else v)
            for n, v in headers
        ]

    if opts.inject_cookie:
        newh = []
        for name, value in headers:
            if name.lower() == "cookie" and value:
                pairs = []
                for item in value.split(";"):
                    item = item.strip()
                    if not item:
                        continue
                    if "=" in item:
                        k, v = item.split("=", 1)
                        pairs.append(f"{k}={v}*")
                    else:
                        pairs.append(f"{item}*")
                newh.append((name, "; ".join(pairs)))
            else:
                newh.append((name, value))
        headers = newh

    if not has_host and parts.netloc:
        headers.append(("Host", parts.netloc))

    body = _mark_body(r)
    body_bytes = body.encode("utf-8", errors="replace") if body is not None else None
    if body_bytes is not None:
        headers = [(n, v) if n.lower() != "content-length"
                   else ("Content-Length", str(len(body_bytes))) for n, v in headers]
        if not has_content_length:
            headers.append(("Content-Length", str(len(body_bytes))))

    lines = [f"{method} {target} HTTP/1.1"]
    lines += [f"{n}: {v}" for n, v in headers]
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", errors="replace")
    if body_bytes:
        raw += body_bytes
    return raw


# ---------------------------------------------------------------------------
# sqlmap 调用
# ---------------------------------------------------------------------------
def build_sqlmap_cmd(reqfile, r, opts, slot):
    """根据请求报文文件构造 sqlmap 命令行(slot 为目标独立 session 目录)。"""
    cmd = [opts.sqlmap, "-r", reqfile]

    # 防止非 TTY 环境(stdin 非终端/脚本/管道)下 sqlmap 把 stdin 当成 targets 列表,
    # 导致 -r 报文文件被忽略直接退出; 终端下此选项等价于 no-op, 可安全恒加
    cmd += ["--ignore-stdin"]

    cmd += ["--answers", "keep testing the others=Y,"
            "are you really sure that you want to continue=Y"]

    cmd += ["--batch"]
    cmd += ["--level", str(opts.level)]
    cmd += ["--risk", str(opts.risk)]
    if opts.technique:
        cmd += ["--technique", opts.technique]
    if opts.smart:
        cmd += ["--smart"]
    if opts.threads:
        cmd += ["--threads", str(opts.threads)]
    if opts.timeout:
        cmd += ["--timeout", str(opts.timeout)]
    if opts.retries:
        cmd += ["--retries", str(opts.retries)]
    # URL 为 https 时强制 SSL(报文请求行为 origin-form, sqlmap 无法从 Host 推导协议)
    if urlsplit(r["url"]).scheme.lower() == "https":
        cmd += ["--force-ssl"]
    if not opts.no_flush:
        cmd += ["--flush-session"]
    if opts.outdir:
        cmd += ["--output-dir", os.path.join(opts.outdir, "sqlmap", slot)]
    if opts.verbose:
        cmd += ["-v", str(opts.verbose)]
    return cmd


def run_sqlmap(cmd, opts, log_path):
    """执行 sqlmap, 返回 (rc, output, timed_out)。"""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
    except FileNotFoundError:
        print(f"[!] 找不到 sqlmap: {opts.sqlmap}")
        sys.exit(2)

    chunks = []
    timed_out = False
    start = time.time()
    try:
        while True:
            try:
                chunk = proc.stdout.read(4096)
            except (ValueError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            with open(log_path, "a", encoding="utf-8", errors="replace") as lf:
                lf.write(chunk)
            if time.time() - start > opts.scan_timeout:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    proc.wait(timeout=10)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        pass
                break
        out = "".join(chunks)
        if not timed_out:
            rc = proc.wait()
        else:
            rc = -9
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = -9
    return rc, out, timed_out


# ---------------------------------------------------------------------------
# 结果解析(以 sqlmap 输出为准)
# ---------------------------------------------------------------------------
def extract_injection_points(text: str):
    blocks = {}
    order = []
    cur = None
    for line in text.splitlines():
        m = PARAM_RE.match(line)  # 最终汇总表: Parameter: #1* ((custom) POST)
        if m:
            param = m.group(1).strip()
            where = m.group(2).strip()
            if param not in blocks:
                blocks[param] = {"parameter": param, "where": where, "details": []}
                order.append(param)
            cur = blocks[param]
            continue
        line2 = _INJ_LINE_RE.search(line)  # 注入确认行(可能出现在汇总表之前)
        if line2:
            grp = line2.groups()
            where = grp[0] if grp[0] else "URI"
            param = grp[1]
            title = grp[2]
            if param not in blocks:
                blocks[param] = {"parameter": param, "where": where, "details": []}
                order.append(param)
            blocks[param]["details"].append(f"Title: {title}")
            continue
        if cur is None:
            continue
        lm = line.strip()
        for tag in ("Type:", "Title:", "Payload:", "Vector:", "Clause:",
                    "Statement:", "Data: ["):
            if lm.startswith(tag):
                cur["details"].append(lm)
                break
    return [blocks[p] for p in order]


def parse_output(text: str, rc: int, timed_out: bool):
    """以 sqlmap 输出为准: 出现明确的“确认注入”强标记才判定为漏洞。"""
    low = text.lower()
    injections = extract_injection_points(text)

    vuln = any(m in low for m in VULN_CONFIRM) or bool(_VULN_TYPE_RE.search(text))

    aborted = (not vuln) and (
        any(m in low for m in _ABORT_MARKERS)) and ("ending @" in text)

    error = (not vuln) and (
        timed_out
        or rc in ERROR_EXIT_CODES
        or any(m.lower() in low for m in ERROR_MARKERS)
        or aborted)

    m = INFO_DBMS_RE.search(text)
    dbms = m.group(1).strip() if m else None

    if vuln:
        status, reason = "vulnerable", None
    elif error:
        status = "error/timedout"
        reason = ("sqlmap 未执行扫描(参数被拒/提前中止)" if aborted
                  else ("扫描超时" if timed_out else "运行出错"))
    else:
        status, reason = "not_vulnerable", None

    return {
        "status": status,
        "vulnerable": vuln,
        "error": error,
        "reason": reason,
        "exit_code": rc,
        "timed_out": timed_out,
        "dbms": dbms,
        "injection_points": injections,
        "tail": text[-3000:],
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def scan_one(args):
    r, opts, outdir, log_path, slot, reqfile = args
    cmd = build_sqlmap_cmd(reqfile, r, opts, slot)
    rc, out, timed_out = run_sqlmap(cmd, opts, log_path)
    parsed = parse_output(out, rc, timed_out)
    return {
        "url": r["url"],
        "method": r["method"],
        "params": [{"name": q.get("name"), "value": q.get("value")}
                   for q in r["qs"]],
        "body_text": r["btext"],
        "request_file": reqfile,
        "command": " ".join(cmd),
        "log_file": log_path,
        **parsed,
    }


def colorize(s, color, enabled):
    if not enabled:
        return s
    codes = {"red": "31", "green": "32", "yellow": "33", "cyan": "36"}
    return f"\033[{codes[color]}m{s}\033[0m"


def main():
    ap = argparse.ArgumentParser(
        description="HAR -> 带*注入点 HTTP 报文 -> sqlmap -r 扫描 SQL 注入, 以 sqlmap 输出判定")
    ap.add_argument("har", help="HAR 文件路径")
    ap.add_argument("--sqlmap", default="sqlmap", help="sqlmap 可执行文件路径")
    ap.add_argument("--outdir", default="sqlmap_rscan",
                    help="输出目录 (默认: sqlmap_rscan)")
    ap.add_argument("--level", type=int, default=1, help="sqlmap --level (默认 1)")
    ap.add_argument("--risk", type=int, default=1, help="sqlmap --risk (默认 1)")
    ap.add_argument("--threads", type=int, default=4, help="sqlmap --threads (默认 4)")
    ap.add_argument("--parallel", type=int, default=1,
                    help="并行启动的 sqlmap 进程数 (默认 1)")
    ap.add_argument("--technique", default=None, help="sqlmap --technique，如 BEUSTQ")
    ap.add_argument("--smart", action="store_true", help="启用 sqlmap --smart")
    ap.add_argument("--timeout", type=int, default=20, help="单请求 HTTP 超时 (秒)")
    ap.add_argument("--retries", type=int, default=1, help="sqlmap --retries")
    ap.add_argument("--scan-timeout", type=int, default=900,
                    help="单个目标扫描超时 (秒, 默认 900)")
    ap.add_argument("--no-flush", action="store_true",
                    help="不清理 sqlmap session 缓存")
    ap.add_argument("--verbose", type=int, default=0, help="sqlmap 详细级别 -v")
    ap.add_argument("--inject-headers", action="store_true",
                    help="在请求头值后打 * 做请求头注入测试")
    ap.add_argument("--inject-headers-list", default=",".join(DEFAULT_INJECT_HEADERS),
                    help="参与请求头注入测试的头(逗号分隔, 默认见 DEFAULT_INJECT_HEADERS)")
    ap.add_argument("--inject-cookie", action="store_true",
                    help="在 Cookie 头的每个值后打 * 做 Cookie 注入测试")
    ap.add_argument("--no-cookie-header", action="store_true",
                    help="不从 request.cookies 数组重建 Cookie 头(headers 里已有的仍保留)")
    ap.add_argument("--no-exclude-static", action="store_true", help="不过滤静态资源")
    ap.add_argument("--no-dedupe", action="store_true", help="不去重")
    ap.add_argument("--dry-run", action="store_true", help="只生成报文不扫描")
    ap.add_argument("--limit", type=int, default=0, help="最多扫描的目标数 (0=全部)")
    opts = ap.parse_args()
    opts.inject_headers_list = [h.strip() for h in
                                opts.inject_headers_list.split(",") if h.strip()]

    if not os.path.isfile(opts.har):
        print(f"[!] HAR 文件不存在: {opts.har}")
        sys.exit(1)
    if not opts.dry_run and not shutil.which(opts.sqlmap):
        print(f"[!] 找不到 sqlmap: {opts.sqlmap}")
        sys.exit(1)

    os.makedirs(opts.outdir, exist_ok=True)

    print(f"[*] 解析 HAR: {opts.har}")
    reqs = extract_requests(opts.har, exclude_static=not opts.no_exclude_static)
    print(f"[*] 带参数的请求数: {len(reqs)}")
    raw = len(reqs)
    reqs = dedupe_requests(reqs) if not opts.no_dedupe else reqs
    print(f"[*] 去重后待扫描目标数: {len(reqs)} (过滤静态资源后)")

    with open(os.path.join(opts.outdir, "candidates.json"), "w",
              encoding="utf-8") as f:
        json.dump(reqs, f, ensure_ascii=False, indent=2)

    # 生成带 * 注入点的 HTTP 报文文件
    reqdir = os.path.join(opts.outdir, "requests")
    os.makedirs(reqdir, exist_ok=True)
    jobs = []
    for i, r in enumerate(reqs, 1):
        reqfile = os.path.join(reqdir, f"request_{i:03d}.txt")
        with open(reqfile, "wb") as f:
            f.write(build_request_text(r, opts))
        log_path = os.path.join(opts.outdir, "sqlmap", f"target_{i:03d}.log")
        slot = f"target_{i:03d}"
        jobs.append((r, opts, opts.outdir, log_path, slot, reqfile))

    if opts.dry_run:
        print(f"\n=== 带 * 注入点的 HTTP 报文 (位于 {reqdir}) ===")
        for i, (r, *_rest) in enumerate(jobs, 1):
            print(f"\n----- [{i}] [{r['method']}] {r['url']} -----")
            with open(jobs[i - 1][5], "rb") as f:
                sys.stdout.buffer.write(f.read())
            print()
        sys.exit(0)

    if opts.limit:
        jobs = jobs[: opts.limit]
        print(f"[*] 受限只扫描前 {opts.limit} 个目标")

    if not opts.no_flush:
        base = os.path.join(opts.outdir, "sqlmap")
        if os.path.isdir(base):
            shutil.rmtree(base, ignore_errors=True)
            print(f"[*] 已清理 sqlmap 缓存目录: {base}")
    os.makedirs(os.path.join(opts.outdir, "sqlmap"), exist_ok=True)
    for _, __, ___, logpath, slot, ____ in jobs:
        open(logpath, "w").close()
        os.makedirs(os.path.join(opts.outdir, "sqlmap", slot), exist_ok=True)

    color_enabled = sys.stdout.isatty()
    results = []
    started = time.time()
    with ThreadPoolExecutor(max_workers=opts.parallel) as ex:
        futs = {ex.submit(scan_one, j): j for j in jobs}
        done = 0
        for fut in as_completed(futs):
            done += 1
            res = fut.result()
            results.append(res)
            tag = {
                "vulnerable": ("[漏洞!]", "red"),
                "not_vulnerable": ("[安全]", "green"),
                "error/timedout": ("[异常]", "yellow"),
            }[res["status"]]
            txt, col = tag
            line = (f"{txt} ({done}/{len(jobs)}) [{res['method']}] {res['url']}")
            if res["status"] == "vulnerable":
                names = "; ".join(f"{p['parameter']}({p['where']})"
                                  for p in res["injection_points"]) or "?"
                line += f"  注入点: {names}  DBMS: {res['dbms'] or '?'}"
            elif res["status"] == "error/timedout":
                line += f"  exit={res['exit_code']}"
                if res.get("reason"):
                    line += f" ({res['reason']})"
            print(colorize(line, col, color_enabled), flush=True)

    results.sort(key=lambda x: x["url"])
    elapsed = time.time() - started
    report_path = os.path.join(opts.outdir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "har": opts.har,
            "total_candidates": raw,
            "scanned": len(results),
            "elapsed_seconds": round(elapsed, 1),
            "summary": {
                "vulnerable": sum(1 for r in results if r["vulnerable"]),
                "not_vulnerable": sum(1 for r in results if r["status"] == "not_vulnerable"),
                "error": sum(1 for r in results if r["status"] == "error/timedout"),
            },
            "results": results,
        }, f, ensure_ascii=False, indent=2)

    s = {}
    for r in results:
        s.setdefault(r["status"], []).append(r)
    print("\n" + "=" * 70)
    print(f"扫描完成, 耗时 {elapsed:.1f}s, 报告: {report_path}")
    print(f"  漏洞: {len(s.get('vulnerable', []))}  安全: "
          f"{len(s.get('not_vulnerable', []))}  异常: {len(s.get('error/timedout', []))}")
    if s.get("vulnerable"):
        print("\n!!! 发现潜在 SQL 注入漏洞的请求:")
        for r in s.get("vulnerable", []):
            names = "; ".join(f"{p['parameter']}({p['where']})"
                              for p in r["injection_points"]) or "?"
            print(colorize(
                f"  - [{r['method']}] {r['url']}  -> 注入点: {names} "
                f"DBMS: {r['dbms'] or '?'}", "red", color_enabled))
            print(f"    报文: {r['request_file']}")
            print(f"    日志: {r['log_file']}")
    elif s.get("error/timedout"):
        print("\n提示: 有目标扫描异常(连接/超时), 检查 sqlmap 日志与 targets 连通性。")


if __name__ == "__main__":
    main()
