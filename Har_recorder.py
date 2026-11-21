# -*- coding: utf-8 -*-
"""
Playwright 实时 HAR 录制脚本

特点：
  * 退出逻辑在命令行侧 —— 打开页面后自由操作（登录/点击/切换页面），不会退出
  * 手动退出：关闭浏览器窗口，或按 Ctrl+C（脚本内部不监听输入）
  * 实时记录 HAR —— 每 N 秒（默认 5 秒）原子刷新一次文件，录制中随时可查看
  * 所有事件回调内部异常均被捕获并打印警告，绝不向外抛出（避免中断录制）

用法示例:
  python har_recorder.py --har out.har
  python har_recorder.py --login --har out.har
  python har_recorder.py --har out.har --UA "Mozilla/5.0 ..." --proxy http://127.0.0.1:8888
  python har_recorder.py --login --har out.har --Ext ./my-extension

依赖:
  pip install playwright && playwright install chromium
"""

import argparse
import asyncio
import base64
import gc
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl

try:
    from playwright.async_api import async_playwright
except ImportError:
    sys.exit("未安装 playwright，请先执行: pip install playwright && playwright install chromium")


def log_err(tag: str, exc: BaseException) -> None:
    """统一打印事件回调内部异常（只警告，不中断录制）"""
    print(f"[警告] {tag}: {type(exc).__name__}: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# 实时 HAR 记录器
# --------------------------------------------------------------------------- #
class HarRecorder:
    def __init__(self, har_path: str, flush_interval: float = 5.0,
                 max_body_size: int = 10 * 1024 * 1024, capture_content: bool = True):
        self.path = Path(har_path).resolve()
        self.flush_interval = flush_interval
        self.max_body_size = max_body_size
        self.capture_content = capture_content
        self.entries = []
        self._pending = {}
        self._flush_task = None
        self._flush_lock = asyncio.Lock()
        self._closed = False
        self._warned = 0

    def attach(self, context) -> None:
        context.on("request", self._on_request)
        context.on("response", self._on_response)
        self._flush_task = asyncio.create_task(self._periodic_flush())

    # ---- 事件回调（全部防御式包裹，绝不向外抛异常） ----
    def _on_request(self, request):
        try:
            if request.url.startswith(("data:", "blob:")):
                return
            self._pending[id(request)] = {"request": request, "started": time.time()}
        except BaseException as e:
            self._warn(exc := e)

    async def _on_response(self, response):
        # 关键：先从 _pending 移除该请求（拿 started 计时；更避免 close() 把它当
        # “无响应”重复物化 —— 这就是之前 HAR“后半段全部没有 Resp”的根因）
        try:
            request = response.request
            meta = self._pending.pop(id(request), None)
        except BaseException as e:
            self._warn(e)
            return

        # 立即用“请求 + 响应头/状态”构建并马上入列表（不等正文），
        # 正文由 _fill_body 后台异步回填：正文慢/流式/挂起也不会阻塞本条响应落盘。
        entry = None
        try:
            entry = await self._build_entry(request, response, meta, fetch_body=False)
        except BaseException as e:
            self._warn(e)
        if entry is not None:
            self.entries.append(entry)
            if self.capture_content and response is not None:
                asyncio.create_task(self._fill_body(entry, response))

    def _warn(self, exc: BaseException) -> None:
        # 同类异常只提示一次，避免疯狂刷屏
        if self._warned < 20:
            self._warned += 1
            log_err("HAR记录器", exc)

    # ---- 周期刷新（实时写文件） ----
    async def _periodic_flush(self):
        try:
            while not self._closed:
                await asyncio.sleep(self.flush_interval)
                await self.flush()
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self._warn(e)  # 刷新出错只警告，不中断

    async def flush(self, final: bool = False):
        if self._flush_lock.locked():
            return
        async with self._flush_lock:
            if self._closed and not final:
                return
            har = {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "realtime-playwright-har", "version": "1.1"},
                    "pages": [],
                    "entries": list(self.entries),
                }
            }
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(har, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.path)

    # ---- 条目构建 ----
    async def _build_entry(self, request, response, meta, fetch_body: bool = True):
        started = meta["started"] if meta else time.time()
        started_dt = datetime.fromtimestamp(started, tz=timezone.utc).isoformat()\
            .replace("+00:00", "Z")
        total_ms = max((time.time() - started) * 1000.0, 0.0)

        # request 部分
        # 注意：request.headers 会故意省略 Cookie 等安全相关请求头（Playwright 文档说明），
        # 必须用 headers_array()/all_headers() 拿浏览器实际发出的完整请求头，失败再回退。
        req_headers = []
        try:
            req_headers = [{"name": h["name"], "value": h["value"]}
                           for h in await request.headers_array()]
        except BaseException:
            pass
        if not req_headers:
            try:
                req_headers = [{"name": k, "value": v} for k, v in request.headers.items()]
            except BaseException:
                req_headers = []
        req_header_map = {h["name"].lower(): h["value"] for h in req_headers}
        query = [{"name": k, "value": v}
                 for k, v in parse_qsl(urlsplit(request.url).query, keep_blank_values=True)]
        # HAR request.cookies：从 Cookie 头解析（仅完善字段，不影响请求头）
        cookies = []
        try:
            cookie_hdr = req_header_map.get("cookie")
            if cookie_hdr:
                for part in cookie_hdr.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookies.append({"name": k.strip(), "value": v.strip()})
        except BaseException:
            pass
        post, req_body_size = None, 0
        try:
            if request.post_data:
                req_body_size = len(request.post_data)
                post = {
                    "mimeType": (req_header_map.get("content-type")
                                 or "application/octet-stream"),
                    "text": request.post_data,
                }
        except BaseException:
            pass

        # response 部分
        status, status_text = 0, ""
        resp_headers, content_type = [], ""
        body_size, body_b64 = -1, None
        server_ip = ""
        if response is not None:
            try:
                status = response.status
                status_text = response.status_text or ""
            except BaseException:
                pass
            # 同请求头：response.headers 也会省略 Set-Cookie 等安全相关头，
            # 用 response.headers_array() 取完整响应头，失败再回退。
            resp_headers = []
            try:
                resp_headers = [{"name": h["name"], "value": h["value"]}
                                for h in await response.headers_array()]
            except BaseException:
                pass
            if not resp_headers:
                try:
                    resp_headers = [{"name": k, "value": v}
                                    for k, v in response.headers.items()]
                except BaseException:
                    resp_headers = []
            for h in resp_headers:
                if h["name"].lower() == "content-type":
                    content_type = h["value"]
            if self.capture_content and fetch_body:
                try:
                    body = await response.body()
                    body_size = len(body)
                    if body_size <= self.max_body_size:
                        body_b64 = base64.b64encode(body).decode("ascii")
                except BaseException:
                    body_size = -1
            try:
                sa = response.server_addr
                if sa:
                    server_ip = sa.get("ipAddress", "")
            except BaseException:
                pass

        content = {"size": body_size}
        if content_type:
            content["mimeType"] = content_type
        if body_b64 is not None:
            content["text"] = body_b64
            content["encoding"] = "base64"

        entry = {
            "startedDateTime": started_dt,
            "time": total_ms,
            "request": {
                "method": request.method,
                "url": request.url,
                "httpVersion": "HTTP/1.1",
                "cookies": cookies,
                "headers": req_headers,
                "queryString": query,
                "headersSize": -1,
                "bodySize": req_body_size,
                **({"postData": post} if post else {}),
            },
            "response": {
                "status": status,
                "statusText": status_text,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": resp_headers,
                "content": content,
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": body_size,
            },
            "cache": {},
            "timings": self._build_timings(request.timing),
            "serverIPAddress": server_ip,
            "_initiator": "unknown",
        }
        try:
            entry["_initiator"] = request.resource_type or "unknown"
        except BaseException:
            pass
        return entry

    @staticmethod
    def _build_timings(t):
        def dur(s, e):
            return max(e - s, 0) if (s != -1 and e != -1 and e >= s) else -1
        try:
            dns = dur(t.get("domainLookupStart", -1), t.get("domainLookupEnd", -1))
            connect = dur(t.get("connectStart", -1), t.get("connectEnd", -1))
            ssl = dur(t.get("secureConnectionStart", -1), t.get("connectEnd", -1))
            wait = dur(t.get("requestStart", -1), t.get("responseStart", -1))
        except BaseException:
            dns = connect = ssl = wait = -1
        return {"blocked": -1, "dns": dns, "connect": connect,
                "send": 0, "wait": wait, "receive": 0, "ssl": ssl}

    async def _fill_body(self, entry: dict, response) -> None:
        """后台异步拉取响应正文并回填到已入列的条目，完成后立即刷新落盘。"""
        try:
            body = await response.body()
            base = entry["response"]["content"]
            base["size"] = len(body)
            if len(body) <= self.max_body_size:
                base["text"] = base64.b64encode(body).decode("ascii")
                base["encoding"] = "base64"
        except asyncio.CancelledError:
            pass
        except BaseException as e:
            self._warn(e)
            return
        try:
            await self.flush()
        except BaseException as e:
            self._warn(e)

    async def close(self):
        self._closed = True
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except Exception:
                pass
        # 补采无响应/被中断的请求
        for meta in list(self._pending.values()):
            try:
                entry = await self._build_entry(meta["request"], None, meta)
                if entry:
                    self.entries.append(entry)
            except BaseException as e:
                self._warn(e)
        self._pending.clear()
        try:
            await self.flush(final=True)
        except BaseException as e:
            log_err("HAR最终落盘", e)
        print(f"[信息] 实时 HAR 已写入: {self.path} | 共 {len(self.entries)} 条记录")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(
        description="Playwright 实时 HAR 录制脚本（退出逻辑在命令行侧，打开页面后自由操作，手动关窗或 Ctrl+C 结束）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python har_recorder.py --har out.har\n"
            "  python har_recorder.py --login --har out.har --Ext ./my-extension\n"
            "  python har_recorder.py --har out.har --UA 'Mozilla/5.0 ...' --proxy http://127.0.0.1:8888\n"
            "\n"
            "退出方式（命令行手动操作，脚本不停监听输入）:\n"
            "  1. 打开页面后自由操作（登录/点击/切换页面/标签），不会退出\n"
            "  2. 完成后：关闭浏览器窗口，或在终端按 Ctrl+C 结束\n"
            "注意：切换页面/标签页不会结束录制。HAR 每 --flush 秒实时刷新。\n"
        ),
    )
    p.add_argument("--login", action="store_true",
                   help="打开浏览器窗口（有头）以便登录；完成后关闭浏览器或 Ctrl+C 结束")
    p.add_argument("--har", type=str, default=None,
                   help="输出 HAR 文件路径（例如 out.har）；实时刷新")
    p.add_argument("--UA", type=str, default=None,
                   help="设置 User-Agent 字符串")
    p.add_argument("--Ext", type=str, default=None,
                   help="加载 Chrome 插件目录（须含 manifest.json；强制有头 Chromium）")
    p.add_argument("--proxy", type=str, default=None,
                   help="设置代理服务器，例如 http://127.0.0.1:8888 或 socks5://127.0.0.1:1080")
    p.add_argument("--url", type=str, default="https://www.baidu.com",
                   help="启动后打开的初始地址（默认百度）")
    p.add_argument("--flush", type=float, default=5.0,
                   help="HAR 实时刷新间隔秒数（默认 5）")
    p.add_argument("--no-content", action="store_true",
                   help="HAR 不记录响应体内容（减小文件体积）")
    p.add_argument("--headless", action="store_true",
                   help="无头模式（加载插件时无法使用，会被强制有头）")
    return p.parse_args()


async def main():
    args = parse_args()

    # 安装事件循环全局异常处理器：只打印，绝不因回调异常终止录制
    loop = asyncio.get_running_loop()

    def _exception_handler(loop_, ctx):
        exc = ctx.get("exception")
        msg = ctx.get("message", "") or ""
        # 已知良性场景：Ctrl+C 打断 driver 读取时的关机噪音，直接忽略不打印
        if "Connection closed while reading from the driver" in msg or (
                exc is not None and "Connection closed while reading from the driver"
                in str(exc)):
            return
        print(f"[警告] 异步任务异常(已忽略): {type(exc).__name__ if exc else ''} {msg}",
              file=sys.stderr)
        if exc is not None:
            print(f"        详情: {exc}", file=sys.stderr)
    loop.set_exception_handler(_exception_handler)

    # ---------- 参数检查 ----------
    ext_path = Path(args.Ext).resolve() if args.Ext else None
    if ext_path:
        if not ext_path.is_dir():
            sys.exit(f"[错误] 插件目录不存在: {ext_path}")
        if not (ext_path / "manifest.json").is_file():
            sys.exit(f"[错误] 插件目录中未找到 manifest.json: {ext_path}")
        args.headless = False
        print(f"[信息] 插件目录: {ext_path}（强制有头 Chromium）")

    if args.har and not str(args.har).lower().endswith(".har"):
        args.har = str(args.har) + ".har"

    print(f"[信息] login={args.login} | har={args.har} | UA={'是' if args.UA else '否'} | "
          f"proxy={args.proxy} | Ext={ext_path} | flush={args.flush}s | headless={args.headless}")

    # ---------- 持久化上下文（保存登录态 + 代理 + UA + 插件） ----------
    user_data_dir = os.path.join(tempfile.gettempdir(), "pw_har_profile")
    os.makedirs(user_data_dir, exist_ok=True)

    launch_options = {"user_data_dir": user_data_dir, "headless": args.headless, "args": []}
    if args.UA:
        launch_options["user_agent"] = args.UA
    if args.proxy:
        launch_options["proxy"] = {"server": args.proxy}
    if ext_path:
        launch_options["channel"] = "chromium"
        launch_options["args"] += [
            f"--disable-extensions-except={ext_path}",
            f"--load-extension={ext_path}",
        ]

    async with async_playwright() as pw:
        context = await pw.chromium.launch_persistent_context(**launch_options)

        recorder = None
        if args.har:
            recorder = HarRecorder(args.har, flush_interval=args.flush,
                                   capture_content=not args.no_content)
            recorder.attach(context)

        page = context.pages[0] if context.pages else await context.new_page()

        if ext_path:
            try:
                await page.goto(args.url, timeout=15000)
            except BaseException:
                pass
            print(f"[信息] 已加载 service worker 数量: {len(context.service_workers)}")

        try:
            await page.goto(args.url)
        except BaseException as e:
            print(f"[警告] 打开初始地址失败: {type(e).__name__}: {e}")

        # ---------- 开启录制后等待手动退出：关浏览器 或 Ctrl+C ----------
        print("[信息] 正在录制中... 页面内操作（登录/点击/切换页面/标签）不会退出录制；")
        print("       完成后请手动关闭浏览器窗口，或在终端按 Ctrl+C 结束（脚本不监听输入）。")

        try:
            # 注意：必须传 timeout=0（NO_TIMEOUT），而非 None——
            # Playwright 中 timeout=None 会落到默认值 30000ms，30 秒后切换页面会误判退出!
            await context.wait_for_event("close", timeout=0)  # 只会因整个浏览器关闭而触发
        except asyncio.CancelledError:
            print("[信息] 检测到 Ctrl+C，正在收尾 ...")
        except BaseException as e:
            print(f"[警告] 等待退出时出现异常({type(e).__name__}: {e})，仍将收尾并写出 HAR。")

        # ---------- 收尾 ----------
        print("[信息] 正在关闭浏览器并写出 HAR ...")
        try:
            await context.close()
        except BaseException:
            pass
        if recorder:
            await recorder.close()

    # 在事件循环仍存活时回收 Playwright 驱动子进程的 transport，
    # 避免其在循环关闭后于解释器退出时触发 “Event loop is closed” 的 __del__ 噪音
    gc.collect()

    print("[完成] 录制结束。")
    return 0


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[信息] 已通过 Ctrl+C 结束")
