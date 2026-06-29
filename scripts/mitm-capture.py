"""
mitmdump addon — capture WeChat mini-program requests to JSONL.

Output format (one JSON per line, compatible with sign-crack.mjs):
  {"url":"...","method":"POST","req_body":"k=v&sign=xxx","res_body":"...","ts":1234567890}

Usage (managed by MCP tools, or manual):
  mitmdump -s scripts/mitm-capture.py --set capture_dir=/path/to/out [--set url_filter=keyword]

Environment / options:
  capture_dir  — directory for JSONL output (default: captures/)
  url_filter   — only capture URLs containing this substring (optional)
"""
import json
import os
import time
from mitmproxy import http, ctx


class MpCapture:
    def __init__(self):
        self.out_dir = None
        self.out_file = None
        self.fh = None
        self.count = 0

    def load(self, loader):
        loader.add_option("capture_dir", str, "", "Output directory for JSONL capture files")
        loader.add_option("url_filter", str, "", "Only capture URLs containing this substring")

    def configure(self, updated):
        if "capture_dir" in updated:
            d = ctx.options.capture_dir
            if not d:
                d = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")
            os.makedirs(d, exist_ok=True)
            self.out_dir = d
            fname = f"capture-{int(time.time())}.jsonl"
            self.out_file = os.path.join(d, fname)
            self.fh = open(self.out_file, "a", encoding="utf-8")
            ctx.log.info(f"[mp-capture] writing to {self.out_file}")

    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        url_filter = ctx.options.url_filter
        if url_filter and url_filter not in url:
            return

        req_body = flow.request.get_text() or ""
        if not req_body and flow.request.urlencoded_form:
            req_body = "&".join(f"{k}={v}" for k, v in flow.request.urlencoded_form.items())

        content_type = flow.request.headers.get("content-type", "")
        if "json" in content_type and req_body:
            try:
                obj = json.loads(req_body)
                req_body = "&".join(f"{k}={v}" for k, v in _flatten(obj))
            except (json.JSONDecodeError, TypeError):
                pass

        res_body = ""
        try:
            res_body = flow.response.get_text() or ""
        except Exception:
            pass

        entry = {
            "url": url,
            "method": flow.request.method,
            "req_body": req_body,
            "res_body": res_body[:4096],
            "req_headers": dict(flow.request.headers),
            "status": flow.response.status_code,
            "ts": int(time.time()),
        }

        if self.fh:
            self.fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.fh.flush()
            self.count += 1

    def done(self):
        if self.fh:
            self.fh.close()
            ctx.log.info(f"[mp-capture] captured {self.count} requests → {self.out_file}")


def _flatten(obj, prefix=""):
    """Flatten nested JSON to key=value pairs for sign-crack compatibility."""
    items = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, (dict, list)):
                items.extend(_flatten(v, new_key))
            else:
                items.append((new_key, str(v) if v is not None else ""))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            items.extend(_flatten(v, f"{prefix}[{i}]"))
    return items


addons = [MpCapture()]
