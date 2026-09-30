#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
恶意代码样本报告批量查询工具

对哈希清单里的每一个 SHA256 逐个查询，自动下载并保存：
  1. VirusTotal 的完整 JSON 报告（API v3，用 x-apikey 头鉴权）
  2. 国家计算机病毒协同分析平台的报告（开放接口，apikey 放在请求体里）
最后把关键字段汇总成 summary.csv。

典型用法：
    python query_reports.py --hashes hashes.txt                 # 两个平台都查
    python query_reports.py --only vt                           # 只查 VirusTotal
    python query_reports.py --hash <某个sha256>                 # 只查一个哈希
    python query_reports.py --hashes hashes.txt --summary-only   # 只根据已有报告重算汇总表

API key 的提供方式（优先级从高到低）：
    命令行 --vt-key / --cverc-key  >  环境变量 VT_API_KEY / CVERC_API_KEY  >  config.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# 计算 SHA256（--list-only / --samples）只用标准库，不需要 requests。
# 隔离虚拟机里往往没装第三方包，所以这里做成可选导入：只算哈希照样能跑。
try:
    import requests
except ImportError:
    requests = None

# 让 Windows 控制台也能正常打印中文和符号
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

VT_BASE = "https://www.virustotal.com/api/v3"

CVERC_BASE = "https://virus.cverc.org.cn/api"

# 协同分析平台的开放接口。路径取自平台自身的接口文档页
# （https://virus.cverc.org.cn/#/api/info 系列页面）。
# basic   —— 基本信息：文件名、格式、大小、家族名、可信度、检出比
# static  —— 静态信息：PE 头、节表、导入表、模糊哈希等（对应作业里的"PE 文件头/函数信息"）
# engines —— 多引擎检出结果
# dynamic —— 动态行为报告
# full    —— 综合报告（内容最多，也最慢）
CVERC_ENDPOINTS = {
    "basic": "/v1/file/report",
    "static": "/v1/file/staticinfo/report",
    "engines": "/v1/file/multiscan/report",
    "dynamic": "/v1/file/dynamics/report",
    "full": "/v1/file/full/report",
}

# full 综合报告的参数名和其它接口不一样：它要求 hashes（列表），不是 hash
CVERC_LIST_PARAM = {"full"}

# 平台官方文档（https://virus.cverc.org.cn/#/api/code_info）给出的响应码对照表
CVERC_CODES = {
    0: "成功",
    2: "未检索到数据",
    3: "任务进行中",
    4: "文件等待扫描",
    5: "文件扫描超时/无结果",
    -1: "权限受限，或依赖的外部服务不可用",
    -2: "请求无效",
    -3: "请求参数错误",
    -4: "超出系统限制",
    -5: "系统错误",
}

# 多引擎报告里表示"这家引擎没扫这个样本"的占位值，统计检出数时要排除掉。
# 文档示例里未检出的引擎给的是 Undetected，实测未扫描的给的是 UnScanned。
CVERC_NOT_DETECTED = {"", "none", "undetected", "unscanned", "unknown"}


def cverc_payload(api_key: str, name: str, sha256: str) -> dict:
    if name in CVERC_LIST_PARAM:
        return {"apikey": api_key, "hash": sha256, "hashes": [sha256]}
    return {"apikey": api_key, "hash": sha256}


def cverc_error(body: dict) -> tuple:
    """协同平台有两套响应结构：报告接口用 code/msg，上传接口用 error_code/message。
    统一取出来，返回 (错误码, 提示文字)。"""
    code = dig(body, "code")
    if code is None:
        code = dig(body, "error_code")
    msg = dig(body, "msg", default="") or dig(body, "message", default="") or ""
    return code, str(msg)

# 默认只取前三个：作业要求的"检测结果 + PE 头信息 + 函数信息"都在里面
CVERC_DEFAULT = ("basic", "static", "engines")

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) batch-report-fetcher/1.0"

# VirusTotal 免费账号的限制是每分钟 4 次、每天 500 次。
# 16 秒的间隔正好压在每分钟 3.75 次，留一点余量。付费账号可以用 --vt-interval 调小。
VT_DEFAULT_INTERVAL = 16.0


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def ts_to_str(epoch) -> str:
    """VirusTotal 的时间戳是 Unix 秒，转成可读的本地时间字符串。"""
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return ""


def dig(obj, *keys, default=None):
    """安全地取多层嵌套字段，中间任何一层缺失都返回 default。"""
    cur = obj
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, list) and isinstance(k, int) and -len(cur) <= k < len(cur):
            cur = cur[k]
        else:
            return default
    return default if cur is None else cur


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    """分块读取算 SHA256，避免把大文件整个读进内存。只读，不会执行文件。"""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# 哈希清单
# --------------------------------------------------------------------------- #

def load_hashes(path: Path) -> list[str]:
    """读哈希清单，一行一个 SHA256；支持 # 开头的注释和行尾注释，自动去重。"""
    hashes, seen = [], set()
    for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # 兼容"sha256,文件名"这种带附注的写法，也兼容从表格里粘出来的制表符分隔
        token = line.replace(",", " ").replace("\t", " ").split()[0]
        token = token.strip().lower()
        if len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
            log(f"跳过无法识别的行：{raw.strip()[:60]}")
            continue
        if token not in seen:
            seen.add(token)
            hashes.append(token)
    return hashes


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #

class VirusTotal:
    def __init__(self, api_key: str, out_dir: Path, interval: float, retries: int = 5):
        self.api_key = api_key
        self.out_dir = out_dir
        self.interval = interval
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json",
                                     "User-Agent": USER_AGENT})
        self._lock = threading.Lock()
        self._last_call = 0.0

    def _wait_turn(self) -> None:
        """按最小间隔串行化请求，避免触发 429。"""
        with self._lock:
            gap = time.monotonic() - self._last_call
            if gap < self.interval:
                time.sleep(self.interval - gap)
            self._last_call = time.monotonic()

    def fetch(self, sha256: str) -> dict:
        """取一个哈希的报告，返回 {"http": 状态码, "body": 原始 JSON}。"""
        url = f"{VT_BASE}/files/{sha256}"
        delay = 20.0
        for attempt in range(1, self.retries + 1):
            self._wait_turn()
            try:
                resp = self.session.get(url, timeout=60)
            except requests.RequestException as exc:
                log(f"  网络错误（第 {attempt} 次）：{exc}")
                time.sleep(delay)
                delay = min(delay * 2, 300)
                continue

            if resp.status_code == 200:
                return {"http": 200, "body": resp.json()}

            if resp.status_code == 404:
                # 该样本不在 VT 库里，把错误体照样存下来，方便在报告里说明"未收录"
                return {"http": 404, "body": _safe_json(resp)}

            if resp.status_code == 401:
                raise RuntimeError("VirusTotal 拒绝了 API key（401），请检查 key 是否正确。")

            if resp.status_code == 429:
                wait = float(resp.headers.get("Retry-After") or delay)
                log(f"  触发限流 429，等待 {wait:.0f} 秒后重试（第 {attempt}/{self.retries} 次）")
                time.sleep(wait)
                delay = min(delay * 2, 300)
                continue

            log(f"  HTTP {resp.status_code}，{delay:.0f} 秒后重试（第 {attempt}/{self.retries} 次）")
            time.sleep(delay)
            delay = min(delay * 2, 300)

        return {"http": 0, "body": {"error": {"code": "RetriesExhausted",
                                             "message": "重试次数用尽仍未取到报告"}}}

    def upload(self, path: Path) -> dict:
        """把样本提交给 VirusTotal 分析（直传上限 32MB）。
        上传成功后 VT 会新建一个分析任务，报告要过一会儿才能查到。"""
        self._wait_turn()
        try:
            with path.open("rb") as fh:
                resp = self.session.post(
                    f"{VT_BASE}/files",
                    files={"file": (path.name, fh, "application/octet-stream")},
                    timeout=600,
                )
        except (requests.RequestException, OSError) as exc:
            return {"http": 0, "body": {"error": str(exc)}}
        return {"http": resp.status_code, "body": _safe_json(resp)}


# --------------------------------------------------------------------------- #
# 国家计算机病毒协同分析平台
# --------------------------------------------------------------------------- #

class Cverc:
    def __init__(self, api_key: str, out_dir: Path, endpoints, retries: int = 3, interval: float = 1.0):
        self.api_key = api_key
        self.out_dir = out_dir
        self.endpoints = list(endpoints)
        self.retries = retries
        self.interval = interval
        self.disabled = {}  # 接口名 -> 不可用原因（比如账号没开这个接口的权限）
        self.session = requests.Session()
        # 这里不设默认的 Content-Type：报告接口用 json=，上传接口用 files=，
        # requests 会各自带上正确的类型；写死成 application/json 会让 multipart 上传失败。
        self.session.headers.update({
            "accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-Tool": "Antiy-ui-main",
            "x-app-version": "v1.0",
        })

    def upload(self, path: Path) -> dict:
        """把样本提交给协同分析平台扫描。

        用的是平台的 /scan/file 接口，上传后平台会排队分析，
        报告同样要过一会儿才能查到（那时重跑一次程序就能取到）。
        """
        url = CVERC_BASE + "/scan/file"
        data = {
            "apikey": self.api_key,
            "filepath": str(path),
            "filename": path.name,
            "report_ip": "127.0.0.1",
            "source": "batch-reports",
            "rescan": "false",
        }
        try:
            with path.open("rb") as fh:
                resp = self.session.post(
                    url, data=data,
                    files={"file": (path.name, fh, "application/octet-stream")},
                    timeout=600,
                )
        except (requests.RequestException, OSError) as exc:
            return {"http": 0, "body": {"error": str(exc)}, "url": url}
        body = _safe_json(resp)
        _, msg = cverc_error(body)
        if "密钥" in msg:
            raise RuntimeError(f"协同分析平台拒绝了 apikey：{msg}")
        return {"http": resp.status_code, "body": body, "url": url}

    def fetch(self, sha256: str) -> dict:
        """逐个接口取报告，返回 {接口名: {"http": 状态码, "body": 原始 JSON}}。"""
        results = {}
        for name in self.endpoints:
            if name in self.disabled:
                continue
            path = CVERC_ENDPOINTS[name]
            url = CVERC_BASE + path
            payload = cverc_payload(self.api_key, name, sha256)
            for attempt in range(1, self.retries + 1):
                try:
                    resp = self.session.post(url, json=payload, timeout=60)
                except requests.RequestException as exc:
                    log(f"  {name} 网络错误（第 {attempt}/{self.retries} 次）：{exc}")
                    time.sleep(3 * attempt)
                    continue

                body = _safe_json(resp)
                # 不管成功失败都先留一份原始响应，方便事后查平台到底回了什么
                results[name] = {"http": resp.status_code, "body": body, "url": url}

                if resp.status_code == 200:
                    break

                code, msg = cverc_error(body)
                if "密钥" in msg:
                    raise RuntimeError(f"协同分析平台拒绝了 apikey：{msg}")
                if code == -1 or "权限" in msg or "未开通" in msg:
                    # 账号没开这个接口的权限，重试多少次都一样，直接禁用掉省时间
                    self.disabled[name] = msg or "权限受限"
                    log(f"  {name}：{msg or '权限受限'}，后续样本将跳过该接口")
                    break
                if resp.status_code < 500:
                    # 业务层已经给出明确答复（例如未收录），不必重试
                    break
                log(f"  {name} 返回 HTTP {resp.status_code}，{3 * attempt} 秒后重试")
                time.sleep(3 * attempt)
            if name not in results:
                results[name] = {"http": 0, "body": {"error": "重试次数用尽"}, "url": url}
            if self.interval:
                time.sleep(self.interval)
        return results


def _safe_json(resp) -> dict:
    """接口返回的不一定是 JSON（可能是网关的 HTML 错误页），这里兜一下底。"""
    try:
        return resp.json()
    except ValueError:
        return {"__raw__": resp.text[:2000], "__status__": resp.status_code}


# --------------------------------------------------------------------------- #
# 汇总
# --------------------------------------------------------------------------- #

def _top_threat(items) -> str:
    """popular_threat_category / popular_threat_name 是 [{count, value}, ...]，取占比最高的那个。"""
    if isinstance(items, list) and items:
        best = max(items, key=lambda x: dig(x, "count", default=0) or 0)
        return str(dig(best, "value", default="") or "")
    return ""


def vt_row(rec: dict) -> dict:
    """从 VirusTotal 报告里抽出汇总表要用的字段。"""
    body = rec.get("body") or {}
    attrs = dig(body, "data", "attributes", default={}) or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(stats.values()) if stats else 0

    # 家族标签藏在 popular_threat_classification 里，不在 attributes 顶层
    threats = attrs.get("popular_threat_classification") or {}
    label = (dig(threats, "suggested_threat_label", default="")
             or attrs.get("suggested_threat_label", "") or "")

    return {
        "vt_http": rec.get("http", ""),
        "vt_result": ("未收录" if rec.get("http") == 404
                      else ("查询失败" if rec.get("http") != 200 else "已收录")),
        "vt_detection": f"{stats.get('malicious', 0)}/{total}" if stats else "",
        "vt_threat_label": label,
        "vt_threat_category": _top_threat(threats.get("popular_threat_category")),
        "vt_threat_name": _top_threat(threats.get("popular_threat_name")),
        "vt_name": attrs.get("meaningful_name", "") or "",
        "vt_type": attrs.get("type_description", "") or "",
        "vt_size": attrs.get("size", ""),
        "vt_md5": attrs.get("md5", "") or "",
        "vt_sha1": attrs.get("sha1", "") or "",
        "vt_ssdeep": attrs.get("ssdeep", "") or "",
        "vt_tlsh": attrs.get("tlsh", "") or "",
        "vt_first_seen": ts_to_str(attrs.get("first_submission_date")),
        "vt_last_analysis": ts_to_str(attrs.get("last_analysis_date")),
        "vt_times_submitted": attrs.get("times_submitted", ""),
        "vt_tags": ",".join(attrs.get("tags") or []),
    }


def cverc_row(rec: dict) -> dict:
    """从协同分析平台的报告里抽出汇总表要用的字段。"""
    basic_body = dig(rec, "basic", "body", default={}) or {}
    basic = dig(basic_body, "data", default={}) or {}
    code = dig(basic_body, "code")
    engines = dig(rec, "engines", "body", "data", default=None)
    static = dig(rec, "static", "body", "data", default={}) or {}
    general = static.get("general_info") if isinstance(static, dict) else None

    # 检出比优先用平台自己算好的计数（basic 接口的 positives_multiscan/total_multiscan），
    # 没有再从多引擎列表里数，数的时候要排掉 UnScanned/Undetected 这些占位值。
    positives, total = dig(basic, "positives_multiscan"), dig(basic, "total_multiscan")
    if not total and isinstance(engines, list):
        total = len(engines)
        positives = sum(
            1 for e in engines
            if str(dig(e, "malname", default="")).strip().lower() not in CVERC_NOT_DETECTED
        )
    detection = f"{positives}/{total}" if total else ""

    # 报告里没记到 basic，但接口确实问过，就把平台给的原因写清楚
    engines_have_data = isinstance(engines, list) and len(engines) > 0
    result = ""
    if code == 0:
        # 注意：样本不在平台库里时，平台返回的是 code=0 加一个空的 data，
        # 所以"请求成功"不等于"已收录"，要再看 data 里有没有内容。
        result = "已收录" if (basic or engines_have_data) else "未收录"
    elif code is not None:
        # basic 这条路失败了（额度用尽、权限不足等），但只要多引擎报告里有内容就仍算已收录
        result = ("已收录" if engines_have_data
                  else str(dig(basic_body, "msg", default="")
                           or CVERC_CODES.get(code, f"code {code}")))
    elif engines_have_data:
        result = "已收录"
    elif "basic" in rec or "engines" in rec:
        # 两个接口都问了但都没有内容，就是平台没收录这个样本
        result = "未收录"

    return {
        "cverc_result": result,
        "cverc_detection": detection,
        "cverc_malware_name": dig(basic, "malware_name", default="") or "",
        "cverc_format": dig(basic, "format", default="") or "",
        "cverc_name": dig(basic, "file_name", default="") or "",
        "cverc_size": dig(basic, "size", default=""),
        "cverc_trust": dig(basic, "trust", default="") or "",
        "cverc_pack": dig(general, "pack_name", default="") if general else "",
        "cverc_compiler": dig(general, "compiler_name", default="") if general else "",
    }


COLUMNS = [
    "sha256", "vt_result", "vt_detection", "vt_threat_label", "vt_threat_category",
    "vt_threat_name", "vt_name", "vt_type",
    "vt_size", "vt_md5", "vt_sha1", "vt_ssdeep", "vt_tlsh", "vt_first_seen",
    "vt_last_analysis", "vt_times_submitted", "vt_tags",
    "cverc_result", "cverc_detection", "cverc_malware_name", "cverc_format",
    "cverc_name", "cverc_size", "cverc_trust", "cverc_pack", "cverc_compiler",
]


def load_records(vt_dir: Path, cverc_dir: Path) -> list[dict]:
    """把已经落盘的报告读成一个列表，汇总表和检测报告都用它。"""
    records = []
    if not vt_dir.exists():
        return records
    for vt_file in sorted(vt_dir.glob("*.json")):
        if vt_file.name.endswith(".upload.json"):
            continue  # 上传回执，不是检测报告
        sha256 = vt_file.stem
        row = {"sha256": sha256}
        try:
            body = json.loads(vt_file.read_text("utf-8"))
        except (ValueError, OSError):
            row["vt_result"] = "报告解析失败"
            records.append(row)
            continue
        # 未收录时存下来的是 VT 的错误 JSON。要区分两类错误：
        # NotFoundError 是真的没收录；其它错误（例如重试耗尽）是查询失败，不能混为一谈。
        err_code = dig(body, "error", "code")
        if not err_code:
            http = 200
        else:
            http = 404 if err_code == "NotFoundError" else 0
        row.update(vt_row({"http": http, "body": body}))

        cverc_rec = {}
        for name in CVERC_ENDPOINTS:
            f = cverc_dir / f"{sha256}.{name}.json"
            if f.exists():
                try:
                    cverc_rec[name] = {"http": 200, "body": json.loads(f.read_text("utf-8"))}
                except (ValueError, OSError):
                    pass
        if cverc_rec:
            row.update(cverc_row(cverc_rec))
        records.append(row)
    return records


def write_summary(records: list[dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for row in records:
            writer.writerow({c: row.get(c, "") for c in COLUMNS})
    log(f"汇总表已写出：{out_csv}（共 {len(records)} 条）")


def _cell(text) -> str:
    """表格单元格里的竖线会破坏 Markdown 表格，转义掉；空值显示为短横线。"""
    return str(text).replace("|", "\\|").strip() or "-"


def _positives(detection) -> int:
    """把 "12/71" 这样的检出比拆出分子；拆不出来返回 -1 表示没有检出数据。"""
    try:
        return int(str(detection).split("/")[0])
    except (ValueError, IndexError, TypeError):
        return -1


def _ratio(detection) -> float:
    """把 "12/71" 换算成检出比例；拆不出来返回 -1。"""
    parts = str(detection).split("/")
    if len(parts) != 2:
        return -1.0
    try:
        pos, tot = int(parts[0]), int(parts[1])
    except ValueError:
        return -1.0
    return pos / tot if tot else -1.0


def _counter(records: list[dict], key: str) -> dict:
    counts = {}
    for r in records:
        value = (r.get(key) or "").strip()
        if value:
            counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _family(r: dict) -> str:
    """样本的家族标签。

    VT 只给知名样本算聚合标签（suggested_threat_label），大量样本没有；
    这种情况退化成它的类别（ransomware / trojan 这种），否则整张表全是空的。
    """
    return (r.get("vt_threat_label") or r.get("vt_threat_category") or "").strip()


def write_report(records: list[dict], out_md: Path, label: str = "", detail: bool = False,
                 notes=None) -> None:
    """把检测结果整理成一份 Markdown 检测报告。

    默认只出概览性的短表（一页以内）；完整明细表要用 --report-detail 才附加，
    日常看明细直接查 summary.csv 就行。
    """
    total = len(records)
    found = [r for r in records if r.get("vt_result") == "已收录"]
    not_found = [r for r in records if r.get("vt_result") == "未收录"]
    failed = [r for r in records if r.get("vt_result") not in ("已收录", "未收录")]
    detected = [r for r in found if _positives(r.get("vt_detection")) > 0]
    has_cverc = any(r.get("cverc_result") for r in records)

    ratios = [x for x in (_ratio(r.get("vt_detection")) for r in found) if x >= 0]
    avg_rate = f"{sum(ratios) / len(ratios):.1%}" if ratios else "-"

    def pct(n: int) -> str:
        return f"{n / total:.1%}" if total else "-"

    sources = "VirusTotal API v3"
    if has_cverc:
        sources += "；国家计算机病毒协同分析平台开放接口"

    out = ["# 恶意代码批量检测报告", ""]
    out.append(f"- 检测对象：{label}" if label else "- 检测对象：恶意代码样本")
    out += [
        f"- 数据来源：{sources}",
        f"- 样本数：{total}",
        f"- 生成时间：{datetime.now():%Y-%m-%d %H:%M:%S}",
    ]
    for note in (notes or []):
        out.append(f"- 说明：{note}")
    out += [
        "",
        "## 一、检测结果概览",
        "",
        "| 指标 | 数量 | 占比 |",
        "| --- | --- | --- |",
        f"| 样本总数 | {total} | 100.0% |",
        f"| VirusTotal 已收录 | {len(found)} | {pct(len(found))} |",
        f"| VirusTotal 未收录 | {len(not_found)} | {pct(len(not_found))} |",
        f"| 至少一家引擎报毒 | {len(detected)} | {pct(len(detected))} |",
        f"| 平均检出率（报毒引擎占比） | {avg_rate} | — |",
    ]
    if failed:
        out.append(f"| 查询失败（网络等原因） | {len(failed)} | {pct(len(failed))} |")

    # 检出率分档
    buckets = [("0（无引擎报毒）", 0, 0), ("1–5 家", 1, 5), ("6–20 家", 6, 20),
               ("21 家及以上", 21, 10 ** 9)]
    out += ["", "## 二、检出率分布", "", "| 检出的引擎数 | 样本数 | 占比 |", "| --- | --- | --- |"]
    for label_, low, high in buckets:
        n = sum(1 for r in found if low <= _positives(r.get("vt_detection")) <= high)
        out.append(f"| {label_} | {n} | {pct(n)} |")
    if not_found:
        out.append(f"| 平台未收录（无检出数据） | {len(not_found)} | {pct(len(not_found))} |")

    # 恶意家族
    families = {}
    for r in records:
        name = _family(r)
        if name:
            families[name] = families.get(name, 0) + 1
    families = dict(sorted(families.items(), key=lambda kv: (-kv[1], kv[0])))
    labelled = sum(1 for r in records if (r.get("vt_threat_label") or "").strip())
    categorised = sum(1 for r in records
                      if not (r.get("vt_threat_label") or "").strip()
                      and (r.get("vt_threat_category") or "").strip())
    title = "家族 / 类别" if categorised else "家族"
    out += ["", "## 三、主要恶意家族（Top 10）", "",
            f"| {title} | 样本数 |", "| --- | --- |"]
    if families:
        for name, n in list(families.items())[:10]:
            out.append(f"| {_cell(name)} | {n} |")
        if categorised:
            note = (f"家族取自 VirusTotal 的聚合标签，{labelled} 个样本有；"
                    f"另外 {categorised} 个样本没有聚合标签，退化为其类别（如 ransomware、trojan）。")
        else:
            note = (f"VirusTotal 只为 {total} 个样本中的 {labelled} 个给出了聚合家族标签，"
                    f"其余样本没有家族标注——这是平台侧的数据限制，不是漏查；"
                    f"未标注样本的检出命名可查 summary.csv。")
        out += ["", f"> {note}"]
    else:
        out.append("| （没有样本被标记家族） | 0 |")

    # 文件类型
    types = _counter(records, "vt_type")
    out += ["", "## 四、文件类型分布（Top 10）", "", "| 文件类型 | 样本数 |", "| --- | --- |"]
    if types:
        for name, n in list(types.items())[:10]:
            out.append(f"| {_cell(name)} | {n} |")
    else:
        out.append("| （无类型信息） | 0 |")

    # 检出率最高的样本
    out += ["", "## 五、检出率最高的样本（Top 10）", ""]
    top = sorted(found, key=lambda r: -_positives(r.get("vt_detection")))[:10]
    if top:
        header = f"| # | SHA256 | 文件名 | 检出比 | {title} |"
        sep = "| --- | --- | --- | --- | --- |"
        if has_cverc:
            header += " 协同平台检出 |"
            sep += " --- |"
        out += [header, sep]
        for i, r in enumerate(top, 1):
            row = (f"| {i} | `{r['sha256']}` | {_cell(r.get('vt_name'))} | "
                   f"{_cell(r.get('vt_detection'))} | {_cell(_family(r))}")
            if has_cverc:
                row += f" | {_cell(r.get('cverc_detection'))}"
            out.append(row + " |")
    else:
        out.append("（没有样本被检出）")

    if has_cverc:
        cv_data = sum(1 for r in records if (r.get("cverc_detection") or "").strip())
        out += ["", f"> 「协同平台检出」列中的「-」表示国家计算机病毒协同分析平台没有收录该样本；"
                    f"本批 {total} 个样本中该平台有检出数据的是 {cv_data} 个。"]

    # 未收录样本（只列少量，避免报告过长）
    out += ["", "## 六、VirusTotal 未收录的样本", ""]
    if not_found:
        shown = not_found[:8]
        out.append(f"共 {len(not_found)} 个样本未收录，其中：")
        out.append("")
        out.append("、".join(f"`{r['sha256']}`" for r in shown)
                   + (f"，另有 {len(not_found) - len(shown)} 个见 summary.csv。" if len(not_found) > len(shown) else ""))
    else:
        out.append("（全部样本均已在 VirusTotal 收录）")

    # 完整明细表：默认不打印，避免 100 个样本时报告过长
    if detail:
        out += ["", "## 七、全部样本明细", ""]
        header = f"| # | SHA256 | 文件名 | 大小(字节) | 类型 | 检出比 | {title} | 首次提交时间 |"
        sep = "| --- | --- | --- | --- | --- | --- | --- | --- |"
        if has_cverc:
            header += " 协同平台检出 |"
            sep += " --- |"
        out += [header, sep]
        for i, r in enumerate(records, 1):
            row = (f"| {i} | `{r['sha256']}` | {_cell(r.get('vt_name'))} | "
                   f"{_cell(r.get('vt_size'))} | {_cell(r.get('vt_type'))} | "
                   f"{_cell(r.get('vt_detection'))} | {_cell(_family(r))} | "
                   f"{_cell(r.get('vt_first_seen'))}")
            if has_cverc:
                row += f" | {_cell(r.get('cverc_detection'))}"
            out.append(row + " |")
    else:
        out += ["", "> 每个样本的完整字段（哈希、大小、类型、检出比、家族、提交时间等）见同目录的 `summary.csv`。"
                    "需要把明细表也写进报告时，加 `--report-detail` 重新生成。"]

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(out) + "\n", encoding="utf-8")
    log(f"检测报告已写出：{out_md}（共 {total} 个样本）")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="批量下载恶意代码样本的 VirusTotal / 协同分析平台报告")
    ap.add_argument("--hashes", type=Path, default=Path("hashes.txt"), help="哈希清单文件（默认 hashes.txt）")
    ap.add_argument("--samples", type=Path,
                    help="样本目录：直接从样本文件出发，程序自己算 SHA256 再查询")
    ap.add_argument("--list-only", action="store_true",
                    help="只算 SHA256 生成清单、不联网查询（配合 --samples 使用）")
    ap.add_argument("--with-name", action="store_true",
                    help="生成清单时在每行附上文件相对路径，便于对照")
    ap.add_argument("--upload", action="store_true",
                    help="平台里没有的样本，把样本文件本身上传给平台分析（默认关闭，需配合 --samples）")
    ap.add_argument("--hash", dest="one_hash", help="只查询指定的单个哈希")
    ap.add_argument("--out", type=Path, default=Path("reports"), help="报告输出目录（默认 reports/）")
    ap.add_argument("--only", choices=["vt", "cverc", "both"], default="both", help="只查某个平台")
    ap.add_argument("--vt-key", help="VirusTotal API key")
    ap.add_argument("--cverc-key", help="协同分析平台 apikey")
    ap.add_argument("--vt-interval", type=float, default=VT_DEFAULT_INTERVAL,
                    help=f"VT 两次请求的最小间隔秒数（免费 key 默认 {VT_DEFAULT_INTERVAL:.0f}，付费可调小）")
    ap.add_argument("--cverc-endpoints", default=",".join(CVERC_DEFAULT),
                    help="协同平台要取的接口，逗号分隔，可选：" + "/".join(CVERC_ENDPOINTS))
    ap.add_argument("--limit", type=int, help="最多查询几条（便于先小批量试跑）")
    ap.add_argument("--force", action="store_true", help="已存在报告也重新下载")
    ap.add_argument("--summary-only", action="store_true",
                    help="不联网，只根据已有报告重新生成 summary.csv 和 detection_report.md")
    ap.add_argument("--label", help="检测报告里「检测对象」的名称，默认用 --out 的目录名")
    ap.add_argument("--note", action="append",
                    help="写进检测报告开头的一行说明，可重复使用多次；"
                         "会和 --label 一起记到输出目录的 report_meta.json，重出报告时自动带上")
    ap.add_argument("--report-detail", action="store_true",
                    help="把全部样本明细表也写进检测报告（默认不写，避免报告过长）")
    args = ap.parse_args()

    out_root = args.out
    vt_dir, cverc_dir = out_root / "vt", out_root / "cverc"

    # 取 key
    cfg = {}
    cfg_file = Path(__file__).with_name("config.json")
    if cfg_file.exists():
        try:
            cfg = json.loads(cfg_file.read_text("utf-8"))
        except ValueError:
            log(f"警告：{cfg_file} 不是合法 JSON，已忽略")

    vt_key = args.vt_key or os.environ.get("VT_API_KEY") or cfg.get("vt_api_key", "")
    cverc_key = args.cverc_key or os.environ.get("CVERC_API_KEY") or cfg.get("cverc_api_key", "")

    # 准备哈希清单
    hash_to_file = {}  # 哈希 -> 样本文件路径（只有 --samples 模式才有）
    if args.one_hash:
        hashes = [args.one_hash.strip().lower()]
    elif args.summary_only:
        # 从已经落盘的报告里反推哈希清单；协同平台的文件名是 <sha256>.<接口>.json
        found = {p.stem for p in vt_dir.glob("*.json")}
        for p in cverc_dir.glob("*.json"):
            if "." in p.name:
                found.add(p.name.split(".", 1)[0])
        hashes = sorted(found)
    elif args.samples:
        if not args.samples.is_dir():
            log(f"样本目录不存在：{args.samples}")
            return 2
        log(f"正在计算 {args.samples} 下所有文件的 SHA256（只读，不会执行样本）……")
        for path in sorted(p for p in args.samples.rglob("*") if p.is_file()):
            try:
                digest = sha256_of(path)
            except OSError as exc:
                log(f"  跳过 {path.name}：{exc}")
                continue
            # 内容相同的改名副本只算一个
            hash_to_file.setdefault(digest, path)
        hashes = sorted(hash_to_file)
        log(f"共得到 {len(hashes)} 个样本（按内容去重）")
        if args.limit:
            hashes = hashes[: args.limit]
    else:
        if not args.hashes.exists():
            log(f"找不到哈希清单 {args.hashes}，请把老师发的 SHA256 一行一个填进去。")
            return 2
        hashes = load_hashes(args.hashes)
        if args.limit:
            hashes = hashes[: args.limit]

    if args.list_only:
        if not hash_to_file:
            log("--list-only 需要配合 --samples 指定样本目录。")
            return 2
        lines = []
        for digest in hashes:
            path = hash_to_file[digest]
            try:
                rel = path.relative_to(args.samples)
            except ValueError:
                rel = path.name
            lines.append(f"{digest}  {rel}" if args.with_name else digest)
        args.hashes.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log(f"已写出 {len(lines)} 个哈希到 {args.hashes.resolve()}")
        log(f"接着执行：python query_reports.py --hashes {args.hashes}")
        return 0

    want_upload = bool(args.upload and hash_to_file)
    if args.upload and not hash_to_file:
        log("提示：--upload 需要配合 --samples 指定样本目录才有文件可上传，本次忽略。")

    if not hashes and not args.summary_only:
        log("哈希清单里没有有效的 SHA256。")
        return 2

    want_vt = args.only in ("vt", "both")
    want_cverc = args.only in ("cverc", "both")

    if args.summary_only:
        pass
    elif not hashes:
        log("没有可查询的哈希。")
        return 2

    if not args.summary_only:
        log(f"待查询 {len(hashes)} 个哈希；平台："
            f"{'VirusTotal ' if want_vt else ''}{'协同分析平台' if want_cverc else ''}")
        if want_vt:
            if not vt_key:
                log("缺少 VirusTotal API key（用 --vt-key 或环境变量 VT_API_KEY 指定）。")
                want_vt = False
            else:
                vt_dir.mkdir(parents=True, exist_ok=True)
                per_min = 60 / args.vt_interval
                log(f"VirusTotal 限速：每 {args.vt_interval:.0f} 秒 1 次，"
                    f"预计耗时约 {len(hashes) * args.vt_interval / 60:.0f} 分钟"
                    f"（免费 key 每天上限 500 次，当前速率 {per_min:.1f} 次/分钟）")
        if want_cverc:
            if not cverc_key:
                log("缺少协同分析平台 apikey（用 --cverc-key 或环境变量 CVERC_API_KEY 指定）。")
                want_cverc = False
            else:
                cverc_dir.mkdir(parents=True, exist_ok=True)

        if requests is None:
            log("这台机器没有 requests 模块，没法联网查询（算哈希不需要它）。")
            log("  想联网查：pip install requests")
            log("  只想算哈希生成清单：加 --list-only 再跑，不需要联网也不需要 requests")
            return 2

        vt = VirusTotal(vt_key, vt_dir, args.vt_interval) if want_vt else None
        endpoints = [e.strip() for e in args.cverc_endpoints.split(",") if e.strip() in CVERC_ENDPOINTS]
        cverc = Cverc(cverc_key, cverc_dir, endpoints) if want_cverc else None

        if want_upload:
            log("提醒：--upload 会把样本文件本身提交给平台，样本将进入对方数据库并可能"
                "共享给其合作方。只上传你有权对外提交的样本（课程发放的样本没问题），"
                "带隐私或企业内部数据的样本不要上传。")

        done = 0
        try:
            for i, sha256 in enumerate(hashes, 1):
                log(f"[{i}/{len(hashes)}] {sha256}")

                if vt:
                    vt_file = vt_dir / f"{sha256}.json"
                    if vt_file.exists() and not args.force:
                        log("  VirusTotal：已有报告，跳过")
                    else:
                        rec = vt.fetch(sha256)
                        vt_file.write_text(json.dumps(rec["body"], ensure_ascii=False, indent=2),
                                           encoding="utf-8")
                        if rec["http"] == 200:
                            log(f"  VirusTotal：已保存（{vt_row(rec)['vt_detection']} 家引擎报毒）")
                        elif rec["http"] == 404:
                            log("  VirusTotal：该样本未收录")
                            if want_upload:
                                up = vt.upload(hash_to_file[sha256])
                                (vt_dir / f"{sha256}.upload.json").write_text(
                                    json.dumps(up["body"], ensure_ascii=False, indent=2),
                                    encoding="utf-8")
                                if up["http"] == 200:
                                    log("  VirusTotal：样本已提交，分析需要几分钟，"
                                        "稍后重跑一次本程序即可取到报告")
                                else:
                                    log(f"  VirusTotal：上传失败（HTTP {up['http']}）")
                        else:
                            log(f"  VirusTotal：查询失败（HTTP {rec['http']}）")

                if cverc:
                    rec = cverc.fetch(sha256)
                    hits = []
                    for name, item in rec.items():
                        f = cverc_dir / f"{sha256}.{name}.json"
                        if f.exists() and not args.force:
                            continue
                        f.write_text(json.dumps(item["body"], ensure_ascii=False, indent=2),
                                     encoding="utf-8")
                        # data 非空才算平台真的收录了这个样本（未收录时 data 是空的）
                        if dig(item, "body", "code") == 0 and dig(item, "body", "data"):
                            hits.append(name)
                    # 只有 basic 明确回了"请求成功但 data 是空的"，才说明平台库里确实没这个样本
                    missing = (dig(rec, "basic", "body", "code") == 0
                               and not dig(rec, "basic", "body", "data"))
                    if hits:
                        log(f"  协同分析平台：已收录，保存 {len(hits)} 份报告（{'、'.join(hits)}）")
                    elif rec:
                        reason = dig(rec, "basic", "body", "msg", default="") or "平台未收录该样本"
                        log(f"  协同分析平台：{reason}（原始响应已存盘备查）")
                        if missing and want_upload:
                            up = cverc.upload(hash_to_file[sha256])
                            (cverc_dir / f"{sha256}.upload.json").write_text(
                                json.dumps(up["body"], ensure_ascii=False, indent=2),
                                encoding="utf-8")
                            code, msg = cverc_error(up["body"])
                            if msg or code not in (0, None):
                                log(f"  协同分析平台：上传失败（{msg or f'error_code {code}'}）")
                            else:
                                log("  协同分析平台：样本已提交，平台排队分析中，"
                                    "稍后重跑本程序即可取到报告")
                    else:
                        log("  协同分析平台：所有接口都不可用，已跳过")

                done += 1
        except KeyboardInterrupt:
            log(f"用户中断，已完成 {done}/{len(hashes)} 个；再次运行会从断点继续。")
        except RuntimeError as exc:
            log(f"中止：{exc}（已下载的报告都保留着，改好 key 后重新运行即可）")

        for name, reason in (cverc.disabled if cverc else {}).items():
            log(f"提示：协同分析平台接口 {name} 本次未取到（{reason}）；"
                f"如果该接口是必需的，可到平台个人中心申请接口权限后重跑。")

    records = load_records(vt_dir, cverc_dir)

    # 标签和说明记到输出目录里，这样以后 --summary-only 重出报告时不用再传一遍
    meta_path = out_root / "report_meta.json"
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text("utf-8"))
        except ValueError:
            meta = {}
    label = args.label or meta.get("label") or (out_root.name if out_root.name != "reports" else "")
    notes = args.note if args.note is not None else list(meta.get("notes") or [])

    if records:
        if args.label or args.note is not None:
            meta_path.write_text(
                json.dumps({"label": label, "notes": notes}, ensure_ascii=False, indent=2),
                encoding="utf-8")
        write_summary(records, out_root / "summary.csv")
        write_report(records, out_root / "detection_report.md",
                     label=label, detail=args.report_detail, notes=notes)
    else:
        log(f"{out_root} 里还没有任何报告，先跑一次查询再来生成汇总。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
