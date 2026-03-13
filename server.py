#!/usr/bin/env python3
"""
模型健康监控服务
作者：liusheng
时间：2026-03-13

定时从 New API 拉取可见模型并做真实 completion 探测，提供公开的 JSON API 和监控页面。
"""

import http.server
import json
import urllib.request
import urllib.parse
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ========== 配置 ==========
NEWAPI_BASE = os.environ.get("NEWAPI_BASE", "http://127.0.0.1:3000")
NEWAPI_USERNAME = os.environ.get("NEWAPI_USERNAME", "admin")
NEWAPI_PASSWORD = os.environ.get("NEWAPI_PASSWORD", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "1800"))  # 秒
PROBE_TIMEOUT = int(os.environ.get("PROBE_TIMEOUT", "15"))  # 秒
PROBE_WORKERS = int(os.environ.get("PROBE_WORKERS", "6"))
PROBE_MAX_TOKENS = int(os.environ.get("PROBE_MAX_TOKENS", "3"))
MODEL_HISTORY_LIMIT = int(os.environ.get("MODEL_HISTORY_LIMIT", "30"))
PROBE_TOKEN_NAME = os.environ.get("PROBE_TOKEN_NAME", "")
PROBE_PROMPT = os.environ.get("PROBE_PROMPT", "hi")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8890"))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "8891"))
CERT_FILE = os.environ.get("CERT_FILE", "cert.pem")
KEY_FILE = os.environ.get("KEY_FILE", "key.pem")
PUBLIC_API_URL = os.environ.get("PUBLIC_API_URL", "http://your-server-ip:3000")

# ========== 全局数据 ==========
cached_data = {
    "channels": [],
    "models": {},
    "last_update": None,
    "error": None,
    "meta": {}
}
data_lock = threading.Lock()
refresh_lock = threading.Lock()
probe_history_map = {}


def login_and_get_cookie():
    """登录 New API 获取 session cookie"""
    url = f"{NEWAPI_BASE}/api/user/login"
    payload = json.dumps({"username": NEWAPI_USERNAME, "password": NEWAPI_PASSWORD}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=10)
    # 提取 session cookie
    cookies = resp.headers.get_all("Set-Cookie")
    session = None
    user_id = None
    if cookies:
        for c in cookies:
            if "session=" in c:
                session = c.split("session=")[1].split(";")[0]
    # 解析 user id
    body = json.loads(resp.read().decode())
    if body.get("success") and body.get("data"):
        user_id = body["data"].get("id", 2)
    return session, user_id


def fetch_channels(session, user_id):
    """获取所有渠道信息"""
    url = f"{NEWAPI_BASE}/api/channel/?p=0&page_size=200"
    req = urllib.request.Request(url, headers={
        "Cookie": f"session={session}",
        "New-Api-User": str(user_id)
    })
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read().decode())
    if body.get("success"):
        return body["data"]["items"]
    return []


def fetch_tokens(session, user_id):
    """
    获取当前管理账号可用的 API Token。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    url = f"{NEWAPI_BASE}/api/token/?p=0&page_size=100"
    req = urllib.request.Request(url, headers={
        "Cookie": f"session={session}",
        "New-Api-User": str(user_id)
    })
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read().decode())
    if body.get("success"):
        return body["data"]["items"]
    return []


def select_probe_token(tokens):
    """
    从启用 token 中选一个用于真实探测。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    enabled_tokens = [item for item in tokens if item.get("status") == 1]
    if PROBE_TOKEN_NAME:
        named_tokens = [item for item in enabled_tokens if item.get("name") == PROBE_TOKEN_NAME]
        if named_tokens:
            enabled_tokens = named_tokens
    if not enabled_tokens:
        raise RuntimeError("未找到可用于探测的启用 token")
    enabled_tokens.sort(key=lambda item: item.get("accessed_time", 0), reverse=True)
    token = enabled_tokens[0]
    token_value = token.get("key", "")
    if not token_value:
        raise RuntimeError("探测 token 缺少 key")
    if not token_value.startswith("sk-"):
        token_value = f"sk-{token_value}"
    return token_value, token.get("name") or f"token-{token.get('id')}"


def fetch_visible_models(api_key):
    """
    获取当前 token 实际可见的模型列表。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    req = urllib.request.Request(
        f"{NEWAPI_BASE}/v1/models",
        headers={"Authorization": f"Bearer {api_key}"}
    )
    resp = urllib.request.urlopen(req, timeout=15)
    body = json.loads(resp.read().decode())
    visible_models = []
    for item in body.get("data", []):
        model_name = item.get("id", "").strip()
        if model_name and model_name not in visible_models:
            visible_models.append(model_name)
    return visible_models


def summarize_probe_error(raw_text, fallback_message):
    """
    将上游错误收敛成页面可读的简短描述。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    fallback_message = fallback_message or ""
    error_message = raw_text or fallback_message or "未知错误"
    try:
        error_body = json.loads(raw_text) if raw_text else {}
        error_message = error_body.get("error", {}).get("message") or error_message
    except json.JSONDecodeError:
        pass
    if "No available channel" in error_message:
        return "无可用渠道"
    if "auth_unavailable" in error_message or "no auth available" in error_message:
        return "上游认证池不可用"
    if "unknown provider" in error_message:
        return "模型映射异常"
    if "timed out" in fallback_message.lower():
        return "请求超时"
    if "HTTP Error 403" in fallback_message:
        return "请求被上游拒绝"
    if "HTTP Error 502" in fallback_message:
        return "上游网关异常"
    if "HTTP Error 503" in fallback_message:
        return "服务暂不可用"
    if "openai_error" in error_message:
        return "上游返回 openai_error"
    return error_message[:80]


def probe_single_model(api_key, model_name, timeout=PROBE_TIMEOUT):
    """
    对单个模型发起最小 chat completion 请求。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    payload = json.dumps({
        "model": model_name,
        "messages": [{"role": "user", "content": PROBE_PROMPT}],
        "max_tokens": PROBE_MAX_TOKENS,
        "temperature": 0
    }).encode()
    req = urllib.request.Request(
        f"{NEWAPI_BASE}/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    started_at = time.perf_counter()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        resp.read()
        elapsed_ms = int((time.perf_counter() - started_at) * 1000)
        return {
            "name": model_name,
            "ok": True,
            "status": "healthy",
            "response_time": elapsed_ms,
            "error": None,
            "checked_at": checked_at
        }
    except Exception as exc:
        raw_text = ""
        if hasattr(exc, "read"):
            try:
                raw_text = exc.read().decode("utf-8", "ignore")
            except Exception:
                raw_text = ""
        return {
            "name": model_name,
            "ok": False,
            "status": "unhealthy",
            "response_time": None,
            "error": summarize_probe_error(raw_text, str(exc)),
            "checked_at": checked_at
        }


def probe_models(api_key, model_names):
    """
    并发探测一组模型的真实可用性。
    作者：liusheng
    时间：2026-03-13 14:20
    """
    if not model_names:
        return {}
    results = {}
    max_workers = min(PROBE_WORKERS, len(model_names))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(probe_single_model, api_key, model_name): model_name
            for model_name in model_names
        }
        for future in as_completed(futures):
            result = future.result()
            results[result["name"]] = result
    return results


def aggregate_models(channels, visible_models, probe_results):
    """
    聚合模型健康状态
    以真实 completion 探测结果为准，渠道测试状态只作为辅助信息展示。
    """
    models = {}
    visible_set = set(visible_models)
    for model_name in visible_models:
        models[model_name] = {
            "name": model_name,
            "status": "unhealthy",
            "response_time": None,
            "error": None,
            "checked_at": None,
            "channels": [],
            "healthy_count": 0,
            "total_count": 0,
            "min_response_time": None,
            "history": list(probe_history_map.get(model_name, []))
        }
    for ch in channels:
        ch_status = ch.get("status", 0)
        ch_name = ch.get("name", "")
        ch_response = ch.get("response_time", 0)
        ch_test_time = ch.get("test_time", 0)
        model_list = ch.get("models", "").split(",")
        for m in model_list:
            m = m.strip()
            if not m or m not in visible_set:
                continue
            models[m]["total_count"] += 1
            channel_info = {
                "id": ch.get("id"),
                "name": ch_name,
                "status": "healthy" if ch_status == 1 else "unhealthy",
                "response_time": ch_response,
                "test_time": ch_test_time
            }
            models[m]["channels"].append(channel_info)
            if ch_status == 1:
                models[m]["healthy_count"] += 1
                if models[m]["min_response_time"] is None or ch_response < models[m]["min_response_time"]:
                    models[m]["min_response_time"] = ch_response
    for model_name, result in probe_results.items():
        if model_name not in models:
            continue
        models[model_name]["status"] = result["status"]
        models[model_name]["response_time"] = result["response_time"]
        models[model_name]["error"] = result["error"]
        models[model_name]["checked_at"] = result["checked_at"]
        models[model_name]["history"] = list(probe_history_map.get(model_name, []))
    return models


def refresh_health_data(reason="auto", block=True):
    """
    执行一次完整的健康探测并刷新缓存。
    作者：liusheng
    时间：2026-03-13 14:40
    """
    global cached_data
    acquired = refresh_lock.acquire(blocking=block)
    if not acquired:
        with data_lock:
            return {
                "success": False,
                "message": "已有刷新任务在执行，请稍后再试",
                "data": cached_data
            }
    try:
        session, user_id = login_and_get_cookie()
        channels = fetch_channels(session, user_id)
        tokens = fetch_tokens(session, user_id)
        probe_api_key, probe_token_name = select_probe_token(tokens)
        visible_models = fetch_visible_models(probe_api_key)
        probe_results = probe_models(probe_api_key, visible_models)
        current_visible_set = set(visible_models)
        for model_name in list(probe_history_map):
            if model_name not in current_visible_set:
                probe_history_map.pop(model_name, None)
        for model_name in visible_models:
            history = probe_history_map.setdefault(model_name, [])
            history.append(bool(probe_results.get(model_name, {}).get("ok")))
            if len(history) > MODEL_HISTORY_LIMIT:
                del history[:-MODEL_HISTORY_LIMIT]
        models = aggregate_models(channels, visible_models, probe_results)
        safe_channels = []
        for ch in channels:
            safe_channels.append({
                "id": ch.get("id"),
                "name": ch.get("name"),
                "status": ch.get("status"),
                "response_time": ch.get("response_time"),
                "test_time": ch.get("test_time"),
                "models": [item.strip() for item in ch.get("models", "").split(",") if item.strip()],
            })
        snapshot = {
            "channels": safe_channels,
            "models": models,
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": None,
            "meta": {
                "probe_mode": "chat_completions",
                "probe_user": NEWAPI_USERNAME,
                "probe_token_name": probe_token_name,
                "probe_timeout": PROBE_TIMEOUT,
                "history_limit": MODEL_HISTORY_LIMIT,
                "auto_refresh_interval": POLL_INTERVAL,
                "last_refresh_reason": reason
            }
        }
        with data_lock:
            cached_data = snapshot
        print(
            f"[{datetime.now()}] 数据刷新成功({reason}): "
            f"{len(channels)} 渠道, {len(visible_models)} 可见模型, "
            f"{sum(1 for item in probe_results.values() if item.get('ok'))} 个真实可用"
        )
        return {
            "success": True,
            "message": "刷新成功",
            "data": snapshot
        }
    except Exception as e:
        with data_lock:
            cached_data["error"] = str(e)
            cached_data["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{datetime.now()}] 数据刷新失败({reason}): {e}")
        return {
            "success": False,
            "message": str(e),
            "data": cached_data
        }
    finally:
        refresh_lock.release()


def poll_loop():
    """后台定时拉取模型和真实探测数据"""
    while True:
        refresh_health_data(reason="auto", block=True)
        time.sleep(POLL_INTERVAL)


# ========== HTML 页面 ==========
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>模型健康监控</title>
<style>
  :root {
    --bg: #0f1117;
    --card-bg: #1a1d28;
    --card-border: #2a2d3a;
    --text: #e4e4e7;
    --text-dim: #8b8fa3;
    --text-muted: #555870;
    --green: #22c55e;
    --green-bg: rgba(34,197,94,0.12);
    --green-dim: rgba(34,197,94,0.06);
    --red: #ef4444;
    --red-bg: rgba(239,68,68,0.12);
    --yellow: #eab308;
    --yellow-bg: rgba(234,179,8,0.12);
    --blue: #3b82f6;
    --blue-bg: rgba(59,130,246,0.12);
    --purple: #a855f7;
    --purple-bg: rgba(168,85,247,0.12);
    --sidebar-width: 200px;
    --radius: 12px;
    --radius-sm: 8px;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'SF Pro Display', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  /* ===== 主布局 ===== */
  .page-wrapper {
    max-width: 1400px;
    margin: 0 auto;
    padding: 80px 24px 48px;
  }

  /* ===== 刷新状态指示器（嵌入模型标题栏） ===== */
  .models-section-title {
    flex-wrap: wrap;
  }
  .refresh-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-left: auto;
    font-size: 12px;
    color: var(--text-muted);
  }
  .refresh-note {
    color: var(--text-dim);
    white-space: nowrap;
  }
  .refresh-indicator .pulse-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 6px var(--green);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.7); }
  }
  .refresh-indicator .countdown {
    font-family: 'SF Mono', Consolas, monospace;
    color: var(--text-dim);
    min-width: 22px;
    text-align: right;
  }
  .manual-refresh-btn {
    border: 1px solid rgba(59,130,246,0.3);
    background: linear-gradient(135deg, rgba(59,130,246,0.22), rgba(59,130,246,0.08));
    color: #d7e8ff;
    border-radius: 999px;
    padding: 5px 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.2px;
    cursor: pointer;
    transition: all 0.15s;
    box-shadow: 0 0 0 1px rgba(59,130,246,0.08) inset;
  }
  .manual-refresh-btn:hover {
    background: linear-gradient(135deg, rgba(59,130,246,0.32), rgba(59,130,246,0.14));
    border-color: rgba(59,130,246,0.45);
    transform: translateY(-1px);
  }
  .manual-refresh-btn.loading {
    cursor: wait;
    opacity: 0.75;
  }

  /* ===== 统计卡片 ===== */
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 32px;
  }
  .stat-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--radius);
    padding: 16px 20px;
    text-align: center;
    transition: border-color 0.2s;
  }
  .stat-card:hover { border-color: #3a3d4a; }
  .stat-card .num {
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    letter-spacing: -1px;
  }
  .stat-card .label {
    color: var(--text-dim);
    font-size: 12px;
    margin-top: 5px;
    letter-spacing: 0.3px;
  }
  .stat-card.total .num { color: var(--blue); }
  .stat-card.healthy .num { color: var(--green); }
  .stat-card.unhealthy .num { color: var(--red); }
  .stat-card.channels .num { color: var(--purple); }

  /* ===== 错误消息 ===== */
  .error-msg {
    padding: 12px 16px;
    color: var(--red);
    font-size: 13px;
    background: var(--red-bg);
    border: 1px solid rgba(239,68,68,0.25);
    border-radius: var(--radius-sm);
    margin-bottom: 20px;
  }

  /* ===== 分区标题 ===== */
  .section {
    margin-bottom: 32px;
  }
  .section-title {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--card-border);
  }
  .section-title h2 {
    font-size: 17px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: -0.2px;
  }
  .section-title .icon {
    width: 30px; height: 30px;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 15px;
  }
  .section-title .icon.blue { background: var(--blue-bg); }
  .section-title .icon.green { background: var(--green-bg); }
  .section-title .badge {
    margin-left: auto;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    color: var(--text-dim);
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 20px;
  }

  /* ===== 接入工具区域 ===== */
  .tools-layout {
    display: grid;
    grid-template-columns: var(--sidebar-width) 1fr;
    gap: 0;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--radius);
    overflow: hidden;
    min-height: 420px;
  }

  /* 工具侧边栏 */
  .tools-sidebar {
    border-right: 1px solid var(--card-border);
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: rgba(0,0,0,0.15);
  }
  .tool-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: all 0.15s;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-dim);
    font-size: 13px;
    font-weight: 500;
    text-align: left;
    width: 100%;
  }
  .tool-btn:hover {
    background: rgba(255,255,255,0.05);
    color: var(--text);
    border-color: var(--card-border);
  }
  .tool-btn.active {
    background: var(--blue-bg);
    color: var(--blue);
    border-color: rgba(59,130,246,0.25);
  }
  .tool-btn .tool-icon {
    width: 22px; height: 22px;
    border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px;
    flex-shrink: 0;
    background: rgba(255,255,255,0.07);
  }
  .tool-btn.active .tool-icon {
    background: var(--blue-bg);
  }
  .tool-category {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 8px 12px 4px;
    font-weight: 600;
    user-select: none;
  }
  .tool-category:first-child {
    padding-top: 4px;
  }

  /* 工具内容面板 */
  .tools-panel {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .tool-content {
    display: none;
    flex-direction: column;
    height: 100%;
  }
  .tool-content.active {
    display: flex;
  }
  .tool-content-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--card-border);
    flex-shrink: 0;
  }
  .tool-content-header .tool-name {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 15px;
    font-weight: 600;
  }
  .tool-content-header .tool-desc {
    color: var(--text-dim);
    font-size: 12px;
    margin-top: 2px;
  }
  .copy-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    background: var(--blue-bg);
    border: 1px solid rgba(59,130,246,0.3);
    color: var(--blue);
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .copy-btn:hover {
    background: rgba(59,130,246,0.2);
    border-color: rgba(59,130,246,0.5);
  }
  .copy-btn.copied {
    background: var(--green-bg);
    border-color: rgba(34,197,94,0.3);
    color: var(--green);
  }

  .tool-code-wrap {
    flex: 1;
    overflow: auto;
    padding: 18px;
    position: relative;
  }
  .tool-code-wrap pre {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', Consolas, monospace;
    font-size: 13px;
    line-height: 1.7;
    color: #d4d4d4;
    white-space: pre;
    overflow-x: auto;
    tab-size: 2;
  }

  /* 代码高亮色 */
  .c-comment { color: #6a9955; }
  .c-key { color: #9cdcfe; }
  .c-val { color: #ce9178; }
  .c-keyword { color: #569cd6; }
  .c-string { color: #ce9178; }
  .c-num { color: #b5cea8; }
  .c-prop { color: #4ec9b0; }
  .c-func { color: #dcdcaa; }
  .c-var { color: #9cdcfe; }
  .c-op { color: #d4d4d4; }

  /* 端点信息栏 */
  .tools-footer {
    border-top: 1px solid var(--card-border);
    padding: 12px 18px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    background: rgba(0,0,0,0.1);
    flex-shrink: 0;
  }
  .tools-footer .info-item {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .tools-footer .info-label {
    color: var(--text-muted);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.8px;
    text-transform: uppercase;
  }
  .tools-footer .info-val {
    color: var(--text);
    font-family: 'SF Mono', Consolas, monospace;
    font-size: 12px;
    background: rgba(255,255,255,0.06);
    border: 1px solid var(--card-border);
    padding: 3px 10px;
    border-radius: 5px;
  }
  .tools-footer .info-val.endpoint { color: var(--blue); }
  .tools-footer .info-val.protocol { color: var(--green); }

  /* ===== 模型健康度区域 ===== */
  .models-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .model-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 14px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: var(--radius-sm);
    transition: all 0.15s;
    cursor: default;
  }
  .model-row:hover {
    border-color: #3a3d4a;
    background: #1e2130;
  }
  .model-row:hover .model-name-text { color: var(--blue); }

  /* 健康度百分比徽章 */
  .health-badge {
    width: 64px;
    flex-shrink: 0;
    text-align: center;
    padding: 4px 0;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: -0.3px;
  }
  .health-badge.full { background: var(--green-bg); color: var(--green); }
  .health-badge.partial { background: var(--yellow-bg); color: var(--yellow); }
  .health-badge.zero { background: var(--red-bg); color: var(--red); }

  /* 模型名 */
  .model-name-wrap {
    flex: 1;
    min-width: 0;
  }
  .model-name-text {
    font-size: 13.5px;
    font-weight: 500;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    transition: color 0.15s;
    font-family: 'SF Mono', 'Cascadia Code', Consolas, monospace;
  }
  .model-meta-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-top: 2px;
    font-size: 11px;
    color: var(--text-muted);
    min-width: 0;
    overflow: hidden;
  }
  .model-probe {
    white-space: nowrap;
    font-weight: 600;
  }
  .model-probe.ok { color: var(--green); }
  .model-probe.fail { color: var(--red); }
  .model-channel-meta {
    color: var(--text-dim);
    white-space: nowrap;
  }
  .model-error {
    margin-top: 4px;
    font-size: 11px;
    color: var(--red);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .model-rt {
    font-family: 'SF Mono', Consolas, monospace;
    font-size: 11px;
  }
  .model-rt.fast { color: var(--green); }
  .model-rt.medium { color: var(--yellow); }
  .model-rt.slow { color: var(--red); }
  .model-rt.na { color: var(--text-muted); }

  /* 健康条 */
  .health-bar-wrap {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 4px;
    flex-shrink: 0;
  }
  .health-bar {
    display: flex;
    gap: 2px;
    align-items: center;
  }
  .health-block {
    width: 8px;
    height: 22px;
    border-radius: 3px;
    transition: opacity 0.2s;
  }
  .health-block:hover { opacity: 0.8; }
  .health-block.ok { background: var(--green); }
  .health-block.fail { background: var(--red); }
  .health-block.ok-dim { background: rgba(34,197,94,0.4); }
  .health-block.empty { background: rgba(255,255,255,0.08); }
  .health-bar-label {
    display: flex;
    justify-content: space-between;
    width: 100%;
    font-size: 10px;
    color: var(--text-muted);
  }
  .health-bar-label span:last-child { color: var(--green); font-weight: 600; }

  /* 渠道数量徽章 */
  .ch-count {
    flex-shrink: 0;
    font-size: 11px;
    color: var(--text-muted);
    white-space: nowrap;
    min-width: 52px;
    text-align: right;
  }
  .ch-count .ch-ok { color: var(--green); font-weight: 600; }
  .ch-count .ch-total { color: var(--text-muted); }
  .model-actions {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 8px;
    flex-shrink: 0;
  }
  .copy-model-btn {
    border: 1px solid rgba(59,130,246,0.28);
    background: var(--blue-bg);
    color: var(--blue);
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    line-height: 1;
    transition: all 0.15s;
  }
  .copy-model-btn:hover {
    background: rgba(59,130,246,0.2);
    border-color: rgba(59,130,246,0.45);
  }
  .copy-model-btn.copied {
    background: var(--green-bg);
    border-color: rgba(34,197,94,0.35);
    color: var(--green);
  }
  .copy-model-btn.failed {
    background: var(--yellow-bg);
    border-color: rgba(234,179,8,0.35);
    color: var(--yellow);
  }

  /* 分组标题 */
  .group-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 4px;
    margin-top: 8px;
    margin-bottom: 4px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-dim);
    letter-spacing: 0.4px;
    text-transform: uppercase;
  }
  .group-header .gh-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .group-header.g-healthy .gh-dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .group-header.g-unhealthy .gh-dot { background: var(--red); box-shadow: 0 0 6px var(--red); }
  .group-header .gh-count {
    margin-left: auto;
    font-weight: 400;
    color: var(--text-muted);
    text-transform: none;
    letter-spacing: 0;
    font-size: 12px;
  }

  /* 复制提示 Toast */
  .toast {
    position: fixed;
    bottom: 32px;
    left: 50%;
    transform: translateX(-50%) translateY(20px);
    background: #262a38;
    border: 1px solid #3a3d4a;
    color: var(--text);
    font-size: 13px;
    padding: 10px 18px;
    border-radius: var(--radius-sm);
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    opacity: 0;
    transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1);
    z-index: 9999;
    pointer-events: none;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }
  .toast-icon { color: var(--green); }

  /* 加载 */
  .loading {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-dim);
    font-size: 14px;
  }

  /* ===== 响应式 ===== */
  @media (max-width: 900px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .tools-layout { grid-template-columns: 1fr; min-height: auto; }
    .tools-sidebar {
      flex-direction: row;
      flex-wrap: wrap;
      border-right: none;
      border-bottom: 1px solid var(--card-border);
      padding: 8px;
    }
    .tool-btn { width: auto; flex: 1; min-width: 80px; justify-content: center; }
    .tool-btn .tool-icon { display: none; }
    .health-bar { display: none; }
  }
  @media (max-width: 640px) {
    .page-wrapper { padding: 12px 12px 32px; }
    .header h1 { font-size: 21px; }
    .stats { grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .stat-card .num { font-size: 26px; }
    .refresh-indicator {
      margin-left: 0;
      width: 100%;
      order: 10;
      flex-wrap: wrap;
    }
    .tools-footer { flex-direction: column; gap: 10px; }
    .model-meta-row { display: none; }
    .health-bar-wrap { display: none; }
    .ch-count { display: none; }
  }
</style>
</head>
<body>
<div class="page-wrapper">

  <!-- 错误消息占位 -->
  <div id="errorMsg" style="display:none" class="error-msg"></div>

  <!-- 统计卡片 -->
  <div class="stats" id="statsCards">
    <div class="stat-card total"><div class="num" id="statTotal">—</div><div class="label">模型总数</div></div>
    <div class="stat-card healthy"><div class="num" id="statHealthy">—</div><div class="label">健康</div></div>
    <div class="stat-card unhealthy"><div class="num" id="statUnhealthy">—</div><div class="label">异常</div></div>
    <div class="stat-card channels"><div class="num" id="statChannels">—</div><div class="label">渠道总数</div></div>
  </div>

  <!-- ===== Section 1: 接入工具 ===== -->
  <div class="section">
    <div class="section-title">
      <div class="icon blue">🔌</div>
      <h2>接入工具</h2>
      <span class="badge">10 种工具</span>
    </div>

    <div class="tools-layout">
      <!-- 侧边栏 -->
      <div class="tools-sidebar">
        <div class="tool-category">CLI 工具</div>
        <button class="tool-btn active" onclick="selectTool('claude-code')" id="btn-claude-code">
          <span class="tool-icon">△</span> Claude Code
        </button>
        <button class="tool-btn" onclick="selectTool('codex-cli')" id="btn-codex-cli">
          <span class="tool-icon">⬡</span> Codex CLI
        </button>
        <button class="tool-btn" onclick="selectTool('gemini-cli')" id="btn-gemini-cli">
          <span class="tool-icon">✦</span> Gemini CLI
        </button>
        <div class="tool-category">VS Code</div>
        <button class="tool-btn" onclick="selectTool('cline')" id="btn-cline">
          <span class="tool-icon">◇</span> Cline
        </button>
        <button class="tool-btn" onclick="selectTool('kilo-code')" id="btn-kilo-code">
          <span class="tool-icon">◈</span> Kilo Code
        </button>
        <button class="tool-btn" onclick="selectTool('continue')" id="btn-continue">
          <span class="tool-icon">▶</span> Continue
        </button>
        <div class="tool-category">JetBrains IDE</div>
        <button class="tool-btn" onclick="selectTool('codegpt')" id="btn-codegpt">
          <span class="tool-icon">⚙</span> CodeGPT
        </button>
        <div class="tool-category">桌面应用</div>
        <button class="tool-btn" onclick="selectTool('cherry-studio')" id="btn-cherry-studio">
          <span class="tool-icon">🍒</span> Cherry Studio
        </button>
        <div class="tool-category">开发集成</div>
        <button class="tool-btn" onclick="selectTool('openai-sdk')" id="btn-openai-sdk">
          <span class="tool-icon">⬢</span> OpenAI SDK
        </button>
        <button class="tool-btn" onclick="selectTool('curl')" id="btn-curl">
          <span class="tool-icon">⌁</span> cURL
        </button>
      </div>

      <!-- 内容面板 -->
      <div class="tools-panel">

        <!-- Claude Code -->
        <div class="tool-content active" id="content-claude-code">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">△ Claude Code</div>
              <div class="tool-desc">通过环境变量配置 API 代理和密钥</div>
            </div>
            <button class="copy-btn" onclick="copyCode('claude-code')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-claude-code"><span class="c-comment"># 方式一：临时设置环境变量（当前终端有效）</span>
<span class="c-keyword">export</span> <span class="c-var">ANTHROPIC_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__"</span>
<span class="c-keyword">export</span> <span class="c-var">ANTHROPIC_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span>

<span class="c-comment"># 然后直接启动 Claude Code</span>
<span class="c-func">claude</span>

<span class="c-comment"># 方式二：单行启动（推荐，不污染全局环境）</span>
<span class="c-var">ANTHROPIC_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__"</span> <span class="c-var">ANTHROPIC_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span> <span class="c-func">claude</span>

<span class="c-comment"># 方式三：写入 ~/.bashrc 或 ~/.zshrc 永久生效</span>
<span class="c-keyword">echo</span> <span class="c-string">'export ANTHROPIC_BASE_URL="__PUBLIC_API_URL__"'</span> <span class="c-op">>></span> ~/.zshrc
<span class="c-keyword">echo</span> <span class="c-string">'export ANTHROPIC_API_KEY="sk-your-api-key"'</span> <span class="c-op">>></span> ~/.zshrc
<span class="c-keyword">source</span> ~/.zshrc</pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Kilo Code -->
        <div class="tool-content" id="content-kilo-code">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">◈ Kilo Code</div>
              <div class="tool-desc">在 VS Code 设置中配置 Kilo Code 扩展</div>
            </div>
            <button class="copy-btn" onclick="copyCode('kilo-code')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-kilo-code"><span class="c-comment">// VS Code settings.json（Cmd+Shift+P → "Open User Settings JSON"）</span>
<span class="c-op">{</span>
  <span class="c-key">"kilo-code.apiProvider"</span><span class="c-op">:</span> <span class="c-string">"openai-compatible"</span><span class="c-op">,</span>
  <span class="c-key">"kilo-code.openAiBaseUrl"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
  <span class="c-key">"kilo-code.openAiApiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span><span class="c-op">,</span>
  <span class="c-key">"kilo-code.openAiModelId"</span><span class="c-op">:</span> <span class="c-string">"claude-sonnet-4-5"</span><span class="c-op">,</span>
  <span class="c-key">"kilo-code.maxTokens"</span><span class="c-op">:</span> <span class="c-num">8192</span>
<span class="c-op">}</span>

<span class="c-comment">// 或在 Kilo Code 扩展设置面板中填写：</span>
<span class="c-comment">// API Provider:  OpenAI Compatible</span>
<span class="c-comment">// Base URL:      __PUBLIC_API_URL__/v1</span>
<span class="c-comment">// API Key:       sk-your-api-key</span>
<span class="c-comment">// Model ID:      claude-sonnet-4-5（可改为其他模型）</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Cline -->
        <div class="tool-content" id="content-cline">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">◇ Cline</div>
              <div class="tool-desc">在 VS Code 设置中配置 Cline 扩展</div>
            </div>
            <button class="copy-btn" onclick="copyCode('cline')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-cline"><span class="c-comment">// VS Code settings.json（Cmd+Shift+P → "Open User Settings JSON"）</span>
<span class="c-op">{</span>
  <span class="c-key">"cline.apiProvider"</span><span class="c-op">:</span> <span class="c-string">"openai-compatible"</span><span class="c-op">,</span>
  <span class="c-key">"cline.openAiBaseUrl"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
  <span class="c-key">"cline.openAiApiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span><span class="c-op">,</span>
  <span class="c-key">"cline.openAiModelId"</span><span class="c-op">:</span> <span class="c-string">"claude-sonnet-4-5"</span>
<span class="c-op">}</span>

<span class="c-comment">// 或在 Cline 扩展侧边栏中配置：</span>
<span class="c-comment">// 1. 点击侧边栏 Cline 图标</span>
<span class="c-comment">// 2. 点击设置（齿轮图标）</span>
<span class="c-comment">// 3. API Provider 选择 "OpenAI Compatible"</span>
<span class="c-comment">// 4. Base URL:  __PUBLIC_API_URL__/v1</span>
<span class="c-comment">// 5. API Key:   sk-your-api-key</span>
<span class="c-comment">// 6. Model:     claude-sonnet-4-5</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Cherry Studio -->
        <div class="tool-content" id="content-cherry-studio">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">🍒 Cherry Studio</div>
              <div class="tool-desc">在 Cherry Studio 中添加自定义服务商</div>
            </div>
            <button class="copy-btn" onclick="copyCode('cherry-studio')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-cherry-studio"><span class="c-comment"># Cherry Studio 配置步骤：</span>
<span class="c-comment"># 1. 打开 Cherry Studio → 设置 → 模型服务</span>
<span class="c-comment"># 2. 点击"添加服务商" → 选择 OpenAI 兼容</span>
<span class="c-comment"># 3. 填写以下信息：</span>

<span class="c-key">服务商名称</span><span class="c-op">:</span>  <span class="c-string">New API</span>
<span class="c-key">API 地址</span><span class="c-op">:</span>   <span class="c-string">__PUBLIC_API_URL__/v1</span>
<span class="c-key">API Key</span><span class="c-op">:</span>    <span class="c-string">sk-your-api-key</span>

<span class="c-comment"># 4. 点击"检查"验证连接</span>
<span class="c-comment"># 5. 在模型列表中添加可用模型，例如：</span>
<span class="c-comment">#    claude-sonnet-4-5</span>
<span class="c-comment">#    gpt-4o</span>
<span class="c-comment">#    deepseek-chat</span>
<span class="c-comment"># 6. 保存并在对话中选择对应模型</span>

<span class="c-comment"># JSON 导入格式（设置 → 数据 → 导入配置）：</span>
<span class="c-op">{</span>
  <span class="c-key">"providers"</span><span class="c-op">:</span> <span class="c-op">[{</span>
    <span class="c-key">"id"</span><span class="c-op">:</span> <span class="c-string">"new-api"</span><span class="c-op">,</span>
    <span class="c-key">"name"</span><span class="c-op">:</span> <span class="c-string">"New API"</span><span class="c-op">,</span>
    <span class="c-key">"type"</span><span class="c-op">:</span> <span class="c-string">"openai"</span><span class="c-op">,</span>
    <span class="c-key">"apiHost"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
    <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span>
  <span class="c-op">}]</span>
<span class="c-op">}</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Codex CLI -->
        <div class="tool-content" id="content-codex-cli">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">⬡ Codex CLI</div>
              <div class="tool-desc">通过环境变量配置 OpenAI Codex CLI</div>
            </div>
            <button class="copy-btn" onclick="copyCode('codex-cli')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-codex-cli"><span class="c-comment"># 方式一：环境变量（临时）</span>
<span class="c-keyword">export</span> <span class="c-var">OPENAI_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__/v1"</span>
<span class="c-keyword">export</span> <span class="c-var">OPENAI_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span>

<span class="c-comment"># 使用 codex（指定模型）</span>
<span class="c-func">codex</span> <span class="c-op">--</span>model gpt-5.3-codex <span class="c-string">"帮我写一个快速排序算法"</span>

<span class="c-comment"># 方式二：写入配置文件 ~/.codex/config.json</span>
<span class="c-op">{</span>
  <span class="c-key">"model"</span><span class="c-op">:</span> <span class="c-string">"gpt-5.3-codex"</span><span class="c-op">,</span>
  <span class="c-key">"provider"</span><span class="c-op">:</span> <span class="c-op">{</span>
    <span class="c-key">"name"</span><span class="c-op">:</span> <span class="c-string">"openai"</span><span class="c-op">,</span>
    <span class="c-key">"baseURL"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
    <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span>
  <span class="c-op">}</span>
<span class="c-op">}</span>

<span class="c-comment"># 方式三：单行启动</span>
<span class="c-var">OPENAI_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__/v1"</span> <span class="c-var">OPENAI_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span> <span class="c-func">codex</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Gemini CLI -->
        <div class="tool-content" id="content-gemini-cli">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">✦ Gemini CLI</div>
              <div class="tool-desc">配置 Gemini CLI 使用 OpenAI 兼容代理</div>
            </div>
            <button class="copy-btn" onclick="copyCode('gemini-cli')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-gemini-cli"><span class="c-comment"># 方式一：使用 OpenAI 兼容模式（推荐）</span>
<span class="c-comment"># Gemini CLI 支持通过 OPENAI_API_KEY + OPENAI_BASE_URL 接入</span>
<span class="c-keyword">export</span> <span class="c-var">OPENAI_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span>
<span class="c-keyword">export</span> <span class="c-var">OPENAI_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__/v1"</span>

<span class="c-comment"># 启动时指定模型</span>
<span class="c-func">gemini</span> <span class="c-op">-</span>m gemini-2.5-pro

<span class="c-comment"># 方式二：配置文件 ~/.gemini/settings.json</span>
<span class="c-op">{</span>
  <span class="c-key">"selectedModel"</span><span class="c-op">:</span> <span class="c-string">"gemini-2.5-pro"</span><span class="c-op">,</span>
  <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span><span class="c-op">,</span>
  <span class="c-key">"vertexai"</span><span class="c-op">:</span> <span class="c-op">{</span>
    <span class="c-key">"baseUrl"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span>
  <span class="c-op">}</span>
<span class="c-op">}</span>

<span class="c-comment"># 单行方式</span>
<span class="c-var">OPENAI_BASE_URL</span><span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__/v1"</span> <span class="c-var">OPENAI_API_KEY</span><span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span> <span class="c-func">gemini</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- OpenAI SDK -->
        <div class="tool-content" id="content-openai-sdk">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">⬢ OpenAI SDK (Python)</div>
              <div class="tool-desc">使用 Python openai 库接入</div>
            </div>
            <button class="copy-btn" onclick="copyCode('openai-sdk')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-openai-sdk"><span class="c-comment"># 安装 openai 库</span>
<span class="c-func">pip</span> install openai

<span class="c-comment"># Python 代码示例</span>
<span class="c-keyword">from</span> openai <span class="c-keyword">import</span> OpenAI

client <span class="c-op">=</span> <span class="c-func">OpenAI</span>(
    base_url<span class="c-op">=</span><span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
    api_key<span class="c-op">=</span><span class="c-string">"sk-your-api-key"</span><span class="c-op">,</span>
)

<span class="c-comment"># Chat completion</span>
response <span class="c-op">=</span> client.chat.completions.<span class="c-func">create</span>(
    model<span class="c-op">=</span><span class="c-string">"claude-sonnet-4-5"</span><span class="c-op">,</span>
    messages<span class="c-op">=</span><span class="c-op">[{</span>
        <span class="c-string">"role"</span><span class="c-op">:</span> <span class="c-string">"user"</span><span class="c-op">,</span>
        <span class="c-string">"content"</span><span class="c-op">:</span> <span class="c-string">"你好，请介绍一下你自己"</span>
    <span class="c-op">}]</span><span class="c-op">,</span>
    max_tokens<span class="c-op">=</span><span class="c-num">1024</span>
)
<span class="c-func">print</span>(response.choices[<span class="c-num">0</span>].message.content)

<span class="c-comment"># 流式输出</span>
<span class="c-keyword">with</span> client.chat.completions.<span class="c-func">stream</span>(
    model<span class="c-op">=</span><span class="c-string">"claude-sonnet-4-5"</span><span class="c-op">,</span>
    messages<span class="c-op">=</span><span class="c-op">[{</span><span class="c-string">"role"</span><span class="c-op">:</span> <span class="c-string">"user"</span><span class="c-op">,</span> <span class="c-string">"content"</span><span class="c-op">:</span> <span class="c-string">"写一首诗"</span><span class="c-op">}]</span>
) <span class="c-keyword">as</span> stream:
    <span class="c-keyword">for</span> chunk <span class="c-keyword">in</span> stream:
        <span class="c-func">print</span>(chunk.choices[<span class="c-num">0</span>].delta.content <span class="c-keyword">or</span> <span class="c-string">""</span><span class="c-op">,</span> end<span class="c-op">=</span><span class="c-string">""</span><span class="c-op">,</span> flush<span class="c-op">=</span><span class="c-keyword">True</span>)</pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- cURL -->
        <div class="tool-content" id="content-curl">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">⌁ cURL</div>
              <div class="tool-desc">使用 curl 命令行直接调用 API</div>
            </div>
            <button class="copy-btn" onclick="copyCode('curl')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-curl"><span class="c-comment"># Chat Completion（标准请求）</span>
<span class="c-func">curl</span> __PUBLIC_API_URL__/v1/chat/completions 
  <span class="c-op">-</span>H <span class="c-string">"Content-Type: application/json"</span> 
  <span class="c-op">-</span>H <span class="c-string">"Authorization: Bearer sk-your-api-key"</span> 
  <span class="c-op">-</span>d <span class="c-string">'{
    "model": "claude-sonnet-4-5",
    "messages": [
      {"role": "user", "content": "你好"}
    ],
    "max_tokens": 1024
  }'</span>

<span class="c-comment"># 流式输出（SSE）</span>
<span class="c-func">curl</span> __PUBLIC_API_URL__/v1/chat/completions 
  <span class="c-op">-</span>H <span class="c-string">"Content-Type: application/json"</span> 
  <span class="c-op">-</span>H <span class="c-string">"Authorization: Bearer sk-your-api-key"</span> 
  <span class="c-op">-</span>d <span class="c-string">'{
    "model": "claude-sonnet-4-5",
    "messages": [{"role": "user", "content": "写一首诗"}],
    "stream": true
  }'</span>

<span class="c-comment"># 列出可用模型</span>
<span class="c-func">curl</span> __PUBLIC_API_URL__/v1/models 
  <span class="c-op">-</span>H <span class="c-string">"Authorization: Bearer sk-your-api-key"</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- Continue -->
        <div class="tool-content" id="content-continue">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">▶ Continue</div>
              <div class="tool-desc">配置 Continue 扩展/插件（VS Code 和 JetBrains IDE）</div>
            </div>
            <button class="copy-btn" onclick="copyCode('continue')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-continue"><span class="c-comment">// ~/.continue/config.json</span>
<span class="c-op">{</span>
  <span class="c-key">"models"</span><span class="c-op">:</span> <span class="c-op">[</span>
    <span class="c-op">{</span>
      <span class="c-key">"title"</span><span class="c-op">:</span> <span class="c-string">"Claude Sonnet 4.5"</span><span class="c-op">,</span>
      <span class="c-key">"provider"</span><span class="c-op">:</span> <span class="c-string">"openai"</span><span class="c-op">,</span>
      <span class="c-key">"model"</span><span class="c-op">:</span> <span class="c-string">"claude-sonnet-4-5"</span><span class="c-op">,</span>
      <span class="c-key">"apiBase"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
      <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span>
    <span class="c-op">},</span>
    <span class="c-op">{</span>
      <span class="c-key">"title"</span><span class="c-op">:</span> <span class="c-string">"GPT-5.4"</span><span class="c-op">,</span>
      <span class="c-key">"provider"</span><span class="c-op">:</span> <span class="c-string">"openai"</span><span class="c-op">,</span>
      <span class="c-key">"model"</span><span class="c-op">:</span> <span class="c-string">"gpt-5.4"</span><span class="c-op">,</span>
      <span class="c-key">"apiBase"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
      <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span>
    <span class="c-op">}</span>
  <span class="c-op">],</span>
  <span class="c-key">"tabAutocompleteModel"</span><span class="c-op">:</span> <span class="c-op">{</span>
    <span class="c-key">"title"</span><span class="c-op">:</span> <span class="c-string">"Codex"</span><span class="c-op">,</span>
    <span class="c-key">"provider"</span><span class="c-op">:</span> <span class="c-string">"openai"</span><span class="c-op">,</span>
    <span class="c-key">"model"</span><span class="c-op">:</span> <span class="c-string">"gpt-5.3-codex"</span><span class="c-op">,</span>
    <span class="c-key">"apiBase"</span><span class="c-op">:</span> <span class="c-string">"__PUBLIC_API_URL__/v1"</span><span class="c-op">,</span>
    <span class="c-key">"apiKey"</span><span class="c-op">:</span> <span class="c-string">"sk-your-api-key"</span>
  <span class="c-op">}</span>
<span class="c-op">}</span>

<span class="c-comment">// 适用于 VS Code 和 JetBrains IDE（IntelliJ IDEA、PyCharm 等）</span>
<span class="c-comment">// 1. 安装 Continue 扩展/插件</span>
<span class="c-comment">// 2. 打开配置文件：~/.continue/config.json</span>
<span class="c-comment">// 3. 粘贴以上配置</span>
<span class="c-comment">// 4. 重启 IDE 生效</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

        <!-- CodeGPT -->
        <div class="tool-content" id="content-codegpt">
          <div class="tool-content-header">
            <div>
              <div class="tool-name">⚙ CodeGPT</div>
              <div class="tool-desc">在 IntelliJ IDEA / PyCharm / WebStorm 中配置 CodeGPT 插件</div>
            </div>
            <button class="copy-btn" onclick="copyCode('codegpt')">
              <span>📋</span> 复制代码
            </button>
          </div>
          <div class="tool-code-wrap">
            <pre id="code-codegpt"><span class="c-comment"># CodeGPT 配置步骤（IntelliJ IDEA / PyCharm / WebStorm 等）：</span>
<span class="c-comment"># 1. 安装 CodeGPT 插件：Settings → Plugins → 搜索 "CodeGPT"</span>
<span class="c-comment"># 2. 打开设置：Settings → Tools → CodeGPT</span>
<span class="c-comment"># 3. 填写以下配置：</span>

<span class="c-key">Provider</span><span class="c-op">:</span>     <span class="c-string">Custom OpenAI</span>
<span class="c-key">API Host</span><span class="c-op">:</span>     <span class="c-string">__PUBLIC_API_URL__/v1</span>
<span class="c-key">API Key</span><span class="c-op">:</span>      <span class="c-string">sk-your-api-key</span>
<span class="c-key">Model</span><span class="c-op">:</span>        <span class="c-string">claude-sonnet-4-5</span>

<span class="c-comment"># 或在配置文件中设置（IDE 配置目录/options/codegpt.xml）：</span>
<span class="c-comment"># API Host:  __PUBLIC_API_URL__/v1</span>
<span class="c-comment"># API Key:   sk-your-api-key</span>
<span class="c-comment">#</span>
<span class="c-comment"># 支持的功能：</span>
<span class="c-comment"># - 代码补全</span>
<span class="c-comment"># - 代码解释</span>
<span class="c-comment"># - 代码重构</span>
<span class="c-comment"># - 对话问答</span></pre>
          </div>
          <div class="tools-footer">
            <div class="info-item">
              <span class="info-label">ENDPOINT</span>
              <span class="info-val endpoint">__PUBLIC_API_URL__/v1</span>
            </div>
            <div class="info-item">
              <span class="info-label">PROTOCOL</span>
              <span class="info-val protocol">OpenAI Compatible</span>
            </div>
          </div>
        </div>

      </div><!-- /tools-panel -->
    </div><!-- /tools-layout -->
  </div><!-- /section 接入工具 -->

  <!-- ===== Section 2: 模型健康度 ===== -->
  <div class="section">
  <div class="section-title models-section-title">
    <div class="icon green">📊</div>
    <h2>模型真实可用性</h2>
    <div class="refresh-indicator">
      <span class="pulse-dot"></span>
      <span id="updateTime">加载中...</span>
      <span class="refresh-note" id="refreshNote">自动探测每 30 分钟</span>
      <span class="countdown" id="countdownNum"></span>
      <button class="manual-refresh-btn" type="button" onclick="refreshNow(this)">立即刷新</button>
    </div>
    <span class="badge" id="modelCountBadge">加载中</span>
  </div>
    <div id="modelsContainer">
      <div class="loading">正在加载模型数据...</div>
    </div>
  </div>

</div><!-- /page-wrapper -->

<!-- Toast 通知 -->
<div class="toast" id="toast">
  <span class="toast-icon">✓</span>
  <span id="toastMsg">已复制</span>
</div>

<script>
const API_URL = 'api/health';
const REFRESH_INTERVAL = 1800;
let countdown = REFRESH_INTERVAL;

// ===== 工具切换 =====
function selectTool(id) {
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tool-content').forEach(c => c.classList.remove('active'));
  document.getElementById('btn-' + id).classList.add('active');
  document.getElementById('content-' + id).classList.add('active');
}

// ===== 复制代码 =====
function copyCode(toolId) {
  const pre = document.getElementById('code-' + toolId);
  const text = pre.innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector('#content-' + toolId + ' .copy-btn');
    if (btn) {
      btn.classList.add('copied');
      btn.innerHTML = '<span>✓</span> 已复制';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.innerHTML = '<span>📋</span> 复制代码';
      }, 2000);
    }
    showToast('代码已复制到剪贴板');
  }).catch(() => {
    // fallback
    const sel = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(pre);
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('copy');
    sel.removeAllRanges();
    showToast('代码已复制到剪贴板');
  });
}

// ===== 复制模型名 =====
function copyModelName(name, event, buttonEl) {
  if (event) event.stopPropagation();
  const markButton = (cls, label) => {
    if (!buttonEl) return;
    buttonEl.classList.remove('copied', 'failed');
    if (cls) buttonEl.classList.add(cls);
    buttonEl.textContent = label;
    setTimeout(() => {
      buttonEl.classList.remove('copied', 'failed');
      buttonEl.textContent = '复制';
    }, 1800);
  };

  const tryExecCommandCopy = () => {
    const ta = document.createElement('textarea');
    ta.value = name;
    ta.setAttribute('readonly', 'readonly');
    ta.style.position = 'fixed';
    ta.style.top = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    let ok = false;
    try {
      ok = !!(document.execCommand && document.execCommand('copy'));
    } catch (_) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  };

  const onCopied = () => {
    markButton('copied', '已复制');
    showToast('已复制：' + name);
  };

  const onManualCopy = () => {
    markButton('failed', '手动复制');
    window.prompt('浏览器禁止自动写入剪贴板，请手动复制下面内容：', name);
    showToast('已弹出手动复制窗口');
  };

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(name).then(onCopied).catch(() => {
      if (tryExecCommandCopy()) {
        onCopied();
      } else {
        onManualCopy();
      }
    });
    return;
  }

  if (tryExecCommandCopy()) {
    onCopied();
  } else {
    onManualCopy();
  }
}

// ===== Toast =====
let toastTimer = null;
function showToast(msg) {
  const t = document.getElementById('toast');
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2500);
}

function formatCountdown(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return mins + 'm ' + String(secs).padStart(2, '0') + 's';
}

// ===== 工具函数 =====
function formatRT(ms) {
  if (ms == null || ms === 999999) return null;
  if (ms < 1000) return ms + 'ms';
  return (ms / 1000).toFixed(1) + 's';
}

function rtClass(ms) {
  if (ms == null) return 'na';
  if (ms < 500) return 'fast';
  if (ms < 2000) return 'medium';
  return 'slow';
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ===== 生成健康条 =====
// 根据最近真实探测历史生成 30 个色块
function buildHealthBar(history) {
  const BLOCKS = 30;
  const recentHistory = Array.isArray(history) ? history.slice(-BLOCKS) : [];
  let html = '<div class="health-bar">';
  const emptyBlocks = Math.max(BLOCKS - recentHistory.length, 0);
  for (let i = 0; i < emptyBlocks; i++) {
    html += '<div class="health-block empty" title="暂无探测数据"></div>';
  }
  for (const item of recentHistory) {
    const cls = item ? 'ok' : 'fail';
    const title = item ? '真实探测成功' : '真实探测失败';
    html += `<div class="health-block ${cls}" title="${title}"></div>`;
  }
  html += '</div>';
  html += `<div class="health-bar-label"><span>最近</span><span>${recentHistory.length}次</span></div>`;
  return html;
}

// ===== 渲染模型列表 =====
function renderModels(data) {
  const meta = data.meta || {};
  const models = Object.values(data.models || {});
  models.sort((a, b) => {
    if (a.status !== b.status) return a.status === 'healthy' ? -1 : 1;
    if (a.response_time == null && b.response_time != null) return 1;
    if (a.response_time != null && b.response_time == null) return -1;
    if (a.response_time !== b.response_time) return (a.response_time || 999999) - (b.response_time || 999999);
    return a.name.localeCompare(b.name);
  });

  const healthyModels = models.filter(m => m.status === 'healthy');
  const unhealthyModels = models.filter(m => m.status !== 'healthy');

  // 更新统计
  const channelCount = (data.channels || []).length;
  document.getElementById('statTotal').textContent = models.length;
  document.getElementById('statHealthy').textContent = healthyModels.length;
  document.getElementById('statUnhealthy').textContent = unhealthyModels.length;
  document.getElementById('statChannels').textContent = channelCount;
  document.getElementById('modelCountBadge').textContent = models.length + ' 个可见模型';
  document.getElementById('updateTime').textContent =
    '更新于 ' + (data.last_update || '-') +
    ' · ' + (meta.probe_user || 'admin') +
    ' 真实探测';
  const autoInterval = meta.auto_refresh_interval || REFRESH_INTERVAL;
  document.getElementById('refreshNote').textContent =
    '自动探测每 ' + Math.max(1, Math.round(autoInterval / 60)) + ' 分钟';

  let html = '<div class="models-list">';

  function renderGroup(list, groupClass, groupLabel) {
    if (list.length === 0) return '';
    let g = `<div class="group-header ${groupClass}">
      <div class="gh-dot"></div>
      ${groupLabel}
      <span class="gh-count">${list.length} 个模型</span>
    </div>`;
    for (const m of list) {
      const total = m.total_count || 0;
      const healthy = m.healthy_count || 0;
      const badgeClass = m.status === 'healthy' ? 'full' : 'zero';
      const badgeText = m.status === 'healthy' ? '可用' : '异常';
      const probeRtStr = formatRT(m.response_time);
      const channelRtStr = formatRT(m.min_response_time);
      const checkedAt = escHtml(m.checked_at || '-');
      const errorText = m.error ? escHtml(m.error) : '';
      const encodedName = encodeURIComponent(m.name);
      const rowTitle = [
        '点击右侧复制按钮',
        '最近探测: ' + checkedAt,
        m.error ? '失败原因: ' + errorText : ''
      ].filter(Boolean).join(' | ');

      g += `<div class="model-row" title="${rowTitle}">
        <div class="health-badge ${badgeClass}">${badgeText}</div>
        <div class="model-name-wrap">
          <div class="model-name-text">${escHtml(m.name)}</div>
          <div class="model-meta-row">
            <span class="model-probe ${m.status === 'healthy' ? 'ok' : 'fail'}">
              ${m.status === 'healthy' ? '真实探测 ' + (probeRtStr || '成功') : '真实探测失败'}
            </span>
            <span class="model-channel-meta">后台渠道测试 ${healthy}/${total}</span>
            ${channelRtStr ? `<span class="model-rt ${rtClass(m.min_response_time)}">后台最快 ${channelRtStr}</span>` : ''}
          </div>
          ${m.status !== 'healthy' && errorText ? `<div class="model-error">${errorText}</div>` : ''}
        </div>
        <div class="model-actions">
          <button class="copy-model-btn" type="button" onclick="copyModelName(decodeURIComponent('${encodedName}'), event, this)">
            复制
          </button>
          <div class="ch-count">
            <span class="ch-ok">${healthy}</span><span class="ch-total">/${total}</span>
          </div>
        </div>
        <div class="health-bar-wrap">
          ${buildHealthBar(m.history)}
        </div>
      </div>`;
    }
    return g;
  }

  html += renderGroup(healthyModels, 'g-healthy', '健康模型');
  html += renderGroup(unhealthyModels, 'g-unhealthy', '异常模型');
  html += '</div>';

  document.getElementById('modelsContainer').innerHTML = html;
}

// ===== 数据获取 =====
function applyHealthData(data) {
  if (data.error) {
    const em = document.getElementById('errorMsg');
    em.textContent = '⚠ 数据获取异常: ' + data.error;
    em.style.display = 'block';
  } else {
    document.getElementById('errorMsg').style.display = 'none';
  }
  renderModels(data);
}

async function fetchData(resetCountdown = false) {
  try {
    const resp = await fetch(API_URL);
    const data = await resp.json();
    applyHealthData(data);
    if (resetCountdown) {
      countdown = REFRESH_INTERVAL;
      document.getElementById('countdownNum').textContent = formatCountdown(countdown);
    }
  } catch (e) {
    document.getElementById('errorMsg').textContent = '⚠ 无法连接监控服务: ' + e.message;
    document.getElementById('errorMsg').style.display = 'block';
    document.getElementById('updateTime').textContent = '连接失败，请检查服务状态';
  }
}

async function refreshNow(buttonEl) {
  if (buttonEl.classList.contains('loading')) return;
  const originalText = buttonEl.textContent;
  buttonEl.classList.add('loading');
  buttonEl.textContent = '刷新中...';
  try {
    const resp = await fetch('api/refresh', { cache: 'no-store' });
    const result = await resp.json();
    if (!resp.ok || !result.success) {
      throw new Error(result.message || '刷新失败');
    }
    applyHealthData(result.data);
    countdown = REFRESH_INTERVAL;
    document.getElementById('countdownNum').textContent = formatCountdown(countdown);
    showToast('已完成一次真实探测刷新');
  } catch (e) {
    showToast('刷新失败：' + e.message);
  } finally {
    buttonEl.classList.remove('loading');
    buttonEl.textContent = originalText;
  }
}

// ===== 刷新倒计时 =====
function updateCountdown() {
  countdown--;
  const el = document.getElementById('countdownNum');
  if (el) el.textContent = formatCountdown(countdown);
  if (countdown <= 0) {
    countdown = REFRESH_INTERVAL;
    fetchData(true);
  }
}

// ===== 初始化 =====
fetchData();
document.getElementById('countdownNum').textContent = formatCountdown(REFRESH_INTERVAL);
setInterval(updateCountdown, 1000);
</script>
</body>
</html>
"""
INDEX_HTML = INDEX_HTML.replace("__PUBLIC_API_URL__", PUBLIC_API_URL)


class HealthHandler(http.server.BaseHTTPRequestHandler):
    """HTTP 请求处理器"""

    # 设置较短的超时，防止连接挂起
    timeout = 10

    def log_message(self, format, *args):
        pass  # 静默日志

    def do_GET(self):
        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with data_lock:
                self.wfile.write(json.dumps(cached_data, ensure_ascii=False).encode())
        elif self.path == "/api/refresh":
            result = refresh_health_data(reason="manual", block=False)
            self.send_response(200 if result.get("success") else 409)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(result, ensure_ascii=False).encode())
        elif self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode())
        else:
            self.send_response(404)
            self.end_headers()


def main():
    print(f"[启动] 模型健康监控服务")
    print(f"  New API: {NEWAPI_BASE}")
    print(f"  拉取间隔: {POLL_INTERVAL}s")
    print(f"  监听端口: {LISTEN_PORT}")

    # 启动后台拉取线程
    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()

    # 启动 HTTP 和 HTTPS 服务
    import socketserver
    import ssl

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    # HTTP 服务
    http_server = ThreadedHTTPServer(("0.0.0.0", LISTEN_PORT), HealthHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    print(f"  HTTP:  http://0.0.0.0:{LISTEN_PORT}/")

    # HTTPS 服务
    https_server = ThreadedHTTPServer(("0.0.0.0", HTTPS_PORT), HealthHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    https_server.socket = ctx.wrap_socket(https_server.socket, server_side=True)
    print(f"  HTTPS: https://0.0.0.0:{HTTPS_PORT}/")
    https_server.serve_forever()


if __name__ == "__main__":
    main()
