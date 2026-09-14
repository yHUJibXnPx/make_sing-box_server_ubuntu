#!/usr/bin/env python3
"""
export_nodes.py

将多个代理订阅 URL / 本地文件 / stdin 中的节点解析、规范化、去重并汇聚为
sing-box outbounds JSON。

设计目标：
1. 只专注 VLESS / VMess / Trojan / TUIC / Hysteria2 / AnyTLS。
2. 尽量完整地把这些 URI 中与 sing-box 当前 outbound schema 对应的参数转换出来。
3. 不伪造 sing-box 不支持的 transport；例如 XHTTP 当前不能安全地当作稳定
   sing-box transport 输出，因此遇到 type=xhttp 时跳过并报告。
4. identity 去重：按“语义节点身份”去重，忽略 tag、内部元数据以及明显只影响
   会话调优而不改变节点身份的字段。
5. exact 去重：除 tag / 内部元数据之外，完整 sing-box 配置参与去重。
6. none：完全不去重，只保证 tag 唯一。

命令行兼容：
    python3 export_nodes.py "url1|url2|file1" nodes.json

参数：
    --dedupe {identity,exact,none}
    --tag-suffix {bracket,number}
    --report FILE
    --sing-box-version VERSION (default 1.14)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import sys
import urllib.parse
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable


SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "tuic://",
    "hysteria2://",
    "hy2://",
    "anytls://",
)

PARSER_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "tuic",
    "hysteria2",
    "hy2",
    "anytls",
}

INTERNAL_KEYS = {
    "_source",
    "_sources",
    "_original_tag",
    "_fingerprint",
    "_identity_fingerprint",
    "_exact_fingerprint",
    "_warnings",
}

# 查询参数里常见的布尔值。
TRUE_VALUES = {"1", "true", "yes", "on", "enable", "enabled"}
FALSE_VALUES = {"0", "false", "no", "off", "disable", "disabled"}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def parse_bool(val: Any, default: bool = False) -> bool:
    """把常见布尔表示转成 bool。未知值使用 default。"""
    if isinstance(val, bool):
        return val
    if val is None:
        return default
    text = str(val).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return default


def parse_int(val: Any, default: int | None = None) -> int | None:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default


def parse_float(val: Any, default: float | None = None) -> float | None:
    try:
        return float(str(val).strip())
    except (TypeError, ValueError):
        return default


def split_csv(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


def first_query(query: dict[str, str], *keys: str, default: str = "") -> str:
    for key in keys:
        if key in query and query[key] != "":
            return query[key]
    return default


def has_any(query: dict[str, str], *keys: str) -> bool:
    return any(key in query for key in keys)


def normalize_text(value: Any) -> str:
    value = urllib.parse.unquote(str(value or "")).strip()
    return " ".join(value.split())


def normalize_tag(tag: Any, fallback: str = "node") -> str:
    value = normalize_text(tag)
    return value or fallback


def normalize_server(server: Any) -> str:
    """规范化 hostname / IP，避免仅大小写或 IPv6 方括号造成去重失效。"""
    value = normalize_text(server).lower()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        value = str(ipaddress.ip_address(value))
    except ValueError:
        pass
    return value


def decode_base64_string(b64_str: str) -> str:
    """兼容标准/URL-safe Base64，并自动补 padding；失败时原样返回。"""
    text = b64_str.strip().replace("\n", "").replace("\r", "")
    if not text:
        return text

    padding = (-len(text)) % 4
    if padding:
        text += "=" * padding

    try:
        raw = base64.b64decode(text, altchars=b"-_", validate=True)
        return raw.decode("utf-8")
    except Exception:
        return b64_str


def looks_like_node_content(content: str) -> bool:
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return any(line.lower().startswith(SUPPORTED_PROTOCOLS) for line in lines)


def decode_subscription_if_needed(content: str) -> str:
    """单行且不是 URI 时尝试整体 Base64 解码。"""
    stripped = content.strip().lstrip("\ufeff")
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]

    if len(lines) != 1:
        return stripped

    line = lines[0]
    lowered = line.lower()
    if lowered.startswith(SUPPORTED_PROTOCOLS):
        return stripped

    decoded = decode_base64_string(line)
    if decoded != line and looks_like_node_content(decoded):
        return decoded

    # 极少数订阅会对整段内容再做一层 URL 编码。
    try:
        unquoted = urllib.parse.unquote(line)
        decoded = decode_base64_string(unquoted)
        if decoded != unquoted and looks_like_node_content(decoded):
            return decoded
    except Exception:
        pass

    return stripped


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _without_internal_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _without_internal_keys(item)
            for key, item in value.items()
            if key not in INTERNAL_KEYS
        }
    if isinstance(value, list):
        return [_without_internal_keys(item) for item in value]
    return value


def add_warning(node: dict[str, Any], warning: str) -> None:
    warnings = node.setdefault("_warnings", [])
    if warning not in warnings:
        warnings.append(warning)


# ---------------------------------------------------------------------------
# sing-box schema version gate
# ---------------------------------------------------------------------------

class SingBoxVersion:
    def __init__(self, value: str = "1.14") -> None:
        text = str(value or "1.14").strip().lstrip("vV")
        m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", text)
        if not m:
            raise ValueError(f"无法识别 sing-box 版本：{value!r}，例如 1.14 或 1.14.0")
        self.major = int(m.group(1))
        self.minor = int(m.group(2))
        self.patch = int(m.group(3) or 0)

    def at_least(self, major: int, minor: int, patch: int = 0) -> bool:
        return (self.major, self.minor, self.patch) >= (major, minor, patch)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def version_gate(node: dict[str, Any], version: SingBoxVersion) -> tuple[bool, str | None]:
    """检查本脚本会输出的、明确有版本门槛的字段。
    不猜测未来 schema；只对官方明确标注版本变化的字段做硬门槛。
    """
    # ================= 新增：处理 ECH 的 query_server_name 兼容性 =================
    tls = node.get("tls")
    if isinstance(tls, dict):
        ech = tls.get("ech")
        if isinstance(ech, dict) and "query_server_name" in ech:
            # sing-box 1.11.x 及以下版本不支持 query_server_name 字段
            if not version.at_least(1, 12):
                ech.pop("query_server_name", None)
                # 如果移除该字段后，ech 对象里只剩下了 "enabled": True (没有其他 config 原生配置)
                # 这会导致 sing-box 依然报错，因此直接将整个 ech 节点删掉，降级为普通 TLS
                if list(ech.keys()) == ["enabled"]:
                    tls.pop("ech", None)
    # ==============================================================================
    # 增加 AnyTLS 的版本门槛拦截
    if node.get("type") == "anytls":
        # 设定 AnyTLS 至少需要 1.12+ (或更高版本)，如果目标版本低于此，则过滤掉
        if not version.at_least(1, 12):
            return False, f"AnyTLS 协议在 sing-box {version} 中不支持，已跳过该节点。"

    if node.get("type") == "hysteria2":
        obfs = node.get("obfs")
        if obfs and not version.at_least(1, 14):
            return False, "Hysteria2 obfs 在 sing-box 1.14.0 才加入；目标版本过旧，拒绝生成语义缩水的节点。"
        if node.get("hop_interval_max") and not version.at_least(1, 14):
            return False, "Hysteria2 hop_interval_max 需要 sing-box 1.14.0+。"
        if node.get("bbr_profile") and not version.at_least(1, 14):
            return False, "Hysteria2 bbr_profile 需要 sing-box 1.14.0+。"
        if obfs and obfs.get("type") == "gecko" and (obfs.get("min_packet_size") is not None or obfs.get("max_packet_size") is not None) and not version.at_least(1, 14):
            return False, "Hysteria2 Gecko packet-size 参数需要 sing-box 1.14.0+。"
    return True, None


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------


def normalize_pin_list(value: str) -> list[str]:
    return [item for item in re.split(r"[;,\\s]+", value.strip()) if item]


def build_tls(
    query: dict[str, str],
    server: str,
    *,
    force_enabled: bool = False,
) -> dict[str, Any] | None:
    """根据 URI 查询参数构建 sing-box client TLS 配置。"""
    security = first_query(query, "security", default="").lower()

    tls_signals = {
        "tls",
        "reality",
    }
    enabled = force_enabled or security in tls_signals or has_any(
        query,
        "sni",
        "server_name",
        "allowInsecure",
        "allow_insecure",
        "insecure",
        "alpn",
        "fp",
        "fingerprint",
        "pbk",
        "public_key",
        "sid",
        "short_id",
        "pinSHA256",
        "certificate_public_key_sha256",
        "disable_sni",
        "ech",
        "ech_config",
        "min_version",
        "max_version",
        "handshake_timeout",
    )

    if not enabled:
        return None

    insecure_value = first_query(
        query,
        "allowInsecure",
        "allow_insecure",
        "insecure",
        default="0",
    )

    tls_obj: dict[str, Any] = {
        "enabled": True,
        "server_name": first_query(
            query, "sni", "server_name", default=server
        ),
        "insecure": parse_bool(insecure_value, False),
    }

    alpn = split_csv(first_query(query, "alpn", default=""))
    if alpn:
        tls_obj["alpn"] = alpn

    min_version = first_query(query, "min_version", "minVersion")
    max_version = first_query(query, "max_version", "maxVersion")
    if min_version:
        tls_obj["min_version"] = min_version
    if max_version:
        tls_obj["max_version"] = max_version

    if has_any(query, "disable_sni"):
        tls_obj["disable_sni"] = parse_bool(query.get("disable_sni"))

    fp = first_query(query, "fp", "fingerprint")
    if fp:
        tls_obj["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    pin = first_query(
        query,
        "pinSHA256",
        "pin_sha256",
        "certificate_public_key_sha256",
    )
    if pin:
        tls_obj["certificate_public_key_sha256"] = normalize_pin_list(pin)

    handshake_timeout = first_query(query, "handshake_timeout")
    if handshake_timeout:
        tls_obj["handshake_timeout"] = handshake_timeout

    # ECH
    #
    # 兼容常见订阅格式：
    #
    # 1. 动态 ECH：
    #      ech=cloudflare-ech.com+https://dns.alidns.com/dns-query
    #
    #    转换为 sing-box：
    #      "ech": {
    #        "enabled": true,
    #        "query_server_name": "cloudflare-ech.com"
    #      }
    #
    # 2. 原生 ECH CONFIGS PEM：
    #      -----BEGIN ECH CONFIGS-----
    #      ...
    #      -----END ECH CONFIGS-----
    #
    # 3. file://...：
    #      config_path
    #
    # 4. ech=true / 1：
    #      只启用 ECH，不设置 config。
    #
    # 注意：
    # sing-box 的 ech.config 必须是 PEM ECH CONFIGS，
    # 不能把 Xray 风格的 "domain+DoH" 字符串塞进去。

    ech_value = first_query(query, "ech", default="")
    ech_config = first_query(query, "ech_config", default="")
    ech_config_path = first_query(query, "ech_config_path", default="")

    if ech_config or ech_config_path or ech_value:
        ech_obj: dict[str, Any] = {"enabled": True}

        config_value = (ech_config or ech_value).strip()

        if config_value:
            lowered = config_value.lower()

            # -----------------------------------------------------------
            # 1. 纯开关：ech=true / 1
            # -----------------------------------------------------------
            if lowered in {"true", "1", "yes", "on", "enable", "enabled"}:
                pass

            # -----------------------------------------------------------
            # 2. file://...
            # -----------------------------------------------------------
            elif config_value.startswith("file://"):
                ech_obj["config_path"] = config_value.removeprefix("file://")

            # -----------------------------------------------------------
            # 3. Xray / 社区常见动态 ECH：
            #
            #    cloudflare-ech.com+https://dns.alidns.com/dns-query
            #
            # sing-box：
            #    query_server_name = cloudflare-ech.com
            #
            # DoH 地址不能写到 outbound.tls.ech，
            # 所以这里保留查询域名，DoH 后续由 sing-box DNS 配置处理。
            # -----------------------------------------------------------
            elif "+" in config_value:
                ech_name, ech_dns = config_value.split("+", 1)
                ech_name = ech_name.strip()
                ech_dns = ech_dns.strip()

                if (
                    ech_name
                    and (
                        ech_dns.startswith("https://")
                        or ech_dns.startswith("http://")
                    )
                ):
                    ech_obj["query_server_name"] = ech_name

                else:
                    # 非标准的 "+" 格式，不强制解释
                    ech_obj["config"] = [config_value]

            # -----------------------------------------------------------
            # 4. 原生 PEM ECH CONFIGS
            # -----------------------------------------------------------
            elif "-----BEGIN ECH CONFIGS-----" in config_value:
                ech_obj["config"] = [config_value]

            # -----------------------------------------------------------
            # 5. JSON
            # -----------------------------------------------------------
            else:
                try:
                    maybe_json = json.loads(config_value)

                    if isinstance(maybe_json, dict):
                        ech_obj.update(maybe_json)

                    elif isinstance(maybe_json, list):
                        ech_obj["config"] = [str(item) for item in maybe_json]

                    else:
                        ech_obj["config"] = [str(maybe_json)]

                except json.JSONDecodeError:
                    # 普通字符串不能再直接塞进 ech.config，
                    # 否则新版 sing-box 会按 PEM 解码并报：
                    # invalid ECH configs pem
                    pass

        if ech_config_path:
            ech_obj["config_path"] = ech_config_path

        tls_obj["ech"] = ech_obj

    return tls_obj


# ---------------------------------------------------------------------------
# V2Ray transports supported by sing-box
# ---------------------------------------------------------------------------


def parse_headers_from_query(query: dict[str, str]) -> dict[str, str]:
    """读取常见的 header.* / header_<name> / host 形式。"""
    headers: dict[str, str] = {}

    raw_json = first_query(query, "headers", "header_json")
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                headers.update({str(k): str(v) for k, v in parsed.items()})
        except json.JSONDecodeError:
            pass

    for key, value in query.items():
        if key.startswith("header."):
            name = key[len("header.") :]
            if name:
                headers[name] = value
        elif key.startswith("header_"):
            name = key[len("header_") :]
            if name:
                headers[name] = value

    return headers


def split_hosts(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[|,]", value) if item.strip()]


def build_transport(query: dict[str, str]) -> tuple[dict[str, Any] | None, str | None]:
    """
    返回 (transport, warning)。

    支持 sing-box V2Ray Transport：HTTP / WebSocket / QUIC / gRPC /
    HTTPUpgrade。XHTTP 明确不输出，因为当前稳定 sing-box schema 中没有可直接
    安全映射的 transport 类型。
    """
    network = first_query(query, "type", "net", "network", default="tcp").lower()

    if network in {"tcp", "none", "raw", ""}:
        return None, None

    if network in {"xhttp", "splithttp"}:
        return None, (
            "检测到 XHTTP transport；当前 sing-box 稳定 schema 不能直接以 "
            "transport.type=xhttp 输出，本脚本不会伪造配置，因此该节点被跳过。"
        )

    if network == "ws":
        transport: dict[str, Any] = {
            "type": "ws",
            "path": first_query(query, "path", default="/") or "/",
        }
        headers = parse_headers_from_query(query)
        host = first_query(query, "host", "ws_host")
        if host:
            headers.setdefault("Host", host)
        if headers:
            transport["headers"] = headers

        max_early_data = parse_int(
            first_query(query, "max_early_data", "ed", default="")
        )
        if max_early_data is not None:
            transport["max_early_data"] = max_early_data

        early_data_header_name = first_query(
            query, "early_data_header_name", "eh", default=""
        )
        if early_data_header_name:
            transport["early_data_header_name"] = early_data_header_name

        return transport, None

    if network == "http":
        transport = {
            "type": "http",
            "path": first_query(query, "path", default="/") or "/",
        }
        host_value = first_query(query, "host", "http_host", default="")
        if host_value:
            transport["host"] = split_hosts(host_value)

        method = first_query(query, "method", default="")
        if method:
            transport["method"] = method

        headers = parse_headers_from_query(query)
        if headers:
            transport["headers"] = headers

        idle_timeout = first_query(query, "idle_timeout", default="")
        ping_timeout = first_query(query, "ping_timeout", default="")
        if idle_timeout:
            transport["idle_timeout"] = idle_timeout
        if ping_timeout:
            transport["ping_timeout"] = ping_timeout

        return transport, None

    if network in {"grpc", "gun"}:
        transport = {
            "type": "grpc",
            "service_name": first_query(
                query, "serviceName", "service_name", "path", default=""
            ),
        }
        if not transport["service_name"]:
            transport["service_name"] = "TunService"

        idle_timeout = first_query(query, "idle_timeout", default="")
        ping_timeout = first_query(query, "ping_timeout", default="")
        if idle_timeout:
            transport["idle_timeout"] = idle_timeout
        if ping_timeout:
            transport["ping_timeout"] = ping_timeout

        if has_any(query, "permit_without_stream"):
            transport["permit_without_stream"] = parse_bool(
                query.get("permit_without_stream")
            )

        return transport, None

    if network == "httpupgrade":
        transport = {
            "type": "httpupgrade",
            "path": first_query(query, "path", default="/") or "/",
        }
        host = first_query(query, "host", "http_host", default="")
        if host:
            transport["host"] = host
        headers = parse_headers_from_query(query)
        if headers:
            transport["headers"] = headers
        return transport, None

    if network == "quic":
        transport = {"type": "quic"}
        security = first_query(query, "quic_security", "security", default="")
        key = first_query(query, "quic_key", "key", default="")
        if security:
            transport["security"] = security
        if key:
            transport["key"] = key
        return transport, None

    return None, f"未识别的 V2Ray transport type={network}，已跳过该节点。"


# ---------------------------------------------------------------------------
# URI parsers
# ---------------------------------------------------------------------------


def parse_vless_trojan(link: str) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(link)
    protocol = parsed.scheme.lower()
    if protocol not in {"vless", "trojan"}:
        return None
    if not parsed.hostname or not parsed.port or parsed.username is None:
        return None

    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    tag = urllib.parse.unquote(parsed.fragment) or f"{protocol}-{parsed.hostname}"

    outbound: dict[str, Any] = {
        "type": protocol,
        "tag": normalize_tag(tag, protocol),
        "server": normalize_server(parsed.hostname),
        "server_port": parsed.port,
    }

    if protocol == "vless":
        outbound["uuid"] = urllib.parse.unquote(parsed.username)
        flow = first_query(query, "flow")
        if flow:
            outbound["flow"] = flow

        packet_encoding = first_query(
            query, "packetEncoding", "packet_encoding", default=""
        )
        if packet_encoding:
            outbound["packet_encoding"] = packet_encoding
    else:
        outbound["password"] = urllib.parse.unquote(parsed.username)

    network = first_query(query, "network", "type", "net", default="tcp").lower()
    if network in {"tcp", "udp"}:
        outbound["network"] = network

    security = first_query(query, "security", default="").lower()
    tls = build_tls(query, parsed.hostname)
    if tls:
        outbound["tls"] = tls

    transport, warning = build_transport(query)
    if warning:
        # 先构造，再由上层决定是否跳过。
        outbound["_warnings"] = [warning]
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_vmess(link: str) -> dict[str, Any] | None:
    try:
        payload = link.removeprefix("vmess://")
        text = decode_base64_string(payload)
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    server = normalize_server(data.get("add") or data.get("address") or "")
    if not server:
        return None

    port = parse_int(data.get("port"), 443)
    uuid = str(data.get("id") or "").strip()
    if not uuid or port is None:
        return None

    tag = normalize_tag(
        data.get("ps") or data.get("name") or f"vmess-{server}",
        "vmess",
    )

    outbound: dict[str, Any] = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": normalize_text(data.get("scy") or data.get("security") or "auto").lower()
        or "auto",
    }

    alter_id = parse_int(data.get("aid"), 0)
    if alter_id is not None:
        outbound["alter_id"] = alter_id

    if "globalPadding" in data or "global_padding" in data:
        outbound["global_padding"] = parse_bool(
            data.get("globalPadding", data.get("global_padding")), False
        )

    if "authenticatedLength" in data or "authenticated_length" in data:
        outbound["authenticated_length"] = parse_bool(
            data.get("authenticatedLength", data.get("authenticated_length")),
            True,
        )

    network = normalize_text(data.get("net") or data.get("network") or "tcp").lower()
    if network in {"tcp", "udp"}:
        outbound["network"] = network

    packet_encoding = normalize_text(
        data.get("packetEncoding")
        or data.get("packet_encoding")
        or ""
    )
    if packet_encoding:
        outbound["packet_encoding"] = packet_encoding

    tls_type = normalize_text(data.get("tls") or "").lower()
    query: dict[str, str] = {
        "security": tls_type,
        "sni": str(data.get("sni") or data.get("host") or server),
        "allowInsecure": str(data.get("allowInsecure", "0")),
        "alpn": ",".join(data.get("alpn", []) if isinstance(data.get("alpn"), list) else split_csv(str(data.get("alpn") or ""))),
        "fp": str(data.get("fp") or ""),
        "pbk": str(data.get("pbk") or ""),
        "sid": str(data.get("sid") or ""),
    }
    if tls_type:
        tls = build_tls(query, server)
        if tls:
            outbound["tls"] = tls

    # VMess URI JSON 常见 transport 字段来自 net/path/host/type。
    transport_query = {
        "type": network,
        "path": str(data.get("path") or "/"),
        "host": str(data.get("host") or ""),
        "serviceName": str(data.get("serviceName") or ""),
        "security": str(data.get("scy") or ""),
        "key": str(data.get("key") or ""),
        "quic_security": str(data.get("type") or ""),
    }
    # VMess 的 net 是 transport type；tcp/udp 不是 V2Ray transport。
    transport_type = network
    if transport_type not in {"tcp", "udp"}:
        transport_query["type"] = transport_type
        transport, warning = build_transport(transport_query)
        if warning:
            add_warning(outbound, warning)
        if transport:
            outbound["transport"] = transport

    return outbound


def parse_tuic(link: str) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme.lower() != "tuic":
        return None
    if not parsed.hostname or not parsed.port or parsed.username is None:
        return None

    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    tag = urllib.parse.unquote(parsed.fragment) or f"tuic-{parsed.hostname}"

    outbound: dict[str, Any] = {
        "type": "tuic",
        "tag": normalize_tag(tag, "tuic"),
        "server": normalize_server(parsed.hostname),
        "server_port": parsed.port,
        "uuid": username,
        "password": password,
        "congestion_control": first_query(
            query, "congestion_control", "congestion-control", default="cubic"
        ),
    }

    udp_relay_mode = first_query(
        query, "udp_relay_mode", "udp-relay-mode", default=""
    )
    udp_over_stream = first_query(
        query, "udp_over_stream", "udp-over-stream", default=""
    )
    if udp_over_stream:
        outbound["udp_over_stream"] = parse_bool(udp_over_stream)
    elif udp_relay_mode:
        outbound["udp_relay_mode"] = udp_relay_mode
    else:
        outbound["udp_relay_mode"] = "native"

    if has_any(query, "zero_rtt_handshake", "zero-rtt-handshake"):
        outbound["zero_rtt_handshake"] = parse_bool(
            first_query(query, "zero_rtt_handshake", "zero-rtt-handshake")
        )

    heartbeat = first_query(query, "heartbeat")
    if heartbeat:
        outbound["heartbeat"] = heartbeat

    network = first_query(query, "network", default="")
    if network in {"tcp", "udp"}:
        outbound["network"] = network

    tls = build_tls(query, parsed.hostname, force_enabled=True)
    if tls:
        outbound["tls"] = tls

    # TLS 前的 ALPN / SNI / insecure 等参数都由 build_tls 处理。
    return outbound


def parse_hysteria2(link: str) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme.lower() not in {"hysteria2", "hy2"}:
        return None
    if not parsed.hostname or not parsed.port or parsed.username is None:
        return None

    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    password = urllib.parse.unquote(parsed.username)
    tag = urllib.parse.unquote(parsed.fragment) or f"hysteria2-{parsed.hostname}"

    outbound: dict[str, Any] = {
        "type": "hysteria2",
        "tag": normalize_tag(tag, "hysteria2"),
        "server": normalize_server(parsed.hostname),
        "server_port": parsed.port,
        "password": password,
    }

    # Hysteria2 URI 常见带宽参数。
    up_mbps = parse_int(first_query(query, "upmbps", "up_mbps", default=""))
    down_mbps = parse_int(first_query(query, "downmbps", "down_mbps", default=""))
    if up_mbps is not None:
        outbound["up_mbps"] = up_mbps
    if down_mbps is not None:
        outbound["down_mbps"] = down_mbps

    # 端口跳跃：兼容常见 mport/mhop 写法以及 sing-box 命名。
    server_ports = first_query(
        query, "server_ports", "server-ports", "mport", default=""
    )
    if server_ports:
        ranges = [item.strip() for item in re.split(r"[,|]", server_ports) if item.strip()]
        if ranges:
            outbound.pop("server_port", None)
            outbound["server_ports"] = ranges

    hop_interval = first_query(query, "hop_interval", "hop-interval", "mhop")
    if hop_interval:
        outbound["hop_interval"] = hop_interval

    hop_interval_max = first_query(
        query, "hop_interval_max", "hop-interval-max"
    )
    if hop_interval_max:
        outbound["hop_interval_max"] = hop_interval_max

    # Hysteria2 的 QUIC 混淆：salamander / gecko。
    # 重点处理用户特别提出的 obfs / obfs-password。
    obfs_type = first_query(query, "obfs", "obfs_type", default="").lower()
    obfs_password = first_query(query, "obfs-password", "obfs_password", default="")
    obfs_min = parse_int(first_query(query, "obfs-min-packet-size", "obfs_min_packet_size", default=""))
    obfs_max = parse_int(first_query(query, "obfs-max-packet-size", "obfs_max_packet_size", default=""))

    if obfs_type or obfs_password or obfs_min is not None or obfs_max is not None:
        obfs: dict[str, Any] = {}
        if obfs_type:
            obfs["type"] = obfs_type
        if obfs_password:
            obfs["password"] = obfs_password
        if obfs_min is not None:
            obfs["min_packet_size"] = obfs_min
        if obfs_max is not None:
            obfs["max_packet_size"] = obfs_max
        outbound["obfs"] = obfs

    network = first_query(query, "network", default="")
    if network in {"tcp", "udp"}:
        outbound["network"] = network

    bbr_profile = first_query(query, "bbr_profile", "bbr-profile", default="")
    if bbr_profile:
        outbound["bbr_profile"] = bbr_profile

    if has_any(query, "brutal_debug", "brutal-debug"):
        outbound["brutal_debug"] = parse_bool(
            first_query(query, "brutal_debug", "brutal-debug")
        )

    tls = build_tls(query, parsed.hostname, force_enabled=True)
    if tls:
        outbound["tls"] = tls

    return outbound


def parse_anytls(link: str) -> dict[str, Any] | None:
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme.lower() != "anytls":
        return None
    if not parsed.hostname or not parsed.port or parsed.username is None:
        return None

    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    password = urllib.parse.unquote(parsed.username)
    tag = urllib.parse.unquote(parsed.fragment) or f"anytls-{parsed.hostname}"

    outbound: dict[str, Any] = {
        "type": "anytls",
        "tag": normalize_tag(tag, "anytls"),
        "server": normalize_server(parsed.hostname),
        "server_port": parsed.port,
        "password": password,
    }

    tls = build_tls(query, parsed.hostname, force_enabled=True)
    if tls:
        outbound["tls"] = tls

    # AnyTLS 的常用会话参数。
    duration_keys = (
        "idle_session_check_interval",
        "idle_session_timeout",
    )
    for key in duration_keys:
        value = first_query(query, key, default="")
        if value:
            outbound[key] = value

    min_idle = parse_int(first_query(query, "min_idle_session", default=""))
    if min_idle is not None:
        outbound["min_idle_session"] = min_idle

    client_metadata = first_query(query, "client_metadata", default="")
    if client_metadata:
        outbound["client_metadata"] = client_metadata

    return outbound


PARSERS = {
    "vless": parse_vless_trojan,
    "trojan": parse_vless_trojan,
    "vmess": parse_vmess,
    "tuic": parse_tuic,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "anytls": parse_anytls,
}


# ---------------------------------------------------------------------------
# Input / parse pipeline
# ---------------------------------------------------------------------------


def process_links(content: str, sing_box_version: SingBoxVersion) -> tuple[list[dict[str, Any]], list[str]]:
    """解析一份订阅，返回 (nodes, warnings)。"""
    content = decode_subscription_if_needed(content)
    outbounds: list[dict[str, Any]] = []
    warnings: list[str] = []

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#"):
            continue

        try:
            scheme = urllib.parse.urlparse(line).scheme.lower()
            parser = PARSERS.get(scheme)
            if parser is None:
                continue

            node = parser(line)
        except (ValueError, IndexError, TypeError, UnicodeError) as exc:
            node = None
            warnings.append(f"第 {line_no} 行解析异常：{exc}")

        if not node:
            if scheme in PARSER_SCHEMES:
                warnings.append(f"第 {line_no} 行无法解析：{scheme}://")
            continue

        node_warnings = node.get("_warnings", [])
        if node_warnings:
            for warning in node_warnings:
                warnings.append(f"第 {line_no} 行：{warning}")
            # XHTTP / 未识别 transport 无法生成可靠 sing-box 配置，直接跳过。
            if any("跳过该节点" in warning for warning in node_warnings):
                continue

        ok, version_warning = version_gate(node, sing_box_version)
        if not ok:
            warnings.append(f"第 {line_no} 行：{version_warning}")
            continue

        outbounds.append(node)

    return outbounds, warnings


def read_input(source: str) -> str:
    if source == "-":
        return sys.stdin.read()

    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        request = urllib.request.Request(
            source,
            headers={
                "User-Agent": "export_nodes_singbox/3.0",
                "Accept": "text/plain, text/*, */*",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset, errors="replace")

    return Path(source).read_text(encoding="utf-8")


def split_sources(inputs: str) -> list[str]:
    return [item.strip() for item in inputs.split("|") if item.strip()]


def normalize_node(node: dict[str, Any]) -> dict[str, Any]:
    """做不会改变语义的基础规范化。"""
    node["tag"] = normalize_tag(node.get("tag"), node.get("type", "node"))

    if "server" in node:
        node["server"] = normalize_server(node["server"])

    if isinstance(node.get("server_port"), str):
        port = parse_int(node["server_port"])
        if port is not None:
            node["server_port"] = port

    # headers 名称大小写不影响 HTTP 语义；用于 exact 前统一表现。
    if isinstance(node.get("transport"), dict):
        headers = node["transport"].get("headers")
        if isinstance(headers, dict):
            normalized_headers = {
                normalize_text(key).lower(): normalize_text(value)
                for key, value in headers.items()
            }
            node["transport"]["headers"] = normalized_headers

    return node


# ---------------------------------------------------------------------------
# Fingerprints / de-duplication
# ---------------------------------------------------------------------------


def _normalize_for_fingerprint(value: Any, *, semantic: bool) -> Any:
    """递归构建稳定、语义化的 JSON 值。"""
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if key in INTERNAL_KEYS or key == "tag":
                continue
            if semantic and key in {
                "idle_session_check_interval",
                "idle_session_timeout",
                "min_idle_session",
                "client_metadata",
            }:
                # 这些字段影响会话调优/元信息，不改变节点访问身份。
                continue
            result[key] = _normalize_for_fingerprint(item, semantic=semantic)

        # headers 名称不区分大小写，value 保持原值。
        if isinstance(result.get("headers"), dict):
            result["headers"] = {
                str(k).lower(): v for k, v in result["headers"].items()
            }

        # TLS / transport 中空对象通常只是表达方式差异。
        for key in ("tls", "transport"):
            if key in result and result[key] in ({}, None):
                result.pop(key, None)

        return result

    if isinstance(value, list):
        items = [_normalize_for_fingerprint(item, semantic=semantic) for item in value]
        # ALPN 和 header list 不允许随便排序；只有纯标量 set-like 列表才排序。
        if semantic and all(isinstance(item, (str, int, float, bool)) for item in items):
            return items
        return items

    if isinstance(value, str):
        return normalize_text(value)

    return value


def semantic_identity_projection(node: dict[str, Any]) -> dict[str, Any]:
    """
    语义身份投影。

    核心原则：
      - 节点类型、服务器、端口、认证材料必须一致；
      - TLS/Reality/transport 的真实行为参数参与；
      - tag、来源、内部元数据、纯会话调优字段不参与；
      - 不使用“整份 JSON 一刀切”，减少同节点不同订阅表达方式造成的假重复。
    """
    clean = _normalize_for_fingerprint(node, semantic=True)

    if not isinstance(clean, dict):
        return {"value": clean}

    # AnyTLS 的会话级优化字段已经在递归阶段剔除。
    return clean


def node_fingerprint(node: dict[str, Any], mode: str = "identity") -> str:
    if mode not in {"identity", "exact", "none"}:
        raise ValueError(f"未知去重模式：{mode}")

    if mode == "none":
        return hashlib.sha256(
            f"{id(node)}:{node.get('tag', '')}".encode("utf-8")
        ).hexdigest()

    if mode == "identity":
        payload = semantic_identity_projection(node)
    else:
        payload = _normalize_for_fingerprint(node, semantic=False)

    return sha256_json(payload)


def add_source_metadata(node: dict[str, Any], source: str) -> None:
    sources = node.setdefault("_sources", [])
    if source not in sources:
        sources.append(source)
    node.setdefault("_original_tag", node.get("tag", ""))


def deduplicate_nodes(
    nodes: list[dict[str, Any]],
    mode: str = "identity",
) -> tuple[list[dict[str, Any]], int, dict[str, str]]:
    """
    去重并返回：unique_nodes, duplicate_count, duplicate_reason_map。

    reason_map key = survivor tag；value = identity/exact。
    """
    if mode == "none":
        for node in nodes:
            node["_identity_fingerprint"] = node_fingerprint(node, "identity")
            node["_exact_fingerprint"] = node_fingerprint(node, "exact")
            node["_fingerprint"] = node["_identity_fingerprint"]
        return nodes, 0, {}

    seen: dict[str, dict[str, Any]] = {}
    unique_nodes: list[dict[str, Any]] = []
    duplicate_count = 0
    reasons: dict[str, str] = {}

    for node in nodes:
        identity_fp = node_fingerprint(node, "identity")
        exact_fp = node_fingerprint(node, "exact")
        node["_identity_fingerprint"] = identity_fp
        node["_exact_fingerprint"] = exact_fp
        node["_fingerprint"] = identity_fp if mode == "identity" else exact_fp

        fp = node["_fingerprint"]
        existing = seen.get(fp)
        if existing is None:
            seen[fp] = node
            unique_nodes.append(node)
            continue

        duplicate_count += 1

        existing_sources = existing.setdefault("_sources", [])
        for source in node.get("_sources", []):
            if source not in existing_sources:
                existing_sources.append(source)

        survivor_tag = existing.get("tag", "")
        reason = "identity" if mode == "identity" else "exact"
        reasons[survivor_tag] = reason

        # 保留第一份节点作为主配置，但把后续节点的非内部警告并入来源节点。
        for warning in node.get("_warnings", []):
            add_warning(existing, warning)

    return unique_nodes, duplicate_count, reasons


def assign_unique_tags(
    nodes: list[dict[str, Any]],
    suffix_style: str = "bracket",
) -> int:
    used_tags: set[str] = set()
    duplicate_tag_count = 0

    for node in nodes:
        base_tag = normalize_tag(
            node.get("tag"),
            fallback=node.get("type", "node"),
        )

        if base_tag not in used_tags:
            node["tag"] = base_tag
            used_tags.add(base_tag)
            continue

        duplicate_tag_count += 1
        index = 2
        while True:
            if suffix_style == "number":
                candidate = f"{base_tag}-{index}"
            else:
                candidate = f"{base_tag} [{index}]"
            if candidate not in used_tags:
                break
            index += 1

        node["tag"] = candidate
        used_tags.add(candidate)

    return duplicate_tag_count


def build_report(
    nodes: list[dict[str, Any]],
    total_parsed: int,
    duplicate_nodes: int,
    duplicate_tags: int,
    failed_sources: list[str],
    parser_warnings: list[dict[str, Any]],
    dedupe_mode: str,
    sing_box_version: SingBoxVersion,
) -> dict[str, Any]:
    return {
        "version": 4,
        "sing_box_version": str(sing_box_version),
        "dedupe_mode": dedupe_mode,
        "total_parsed": total_parsed,
        "unique_nodes": len(nodes),
        "duplicate_nodes_removed": duplicate_nodes,
        "duplicate_tags_renamed": duplicate_tags,
        "failed_sources": failed_sources,
        "parser_warnings": parser_warnings,
        "nodes": [
            {
                "tag": node.get("tag"),
                "type": node.get("type"),
                "server": node.get("server"),
                "server_port": node.get("server_port"),
                "identity_fingerprint": node.get("_identity_fingerprint"),
                "exact_fingerprint": node.get("_exact_fingerprint"),
                "original_tag": node.get("_original_tag", node.get("tag")),
                "sources": list(node.get("_sources", [])),
                "warnings": list(node.get("_warnings", [])),
            }
            for node in nodes
        ],
    }


def clean_internal_fields(nodes: list[dict[str, Any]]) -> None:
    for node in nodes:
        for key in INTERNAL_KEYS:
            node.pop(key, None)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "将多个 VLESS/VMess/Trojan/TUIC/Hysteria2/AnyTLS 订阅解析、"  
            "去重并汇聚为 sing-box outbounds JSON"
        )
    )
    parser.add_argument(
        "inputs",
        help="多个 URL 或文件路径，用 | 分隔；- 代表从标准输入读取",
    )
    parser.add_argument(
        "output",
        help="输出 JSON 文件路径，例如 nodes.json",
    )
    parser.add_argument(
        "--dedupe",
        choices=("identity", "exact", "none"),
        default="identity",
        help="节点去重策略：identity=语义身份（默认），exact=完整配置，none=不去重",
    )
    parser.add_argument(
        "--tag-suffix",
        choices=("bracket", "number"),
        default="bracket",
        help="重复 tag 后缀风格，默认 bracket",
    )
    parser.add_argument(
        "--report",
        help="可选：输出聚合统计与节点来源报告 JSON",
    )
    parser.add_argument(
        "--sing-box-version",
        default="1.14",
        help="目标 sing-box schema 版本，默认 1.14；例如 1.14.0。只对有明确版本门槛的字段做兼容性检查。",
    )

    args = parser.parse_args()

    try:
        sing_box_version = SingBoxVersion(args.sing_box_version)
    except ValueError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    sources = split_sources(args.inputs)

    if not sources:
        print("未提供有效的输入 URL 或文件路径", file=sys.stderr)
        return 1

    all_nodes: list[dict[str, Any]] = []
    failed_sources: list[str] = []
    parser_warnings: list[dict[str, Any]] = []
    total_parsed = 0

    for source in sources:
        try:
            content = read_input(source)
            if not content.strip():
                print(f"警告：输入内容为空，已跳过：{source}", file=sys.stderr)
                continue

            nodes, warnings = process_links(content, sing_box_version)
            for warning in warnings:
                parser_warnings.append({"source": source, "warning": warning})
                print(f"警告：{source}: {warning}", file=sys.stderr)

            for node in nodes:
                normalize_node(node)
                add_source_metadata(node, source)

            all_nodes.extend(nodes)
            total_parsed += len(nodes)

            print(
                f"已处理：{source}，解析到 {len(nodes)} 个节点",
                file=sys.stderr,
            )
        except Exception as exc:
            failed_sources.append(source)
            print(
                f"警告：读取或解析失败，已跳过：{source}（{exc}）",
                file=sys.stderr,
            )

    if not all_nodes:
        print("没有成功解析到任何节点，未生成输出文件", file=sys.stderr)
        return 1

    unique_nodes, duplicate_nodes, _ = deduplicate_nodes(
        all_nodes,
        args.dedupe,
    )

    duplicate_tags = assign_unique_tags(
        unique_nodes,
        args.tag_suffix,
    )

    report_data = build_report(
        unique_nodes,
        total_parsed=total_parsed,
        duplicate_nodes=duplicate_nodes,
        duplicate_tags=duplicate_tags,
        failed_sources=failed_sources,
        parser_warnings=parser_warnings,
        dedupe_mode=args.dedupe,
        sing_box_version=sing_box_version,
    )

    clean_internal_fields(unique_nodes)

    output_data = {
        "outbounds": unique_nodes,
    }

    try:
        write_json(Path(args.output), output_data)
    except OSError as exc:
        print(f"写入输出文件失败：{exc}", file=sys.stderr)
        return 1

    print(f"已合并写入 {len(unique_nodes)} 个唯一节点到：{Path(args.output)}")
    print(
        f"统计：解析 {total_parsed}，"
        f"删除重复节点 {duplicate_nodes}，"
        f"重命名重复 tag {duplicate_tags}"
    )

    if args.report:
        try:
            write_json(Path(args.report), report_data)
            print(f"报告已写入：{Path(args.report)}")
        except OSError as exc:
            print(f"写入报告失败：{exc}", file=sys.stderr)
            return 1

    if failed_sources:
        print(
            f"警告：共有 {len(failed_sources)} 个输入源读取或解析失败。",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())