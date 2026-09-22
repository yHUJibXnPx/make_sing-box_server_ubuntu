#!/usr/bin/env bash
set -euo pipefail

# 实用技巧
#NODE_REGION_TAG=美国 bash make_sing-box_server_ubuntu.sh   # 打上"美国"标记
#bash make_sing-box_server_ubuntu.sh                       # 不设置=保持原样，12国全占位
# QUIC 系（Hysteria2 / TUIC）不走 TLS ALPN（或忽略）只关心 h3
# WS 系（VMess WS TLS）必须 http/1.1
# Reality / VLESS / Trojan ALPN 可有可无 h2 / http1.1 都行（伪装用）
#         ┌─────────────┐
#         │  WS nodes   │ → http/1.1
#         ├─────────────┤
#         │ TCP nodes   │ → h2 / multiplex
#         ├─────────────┤
#         │ QUIC nodes  │ → h3 (ignore ALPN)
#         └─────────────┘
# Reality 必须 insecure: false 
# WS + TLS 必须 alpn -> ["http/1.1"]
# =====================================================================
#  WORKDIR 改为脚本自身所在目录，避免从任意目录执行时路径乱套
# 原版: WORKDIR=$(pwd)  →  pwd 随调用目录变化，不稳定
# =====================================================================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="${SCRIPT_DIR}"
# 提前、统一将所有可能用到的二进制路径加入环境变量（只写一次，终身受益）
export PATH="${WORKDIR}/sing-boxs":"${WORKDIR}":"$PATH"

# sing-box 版本策略：默认跟随最新 testing；stable 可显式切换。
SING_BOX_CHANNEL="${SING_BOX_CHANNEL:-testing}"
SING_BOX_VERSION="${SING_BOX_VERSION:-}"

# =====================================================================
#  无依赖环境构建：自动获取静态编译版 curl
# =====================================================================
ensure_curl() {
  echo "正在检查 curl 依赖..."
  
  # 1. 检查系统自带
  if command -v curl >/dev/null 2>&1; then
    echo "✔︎ 系统已原生包含 curl"
    return 0
  fi

  # 2. 检查本地是否已经下载过
  if [ -x "${WORKDIR}/curl" ]; then
    echo "✔︎ 检测到本地独立版 curl"
    export PATH="${WORKDIR}:$PATH"
    return 0
  fi

  echo "未检测到 curl，正在自动拉取免安装静态编译版本..."

  # 确定架构映射
  local ARCH_CURL
  case "$(uname -m)" in
    x86_64|amd64) ARCH_CURL="amd64" ;;
    aarch64|arm64) ARCH_CURL="aarch64" ;;
    *) echo "不支持的架构: $(uname -m)，无法下载静态 curl"; exit 1 ;;
  esac

  # 使用静态编译项目：moparisthebest/static-curl
  #local CURL_URL="https://github.com/moparisthebest/static-curl/releases/latest/download/curl-${ARCH_CURL}"
  local CURL_URL="https://github.com/moparisthebest/static-curl/releases/download/v8.11.0/curl-${ARCH_CURL}"

  # 降级兜底方案：没有 curl 的情况下，必须依赖 wget 进行下载
  if command -v wget >/dev/null 2>&1; then
    wget -qO "${WORKDIR}/curl" "$CURL_URL"
  # 尝试利用内置脚本语言下载“静态编译版 curl”作为临时工具
  elif command -v python3 >/dev/null 2>&1; then
    echo "§ wget 不可用，尝试利用系统内置脚本环境获取静态 curl..."
    echo "☯︎ 使用 Python3 获取临时下载器..."
    python3 -c "import urllib.request; urllib.request.urlretrieve('${CURL_URL}', '${WORKDIR}/curl')" >/dev/null 2>&1
  elif command -v python >/dev/null 2>&1; then
    echo "§ Python3 不可用，尝试利用系统内置脚本环境获取静态 curl..."
    echo "☯︎ 使用 Python2 获取临时下载器..."
    python -c "import urllib; urllib.urlretrieve('${CURL_URL}', '${WORKDIR}/curl')" >/dev/null 2>&1
  elif command -v perl >/dev/null 2>&1; then
    echo "§ Python2 不可用，尝试利用系统内置脚本环境获取静态 curl..."
    echo "☯︎ 使用 Perl 获取临时下载器..."
    perl -MLWP::Simple -e "getstore('${CURL_URL}', '${WORKDIR}/curl')" >/dev/null 2>&1
  elif command -v php >/dev/null 2>&1; then
    echo "§ Perl 不可用，尝试利用系统内置脚本环境获取静态 curl..."
    echo "☯︎ 使用 PHP 获取临时下载器..."
    php -r "file_put_contents('${WORKDIR}/curl', file_get_contents('${CURL_URL}'));" >/dev/null 2>&1
  else
    echo "✘ 致命错误：系统中没有任何可用的下载工具 (curl/wget/python/perl/php)，脚本被迫终止！"
    echo "无法进行任何网络下载。请手动安装其中任意一个工具（如：wget/python/perl/php）"
    exit 1
  fi
  # 验证是否成功下载并赋予执行权限
  if [ -s "${WORKDIR}/curl" ]; then
    chmod +x "${WORKDIR}/curl"
  fi
  # 临时加入环境变量
  export PATH="${WORKDIR}:$PATH"
  
  # 验证下载是否成功运行
  if curl -V >/dev/null 2>&1; then
    echo "✔︎ 独立版 curl 拉取成功并已注入环境变量！"
  else
    echo "✘ 下载的独立版 curl 无法运行，可能是架构不匹配或文件损坏。"
    exit 1
  fi
}

# =====================================================================
#  BBR 改用内核原生 sysctl，不再下载并执行第三方脚本
# 原版: 从 github 下载 teddysun/bbr.sh 并 root 执行，无签名校验，供应链风险
# =====================================================================
enable_bbr() {
  echo "正在启用 BBR..."
  # 检查内核版本 >= 4.9
  KERNEL_MAJOR=$(uname -r | cut -d. -f1)
  KERNEL_MINOR=$(uname -r | cut -d. -f2)
  if [ "$KERNEL_MAJOR" -lt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 9 ]; }; then
    echo "警告：内核版本 $(uname -r) 低于 4.9，BBR 不可用，跳过"
    return 0
  fi
  # 写入 sysctl 配置（幂等，重复执行无害）
  if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf 2>/dev/null; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  fi
  if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null 2>&1 || true
  # 验证
  CURRENT_CC=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  echo "BBR 当前拥塞控制算法：${CURRENT_CC}"
  if [ "$CURRENT_CC" = "bbr" ]; then
    echo "BBR 启用成功"
  else
    echo "警告：BBR 启用后验证失败，当前算法为 ${CURRENT_CC}，请手动检查"
  fi
}

# 从系统读取一个真随机整数
get_true_random() {
  # 读取 /dev/urandom 的 2 个字节并转换为十进制数字
  if [ -c /dev/urandom ]; then
    od -An -N2 -tu2 /dev/urandom | tr -d ' '
  # =====================================================================
  #  修复原版 `elif [ command -v openssl ]` 永远为真的 bug
  # `[ command -v openssl ]` 把 "command -v openssl" 当字符串判断 → 永远 true
  # awk 兜底分支实际上从未被执行
  # =====================================================================
  elif command -v openssl >/dev/null 2>&1; then
    printf "%d" "0x$(openssl rand -hex 4)"
  else
    awk 'BEGIN{srand(); print int(rand()*65535)}'
  fi
}

# =====================================================================
#  函数语义修正：原名 is_port_free，但实现是端口被占用返回 0（true）
# 重命名为 is_port_in_use，语义与行为一致，避免误读
# 原有调用处逻辑本身是正确的，只改名+注释
# =====================================================================
# 检查 TCP/UDP 端口是否已被占用（被占用返回 0，空闲返回非零）
# 支持 proto: tcp | udp | both（默认 both）
is_port_in_use() {
  local port=$1
  local proto=${2:-both}

  # 参数简单校验
  [[ "$port" =~ ^[0-9]+$ ]] || { echo "invalid port: $port" >&2; return 2; }
  (( port >= 1 && port <= 65535 )) || { echo "port out of range: $port" >&2; return 2; }

  # ---------- 1. ss ----------
  if command -v ss >/dev/null 2>&1; then
    case "$proto" in
      tcp)  ss -ltn  | grep -qE ":${port}([[:space:]]|$)" ;;
      udp)  ss -lun  | grep -qE ":${port}([[:space:]]|$)" ;;
      both) ss -ltnu | grep -qE ":${port}([[:space:]]|$)" ;;
      *) return 2 ;;
    esac
    return $?
  fi

  # ---------- 2. netstat ----------
  if command -v netstat >/dev/null 2>&1; then
    case "$proto" in
      tcp)  netstat -ltn  | grep -qE ":${port}([[:space:]]|$)" ;;
      udp)  netstat -lun  | grep -qE ":${port}([[:space:]]|$)" ;;
      both) netstat -ltnu | grep -qE ":${port}([[:space:]]|$)" ;;
      *) return 2 ;;
    esac
    return $?
  fi

  # ---------- 3. lsof ----------
  if command -v lsof >/dev/null 2>&1; then
    case "$proto" in
      tcp)  lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 ;;
      udp)  lsof -nP -iUDP:"${port}"              >/dev/null 2>&1 ;;
      both) lsof -nP -i :"${port}"                >/dev/null 2>&1 ;;
      *) return 2 ;;
    esac
    return $?
  fi

  # ---------- 4. 纯 /proc 解析（无任何依赖，Docker 精简镜像兜底） ----------
  # 把十进制端口转成 4 位十六进制（大写，与 /proc 一致）
  local hex_port
  printf -v hex_port '%04X' "$port"

  _check_proc() {
    local file=$1
    # local_address 字段格式：IP:PORT（PORT 为 4 位 hex）
    # 只关心本地监听端口，所以匹配 :HEXPORT
    grep -qE ":${hex_port}[[:space:]]" "$file" 2>/dev/null
  }

  case "$proto" in
    tcp)
      _check_proc /proc/net/tcp  || _check_proc /proc/net/tcp6
      ;;
    udp)
      _check_proc /proc/net/udp  || _check_proc /proc/net/udp6
      ;;
    both)
      _check_proc /proc/net/tcp  || _check_proc /proc/net/tcp6 || \
      _check_proc /proc/net/udp  || _check_proc /proc/net/udp6
      ;;
    *) return 2 ;;
  esac
  return $?
}

# 生成同时避开现有 TCP/UDP 服务的随机端口。
# 这样 Hysteria2/TUIC 等 UDP 节点不会因为“只检查 TCP”而撞到宿主机现有服务。
gen_free_random_ports() {
  local count=${1:-6}
  local tries=0 max_tries=100
  local candidate p conflict

  while [ "$tries" -lt "$max_tries" ]; do
    tries=$((tries+1))
    candidate=$(awk -v seed=$(get_true_random) -v n="$count" 'BEGIN {
      srand(seed);
      for (i=1; i<=n; i++) {
        do { p = int(rand() * 40000) + 20000 } while (seen[p]);
        seen[p] = 1;
        printf "%d%s", p, (i<n ? " " : "\n");
      }
    }')

    conflict=0
    for p in $candidate; do
      if is_port_in_use "$p" both; then
        conflict=1
        break
      elif [ "$?" -eq 2 ]; then
        echo "✘ 无法可靠检查随机端口 ${p}，为避免误覆盖现有服务而终止。" >&2
        return 1
      fi
    done

    if [ "$conflict" -eq 0 ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  echo "✘ 连续 ${max_tries} 次都无法找到 ${count} 个空闲随机端口。" >&2
  return 1
}

# 获取 VPS 对外身份（优先返回绑定的域名，否则返回公网IP）
get_vps_identity() {
    local domain=""
    local ip=""

    set +e
    domain=$(curl -s --connect-timeout 4 -m 6 http://169.254.169.254/latest/meta-data/public-hostname 2>/dev/null)
    set -e
    if [ -n "$domain" ] && [ "$domain" != "404" ]; then
        case "$domain" in 
            *"Not Found"*) ;;
            *) echo "$domain"; return 0 ;;
        esac
    fi

    set +e
    domain=$(curl -s --connect-timeout 3 -m 5 http://169.254.169.254/2009-04-04/meta-data/hostname 2>/dev/null ||
             curl -s --connect-timeout 3 -m 5 http://169.254.169.254/latest/meta-data/hostname 2>/dev/null)
    set -e
    if [ -n "$domain" ] && [ "$domain" != "404" ]; then
        echo "$domain"
        return 0
    fi

    set +e
    ip=$(curl -s -4 --connect-timeout 4 ifconfig.me 2>/dev/null ||
         curl -s -4 --connect-timeout 4 icanhazip.com 2>/dev/null ||
         curl -s -4 --connect-timeout 4 ip.sb)
    set -e
    if [ -n "$ip" ]; then
        domain=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF}' | sed 's/\.$//')
        if [ -n "$domain" ]; then
            case "$domain" in 
                *"not found"*) ;;
                *) echo "$domain"; return 0 ;;
            esac
        fi
    fi

    echo "${ip:-$(curl -s -4 --connect-timeout 5 ifconfig.me || echo "无法获取公网IP")}"
}

# 函数：尝试获取网页内容
fetchPageContent() {
  GITHUB_URI=$1
  PAGE_CONTENT=""
  i=1
  while [ "$i" -le 5 ]; do
    set +e
    PAGE_CONTENT=$(curl -sL "${GITHUB_URI}")
    set -e
    if [ -n "${PAGE_CONTENT}" ]; then
      break
    fi
    echo "尝试获取网页内容失败，重试第 $i 次..."
    sleep 2
    i=$((i+1))
  done
  echo "${PAGE_CONTENT}"
}

# 函数：确保成功获取到网页内容
ensurePageContent() {
  PAGE_CONTENT=$1
  if [ -z "${PAGE_CONTENT}" ]; then
    echo "无法获取网页内容，请稍后再试。"
    exit 1
  fi
}

# 下载 sing-box cloudflared jq 等配置并启用
downloadAndBuild() {
  URI=$1
  GITHUB_URI="https://github.com/${URI}"
  FILENAME=$(basename "${GITHUB_URI}")
  SYS_NAME=$(uname -s)
  MACHINE_OS=$(echo "$SYS_NAME" | tr '[:upper:]' '[:lower:]')

  ARCH_NAME=$(uname -m)
  case "$ARCH_NAME" in
    aarch64|arm64) MACHINE_ARCH="arm64" ;;
    x86_64|amd64) MACHINE_ARCH="amd64" ;;
    *) echo '没有可以支持的架构'; exit 1 ;;
  esac

  # 使用 GitHub Releases API，避免网页结构变化导致把 alpha/beta 当 stable。
  if [ "$FILENAME" = "sing-box" ]; then
    if [ -n "$SING_BOX_VERSION" ]; then
      VERSION="$SING_BOX_VERSION"
    else
      set +e
      RELEASE_JSON=$(curl -fsSL --retry 3 --connect-timeout 8 --max-time 20 \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "https://api.github.com/repos/${URI}/releases?per_page=30")
      rc=$?
      set -e
      VERSION=""
      if [ $rc -eq 0 ] && [ -n "$RELEASE_JSON" ]; then
        if [ "$SING_BOX_CHANNEL" = "stable" ]; then
          VERSION=$(printf '%s' "$RELEASE_JSON" | jq -r '[.[] | select(.draft == false and .prerelease == false) | .tag_name][0] // empty')
        else
          VERSION=$(printf '%s' "$RELEASE_JSON" | jq -r '[.[] | select(.draft == false) | .tag_name][0] // empty')
        fi
      fi
    fi

    if [ -z "$VERSION" ]; then
      echo "无法确定 sing-box 版本，请设置 SING_BOX_VERSION。" >&2
      exit 1
    fi

    echo "sing-box channel=${SING_BOX_CHANNEL}, version=${VERSION}"
    V_NUM=$(echo "${VERSION}" | sed 's/^v//')
    FULL_URL="${GITHUB_URI}/releases/download/${VERSION}/${FILENAME}-${V_NUM}-${MACHINE_OS}-${MACHINE_ARCH}.tar.gz"
    echo "${FULL_URL}"
    curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o "${WORKDIR}/${FILENAME}".tar.gz "${FULL_URL}"
    tar zxvf "${WORKDIR}/${FILENAME}".tar.gz
    rm -frv "${WORKDIR}/${FILENAME}s"
    mv -fv "${WORKDIR}/${FILENAME}-${V_NUM}-${MACHINE_OS}-${MACHINE_ARCH}" "${WORKDIR}/${FILENAME}s"
    chmod -v +x "${WORKDIR}/${FILENAME}s/${FILENAME}"
    rm -fv "${WORKDIR}/${FILENAME}".tar.gz
    printf '%s\n' "${VERSION}" > "${WORKDIR}/sing-box.version"
    return 0
  fi

  # 其他工具继续使用 release 页面提取稳定 tag，避免安装 jq 时形成循环依赖。
  PAGE_CONTENT=$(fetchPageContent "${GITHUB_URI}/releases")
  ensurePageContent "${PAGE_CONTENT}"
  # 替换原有的 PAGE_CONTENT 和 grep 解析逻辑：
  VERSION=$(curl -sIL -o /dev/null -w "%{url_effective}" "https://github.com/${URI}/releases/latest" | awk -F'/' '{print $NF}')

  [ -n "${VERSION}" ] || { echo "无法找到 ${URI} release 版本" >&2; exit 1; }
  echo "获取到 ${URI} 最新版本 Tag: ${VERSION}"

  case ${FILENAME} in
    cloudflared)
      case ${MACHINE_OS} in
        linux)
          FULL_URL="${GITHUB_URI}/releases/download/${VERSION}/${FILENAME}-${MACHINE_OS}-${MACHINE_ARCH}"
          rm -fv "${WORKDIR}/${FILENAME}"
          curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o "${WORKDIR}/${FILENAME}" "${FULL_URL}"
          chmod -v +x "${WORKDIR}/${FILENAME}"
          ;;
        darwin)
          FULL_URL="${GITHUB_URI}/releases/download/${VERSION}/${FILENAME}-${MACHINE_OS}-${MACHINE_ARCH}.tgz"
          rm -fv "${WORKDIR}/${FILENAME}" "${WORKDIR}/${FILENAME}".tgz
          curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o "${WORKDIR}/${FILENAME}".tgz "${FULL_URL}"
          tar zxvf "${WORKDIR}/${FILENAME}".tgz -C "${WORKDIR}/"
          chmod -v +x "${WORKDIR}/${FILENAME}"
          rm -fv "${WORKDIR}/${FILENAME}".tgz
          ;;
        *) echo "不支持"; exit 1 ;;
      esac
      ;;
    jq)
      case ${MACHINE_OS} in
        linux)
          # 适配 jq 的 release 命名规范
          FULL_URL="${GITHUB_URI}/releases/download/${VERSION}/jq-${MACHINE_OS}-${MACHINE_ARCH}"
          rm -fv "${WORKDIR}/${FILENAME}"
          curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o "${WORKDIR}/${FILENAME}" "${FULL_URL}"
          chmod -v +x "${WORKDIR}/${FILENAME}"
          ;;
        *) echo "不支持"; exit 1 ;;
      esac
      ;;
  esac
}

downloadFile() {
  echo "正在安装 jq..."
  if command -v jq >/dev/null 2>&1; then
    echo "jq 已存在，跳过安装"
  elif [ -f "${WORKDIR}/jq" ]; then
    echo "jq 二进制文件已存在于 ${WORKDIR}/jq"
  else
    echo "正在下载 jq (二进制模式)..."
    downloadAndBuild "jqlang/jq"
  fi
  downloadAndBuild "SagerNet/sing-box"
  downloadAndBuild "cloudflare/cloudflared"
}

# 第一优先级：先搞定网络下载工具 curl
ensure_curl

# 检查环境
if [ -d "${WORKDIR}/sing-boxs" ] && [ -f "${WORKDIR}/cloudflared" ] && ( command -v curl >/dev/null 2>&1 ) && ( command -v jq >/dev/null 2>&1 || [ -f "${WORKDIR}/jq" ] ); then
  echo '无需下载，已经存在'
else
  downloadFile
fi

# 开启 BBR
set +e
enable_bbr
set -e

echo "正在同步服务器时间..."
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-ntp true || true
else
  ntpdate pool.ntp.org 2>/dev/null || echo "无法同步时间或容器环境无法同步，仅显示，请手动检查 date"
fi
echo "当前服务器时间: $(date)"
if [ -f "${WORKDIR}/sing-box.version" ]; then
  SING_BOX_ACTUAL_VERSION="$(tr -d "[:space:]" < "${WORKDIR}/sing-box.version")"
else
  SING_BOX_ACTUAL_VERSION="$("${WORKDIR}/sing-boxs/sing-box" version 2>/dev/null | awk 'NR==1 {print $3}' || true)"
fi
SING_BOX_ACTUAL_VERSION="${SING_BOX_ACTUAL_VERSION:-unknown}"
# 仅用于日志与「服务端能否用 obfs」底线检查；不参与客户端 schema 分支
_SB_VER="${SING_BOX_ACTUAL_VERSION#v}"
_SB_VER="${_SB_VER#V}"
echo "当前 sing-box 版本：${SING_BOX_ACTUAL_VERSION}"

# 服务端功能底线：Hysteria2 obfs 等需要 1.14+
if ! printf '%s\n' "${_SB_VER}" | grep -qE '^1\.(1[4-9]|[2-9][0-9])([.]|$)|^([2-9])([.]|$)'; then
  echo "✘ 当前 sing-box ${SING_BOX_ACTUAL_VERSION} 低于 1.14.0；本脚本的 Hysteria2 obfs 配置要求 1.14.0+。" >&2
  echo "  请使用默认 testing，或设置 SING_BOX_VERSION=v1.14.0-beta.4（以后可换成 1.14+ stable）。" >&2
  exit 1
fi

# ==================== sing-box 版本/Schema 说明 ====================
# 默认 testing：使用当前最新 1.14.x 预发布系列。稳定环境可设置：
#   SING_BOX_CHANNEL=stable bash make_sing-box_server_ubuntu_v2.sh
# 或固定：
#   SING_BOX_VERSION=v1.14.0-beta.4 bash make_sing-box_server_ubuntu_v2.sh
# Hysteria2 obfs 使用 sing-box 1.14+ 原生结构；XHTTP 不伪造。
# ===============================================================
# ==================== 配置区 ====================
export PATH=$PATH:"${WORKDIR}/sing-boxs":"${WORKDIR}/"

# ==================== 函数 ====================
gen_uuid()     { sing-box generate uuid; }

# =====================================================================
#  gen_password 改用 hex，输出长度固定 24 位
# 原版: openssl rand -base64 9 | tr -dc 'a-zA-Z0-9'
#   base64(9B)=12字符，过滤后随机剩 4~10 字符，极端情况密码很短
# =====================================================================
gen_password() { openssl rand -hex 12; }

gen_short_id() {
  rand_val=$(get_true_random)
  bytes=$((rand_val % 7 + 2))
  openssl rand -hex "$bytes" | tr '[:upper:]' '[:lower:]'
}

gen_many_short_ids() {
  if [ -n "${1:-}" ]; then count=$1; else 
    rand_val=$(get_true_random)
    count=$((rand_val % 5 + 4))
  fi
  json_list="["
  i=0
  while [ $i -lt $count ]; do
    id=$(gen_short_id)
    if [ $i -eq 0 ]; then
      json_list="${json_list}\"${id}\""
    else
      json_list="${json_list},\"${id}\""
    fi
    i=$((i+1))
  done
  json_list="${json_list}]"
  echo "$json_list"
}

# ==================== 变量区 ====================
echo "正在获取服务器IP..."
set +e
SERVER_IP=$(get_vps_identity 2>&1 || echo "NULL.NULL.NULL.NULL")
set -e
echo "VPS Domain/IP：$SERVER_IP"

# 测速候选域名列表
HANDSHAKE_CANDIDATES="prod.us-east-1.ui.gcr-chat.marketing.aws.dev
img-prod-cms-rt-microsoft-com.akamaized.net
gray-config-prod.api.cdn.arcpublishing.com
gray.video-player.arcpublishing.com
res.public.onecdn.static.microsoft
downloaddispatch.itunes.apple.com
i7158c100-ds-aksb-a.akamaihd.net
gray-config-prod.api.arc-cdn.net
ms-python.gallerycdn.vsassets.io
ms-vscode.gallerycdn.vsassets.io
location-services-prd.tesla.com
vscjava.gallerycdn.vsassets.io
d3agakyjgjv5i8.cloudfront.net
a.b.cdn.console.awsstatic.com
prod.pa.cdn.uis.awsstatic.com
github.gallerycdn.vsassets.io
cdn-dynmedia-1.microsoft.com
store-images.s-microsoft.com
amp-api-edge.apps.apple.com
prod.log.shortbread.aws.dev
visualstudio.microsoft.com
gray-wowt-prod.gtv-cdn.com
configuration.ls.apple.com
services.digitaleast.mobi
tag-logger.demandbase.com
www.google-analytics.com
publisher.liveperson.net
se-edge.itunes.apple.com
iosapps.itunes.apple.com
downloadmirror.intel.com
d.impactradius-event.com
digitalassets.tesla.com
fpinit.itunes.apple.com
s7mbrstream.scene7.com
devblogs.microsoft.com
api.company-target.com
static.cloud.coveo.com
ds-aksb-a.akamaihd.net
assets-xbxweb.xbox.com
cua-chat-ui.tesla.com
cdn77.api.userway.org
s.company-target.com
munchkin.marketo.net
gsp-ssl.ls.apple.com
consent.trustarc.com
catalog.gamepass.com
cdnssl.clicktale.net
acctcdn.msftauth.net
intelcorp.scene7.com
electronics.sony.com
is1-ssl.mzstatic.com
res-1.cdn.office.net
lpcdn.lpsnmedia.net
assets.adobedtm.com
d.oracleinfinity.io
aadcdn.msftauth.net
azure.microsoft.com
logx.optimizely.com
assets-www.xbox.com
tag.demandbase.com
ts2.tc.mm.bing.net
t0.m.awsstatic.com
polyfill-fastly.io
d0.m.awsstatic.com
ce.mf.marsflag.com
ts1.tc.mm.bing.net
d2c.aws.amazon.com
ts3.tc.mm.bing.net
ts4.tc.mm.bing.net
beacon.gtv-pub.com
statici.icloud.com
c.s-microsoft.com
vs.aws.amazon.com
images.nvidia.com
s.mp.marsflag.com
www.microsoft.com
sisu.xboxlive.com
apps.mzstatic.com
go.microsoft.com
a0.awsstatic.com
mscom.demdex.net
s0.awsstatic.com
d1.awsstatic.com
download.amd.com
cdn.userway.org
ocsp2.apple.com
cdn.bizible.com
tags.tiqcdn.com
s.go-mpulse.net
cdn.bizibly.com
drivers.amd.com
aws.amazon.com
snap.licdn.com
www.nvidia.com
c.marsflag.com
apps.apple.com
www.icloud.com
www.oracle.com
www.xilinx.com
www.tesla.com
www.intel.com
www.apple.com
www.wowt.com
xp.apple.com
www.bing.com
rum.hlx.page
www.sony.com
www.xbox.com
ipv6.6sc.co
www.aws.com
www.amd.com
th.bing.com
r.bing.com
intel.com
b.6sc.co
j.6sc.co
c.6sc.co
aws.com
amd.com"

# 测速选 handshake domain（同时验证 TLS 1.3，Reality 必须要求）
echo "测速并验证 Reality handshake 域名（需支持 TLS 1.3）..."
MIN_LAT=999999
BEST_DOMAIN=""

# 验证域名是否支持 TLS 1.3
verify_tls13() {
  local DOMAIN_T="$1"

  # 防呆设计：检查域名是否为空
  if [ -z "$DOMAIN_T" ]; then
    return 1
  fi

  # =========================================================
  # 1. 优先尝试使用 curl 验证
  # =========================================================
  if command -v curl >/dev/null 2>&1; then
    # 纯本地检查：看 curl 的帮助文档是否包含 tlsv1.3 参数
    if curl --help all 2>/dev/null | grep -q -- "--tlsv1.3"; then
      # --tls-max 1.3 和 --tlsv1.3 配合，强制只允许 TLS 1.3 握手
      # 我们不关心 HTTP 状态码，只要 curl 命令退出码为 0，就说明 TLS 隧道建立成功
      if curl -s -o /dev/null --tlsv1.3 --tls-max 1.3 --connect-timeout 3 "https://${DOMAIN_T}/"; then
        return 0
      else
        # curl 可能因为网络波动失败，不直接 return 1，而是放行让下游的 openssl 继续兜底测试
        true 
      fi
    fi
  fi

  # =========================================================
  # 2. curl 不可用或测试失败，回退到 openssl 验证
  # =========================================================
  if command -v openssl >/dev/null 2>&1; then
    local TLSOUT
    # 修复隐患：添加 -servername 开启 SNI 支持
    # 优化写法：使用 echo "Q" 直接安全退出交互，不再依赖外部的 timeout 命令
    TLSOUT=$(echo "Q" | openssl s_client -connect "${DOMAIN_T}:443" -servername "${DOMAIN_T}" -tls1_3 2>/dev/null)
    
    # 不依赖 -brief 参数（旧版 openssl 不支持），直接在标准输出中抓取协议版本
    if echo "$TLSOUT" | grep -qi "TLSv1.3"; then
      return 0
    else
      return 1
    fi
  fi

  # =========================================================
  # 3. 极端情况：没有任何二进制工具，跳过验证
  # =========================================================
  # 打印到标准错误输出 (stderr)，避免污染原本的标准输出日志
  echo "警告: 系统缺失 curl 或 openssl，跳过 TLSv1.3 严格验证" >&2
  return 0
}

echo "正在测速候选域名（全量遍历，寻找最低延迟）..."
MIN_LAT=999999
BEST_DOMAIN=""

while IFS= read -r domain || [ -n "$domain" ]; do
  [ -z "$domain" ] && continue
  
  # 临时关闭严苛模式，防止 curl 超时报错直接炸毁脚本
  set +e
  # 增加 --max-time 3 限制，防止国内网络环境 DNS 解析死等
  lat=$(curl -o /dev/null -s -w "%{time_appconnect}" --connect-timeout 2 --max-time 3 "https://${domain}/" 2>/dev/null | awk '{if($1==0){print 999999}else{printf "%d", $1*1000}}')
  set -e
  
  # 防御性判断：如果由于极特殊原因 awk 返回空值，兜底为 999999
  if [ -z "$lat" ]; then
    lat=999999
  fi

  if [ "$lat" -eq 999999 ]; then
    echo "${domain}: timeout/failed"
    continue
  fi
  
  # 只对延迟比当前最优更低的域名才做 TLS 1.3 验证（减少不必要的验证耗时）
  if [ "$lat" -lt "$MIN_LAT" ]; then
    set +e
    verify_tls13 "$domain"
    tls_ok=$?
    set -e
    
    if [ "$tls_ok" -eq 0 ]; then
      # 粗测 Certificate 是否过大（Reality 硬限约 8192；此处用叶证书 DER 体积做启发式）
      cert_ok=1
      if command -v openssl >/dev/null 2>&1; then
        set +e
        cert_len=$(echo "Q" | openssl s_client -connect "${domain}:443" -servername "${domain}" -tls1_3 2>/dev/null \
          | openssl x509 -outform DER 2>/dev/null | wc -c | tr -d '[:space:]')
        set -e
        # DER 叶证书常小于 TLS Certificate 记录；>5500 时倾向跳过（含大 OCSP/长链风险）
        if [ -n "$cert_len" ] && [ "$cert_len" -gt 5500 ] 2>/dev/null; then
          echo "${domain}: ${lat} ms ✔︎ TLS1.3 但证书偏大(${cert_len}B)，跳过"
          cert_ok=0
        fi
      fi
      if [ "$cert_ok" -eq 1 ]; then
        echo "${domain}: ${lat} ms ✔︎ TLS1.3 (当前最优)"
        MIN_LAT=$lat
        BEST_DOMAIN=$domain
      fi
    else
      echo "${domain}: ${lat} ms ✗ 不支持TLS1.3，跳过"
    fi
  else
    echo "${domain}: ${lat} ms (慢于当前最优，跳过验证)"
  fi
done <<< "$HANDSHAKE_CANDIDATES"

echo "--------------------------------"
if [ -n "$BEST_DOMAIN" ] && [ "$MIN_LAT" -ne 999999 ]; then
  echo "最快且支持TLS1.3的域名: ${BEST_DOMAIN}"
  echo "延迟: ${MIN_LAT} ms"
else
  echo "警告：未找到支持TLS1.3的域名，使用 gateway.icloud.com 作为默认值"
  BEST_DOMAIN="gateway.icloud.com"
fi

# 生成 reality keypair
KEYPAIR=$(sing-box generate reality-keypair)
PRIVATE_KEY=$(echo "$KEYPAIR" | grep 'PrivateKey' | awk '{print $2}' | tr -d '[:space:]')
PUBLIC_KEY=$(echo "$KEYPAIR" | grep 'PublicKey' | awk '{print $2}' | tr -d '[:space:]')

if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
  echo "错误：无法生成 Reality 密钥。"
  exit 1
fi

INBOUND_HYSTERIA2="hysteria2-in"
INBOUND_TUIC="tuic-in"
INBOUND_VLESS="vless-in"
INBOUND_TROJAN="trojan-in"
INBOUND_ANYTLS="anytls-in"
INBOUND_VMESS_REALITY="vmess-reality-in"
INBOUND_VMESS_WS_TLS="vmess-ws-tls-in"
#INBOUND_VMESS_WS="vmess-ws-in"
INBOUND_VLESS_WS="vless-ws-in"

# ── 节点地区前缀 ─────────────────────────────────────────────
# 用来让下面 8 个真实协议 tag（以及 Cloudflare 中转 tag）在"生成时"
# 就带上地区标记，好让脚本末尾的分组分类器（GROUPS_PATTERNS）能匹配到。
# 通过环境变量指定，例如：
#   NODE_REGION_TAG=美国 bash make_sing-box_server_ubuntu.sh
# 不设置则保持空字符串，效果等同于以前——8个 tag 仍是纯英文，
# 对应的国家 urltest 组继续占位指向 直连_，不会被误分类。
# 注意：这里只是"当次生成"时拼进 tag 里，不会像 sed -i 改脚本源码
# 那样越跑越多、也不用在换地区前手动还原脚本。
NODE_REGION_TAG="${NODE_REGION_TAG:-}"

OUTBOUND_HYSTERIA2="${NODE_REGION_TAG}hysteria2-out-$(gen_uuid | tr -d '-')"
OUTBOUND_TUIC="${NODE_REGION_TAG}tuic-out-$(gen_uuid | tr -d '-')"
OUTBOUND_VLESS="${NODE_REGION_TAG}vless-out-$(gen_uuid | tr -d '-')"
OUTBOUND_TROJAN="${NODE_REGION_TAG}trojan-out-$(gen_uuid | tr -d '-')"
OUTBOUND_ANYTLS="${NODE_REGION_TAG}anytls-out-$(gen_uuid | tr -d '-')"
OUTBOUND_VMESS_REALITY="${NODE_REGION_TAG}vmess-reality-out-$(gen_uuid | tr -d '-')"
OUTBOUND_VMESS_WS_TLS="${NODE_REGION_TAG}vmess-ws-tls-out-$(gen_uuid | tr -d '-')"
#OUTBOUND_VMESS_WS="vmess-ws-out-$(gen_uuid | tr -d '-')"
OUTBOUND_VLESS_WS="${NODE_REGION_TAG}vless-ws-out-$(gen_uuid | tr -d '-')"

FINGERPRINT_TYPE="firefox"

# 生成随机值
UUID_VLESS=$(gen_uuid)
UUID_TUIC=$(gen_uuid)
UUID_VMESS_REALITY=$(gen_uuid)
UUID_VMESS_WS_TLS=$(gen_uuid)
#UUID_VMESS_WS=$(gen_uuid)
UUID_VLESS_WS=$(gen_uuid)

# 生成密码
PASSWORD_HYSTERIA2=$(gen_password) 
PASSWORD_TUIC=$(gen_password) 
PASSWORD_TROJAN=$(gen_password) 
PASSWORD_ANYTLS=$(gen_password)
HY2_OBFS_TYPE="${HY2_OBFS_TYPE:-salamander}"
HY2_OBFS_PASSWORD="${HY2_OBFS_PASSWORD:-$(gen_password)}"

SHORT_IDS_VLESS=$(gen_many_short_ids)
SHORT_IDS_TROJAN=$(gen_many_short_ids)
SHORT_IDS_ANYTLS=$(gen_many_short_ids)
SHORT_IDS_VMESS_REALITY=$(gen_many_short_ids)

pick_random_short_id() {
  json_str=$1
  len=$(echo "$json_str" | jq 'length')
  rand_val=$(get_true_random)
  idx=$((rand_val % len))
  echo "$json_str" | jq -r ".[$idx]"
}

SHORT_ID_VLESS=$(pick_random_short_id "$SHORT_IDS_VLESS")
SHORT_ID_TROJAN=$(pick_random_short_id "$SHORT_IDS_TROJAN")
SHORT_ID_ANYTLS=$(pick_random_short_id "$SHORT_IDS_ANYTLS")
SHORT_ID_VMESS_REALITY=$(pick_random_short_id "$SHORT_IDS_VMESS_REALITY")

PATH_VMESS_WS_TLS=$(sing-box generate rand --hex 6)
#PATH_VMESS_WS=$(sing-box generate rand --hex 6)
PATH_VLESS_WS=$(sing-box generate rand --hex 6)

# 一次性为协议节点生成 6 个互不重复、同时避开现有 TCP/UDP 服务的随机端口
ALL_RANDOM_PORTS=$(gen_free_random_ports 6)

PORT_VLESS=$(echo $ALL_RANDOM_PORTS | awk '{print $1}')
PORT_TROJAN=$(echo $ALL_RANDOM_PORTS | awk '{print $2}')
PORT_ANYTLS=$(echo $ALL_RANDOM_PORTS | awk '{print $3}')
PORT_VMESS_REALITY=$(echo $ALL_RANDOM_PORTS | awk '{print $4}')
#PORT_VMESS_WS=$(echo $ALL_RANDOM_PORTS | awk '{print $5}')
PORT_VLESS_WS=$(echo $ALL_RANDOM_PORTS | awk '{print $5}')

# =====================================================================
# 端口策略（混合固定+随机）：
# TCP 443(占用则随机) → VMess WS TLS            （Cloudflare CDN 回源必须走 443/8443/2053）
# UDP 443(占用则随机) → TUIC                    （UDP 443 与 TCP 443 是完全独立的 socket，不冲突）
# TCP 随机: Vless-Reality | UDP随机: Hysteria2  （TCP/UDP共用，其实 Reality 伪装够强，端口不重要）
# TCP 随机 → Trojan/AnyTLS/VMess Reality       （Reality 伪装够强，端口不重要）
#
# 注：TCP 443 和 UDP 443 在操作系统层面是两个独立 socket，
#     sing-box 可以同时监听，不会冲突，这是正确设计。
# =====================================================================
# HYSTERIA2 使用 UDP 端口（与 vless+reality 使用 TCP 端口 互不冲突）
PORT_HYSTERIA2=${PORT_VLESS}
echo "UDP ${PORT_HYSTERIA2} → Hysteria2（UDP/TCP Hysteria2/Vless ${PORT_VLESS} 是独立 socket，无冲突）"

if is_port_in_use 443 tcp; then
  echo "警告：TCP 443 端口已被占用！VMess WS TLS 将使用随机端口"
  PORT_VMESS_WS_TLS=$(echo $ALL_RANDOM_PORTS | awk '{print $6}')
else
  PORT_VMESS_WS_TLS=443
fi
# TUIC 使用 UDP 端口；虽然 TCP/UDP 可共用数字端口，但仍必须确认 UDP socket 本身没有被占用。
PORT_TUIC=${PORT_VMESS_WS_TLS}
if is_port_in_use "${PORT_TUIC}" udp; then
  echo "警告：UDP ${PORT_TUIC} 已被占用，TUIC 将改用第 6 个随机端口"
  PORT_TUIC=$(echo "$ALL_RANDOM_PORTS" | awk '{print $6}')
  if is_port_in_use "${PORT_TUIC}" udp; then
    echo "✘ TUIC 候选 UDP 端口 ${PORT_TUIC} 仍被占用，终止。" >&2
    exit 1
  fi
fi
echo "UDP ${PORT_TUIC} → TUIC（TCP/UDP TUIC/Vmess ${PORT_VMESS_WS_TLS} 可共用数字端口）"

# =====================================================================
#  自动放行防火墙规则（ufw）
# 原版不开端口，部署后节点全部连不上
# =====================================================================
open_firewall_ports() {
  if ! command -v ufw >/dev/null 2>&1; then
    echo "未检测到 ufw，跳过防火墙配置（请手动放行下列端口）"
    echo ufw allow "${PORT_HYSTERIA2}/udp"     comment "sing-box hysteria2"
    echo ufw allow "${PORT_TUIC}/udp"          comment "sing-box tuic UDP${PORT_TUIC}"
    echo ufw allow "${PORT_TROJAN}/tcp"        comment "sing-box trojan-reality"
    echo ufw allow "${PORT_ANYTLS}/tcp"        comment "sing-box anytls-reality"
    echo ufw allow "${PORT_VLESS}/tcp"         comment "sing-box vless-reality"
    echo ufw allow "${PORT_VMESS_REALITY}/tcp" comment "sing-box vmess-reality"
    echo ufw allow "${PORT_VMESS_WS_TLS}/tcp"  comment "sing-box vmess-ws-tls TCP${PORT_VMESS_WS_TLS}"
    #echo ufw allow "${PORT_VMESS_WS}/tcp"      comment "sing-box vmess-ws"
    echo ufw allow "${PORT_VLESS_WS}/tcp"      comment "sing-box vless-ws"
    return 0
  fi

  # 状态检查（如果防火墙没开，就没必要清理和添加）
  if ufw status | grep -qi "inactive"; then
    echo "ufw 处于未激活状态，跳过防火墙配置。"
    return 0
  fi

  echo "正在优化防火墙规则..."

  #【核心逻辑】清理旧的 sing-box 规则
  # 逻辑：获取带编号的列表 -> 过滤出含 "sing-box" 的行 -> 提取编号 -> 倒序排序 -> 逐个删除
  # 为什么要倒序 (sort -rn)？：因为删除第1条规则后，原来的第2条会变成第1条。从大号往小号删可以避免索引错乱。
  OLD_RULES=$(ufw status numbered | grep -i "sing-box" | awk -F"[][]" '{print $2}' | sort -rn)
  
  if [ -n "$OLD_RULES" ]; then
    echo "检测到旧规则，正在清理过时的端口洞开..."
    for NUM in $OLD_RULES; do
      # 使用 yes 命令自动确认删除
      yes | ufw delete "$NUM" >/dev/null 2>&1
    done
  fi

  # 放行新端口
  echo "正在放行当前配置端口..."
  # 推荐做法：所有规则都统一加上特定的 comment 前缀，方便下次清理
  ufw allow "${PORT_HYSTERIA2}/udp"     comment "sing-box:hysteria2"
  ufw allow "${PORT_TUIC}/udp"          comment "sing-box tuic"
  ufw allow "${PORT_TROJAN}/tcp"        comment "sing-box:trojan"
  ufw allow "${PORT_ANYTLS}/tcp"        comment "sing-box:anytls"
  ufw allow "${PORT_VLESS}/tcp"         comment "sing-box:vless"
  ufw allow "${PORT_VMESS_REALITY}/tcp" comment "sing-box:vmess-reality"
  ufw allow "${PORT_VMESS_WS_TLS}/tcp"  comment "sing-box:vmess-ws-tls"
  #ufw allow "${PORT_VMESS_WS}/tcp"      comment "sing-box:vmess-ws"
  ufw allow "${PORT_VLESS_WS}/tcp"      comment "sing-box:vless-ws"

  echo "防火墙规则更新完成，已自动封堵旧端口。"
}
set +e
open_firewall_ports
set -e

# 生成证书
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${WORKDIR}/key.tmp" \
  -out "${WORKDIR}/cert.tmp" \
  -days 3650 \
  -subj "/CN=${BEST_DOMAIN}" \
  -addext "subjectAltName=DNS:${BEST_DOMAIN}"

CERT=$(awk '{gsub(/"/,"\\\""); lines[NR] = "\"" $0 "\""} END{printf "["; for(i=1;i<=NR;i++){printf "%s%s", lines[i], (i<NR? ",":"") } print "]"}' "${WORKDIR}/cert.tmp")
KEY=$(awk '{gsub(/"/,"\\\""); lines[NR] = "\"" $0 "\""} END{printf "["; for(i=1;i<=NR;i++){printf "%s%s", lines[i], (i<NR? ",":"") } print "]"}' "${WORKDIR}/key.tmp")

rm -f "${WORKDIR}/cert.tmp" "${WORKDIR}/key.tmp"

# 随机 Padding
rand_val=$(get_true_random)
STOP_VAL=$((rand_val % 5 + 6))
rand_val=$(get_true_random); R0_MIN=$((20 + rand_val % 20)); R0_MAX=$((R0_MIN + rand_val % 30))
rand_val=$(get_true_random); R1_MIN=$((80 + rand_val % 50)); R1_MAX=$((R1_MIN + rand_val % 300))
rand_val=$(get_true_random); R2_BASE=$((300 + rand_val % 200)); R2_MAX=$((R2_BASE + rand_val % 500))
rand_val=$(get_true_random); R_HIGH=$((400 + rand_val % 600))

STOP_VAL=$(( ($(get_true_random) % 7) + 6 ))

R0_FIXED=$(( ($(get_true_random) % 11) + 20 ))
R0_FIXED2=$(( ($(get_true_random) % 21) + 40 ))
R0_FIXED3=$(( ($(get_true_random) % 11) + 50 ))
R0_FIXED4=$(( ($(get_true_random) % 16) + 25 ))
R1_MIN=$(( ($(get_true_random) % 101) + 80 ))
R1_MAX=$(( R1_MIN + ($(get_true_random) % 201) + 100 ))

R2_BASE=$(( ($(get_true_random) % 201) + 250 ))
R2_GAP1=$(( R2_BASE + ($(get_true_random) % 151) + 100 ))
R2_GAP2=$(( R2_GAP1 + ($(get_true_random) % 201) + 150 ))

R_HIGH_BASE=$(( ($(get_true_random) % 201) + 400 ))
R_HIGH_MID=$(( R_HIGH_BASE + ($(get_true_random) % 301) + 150 ))
R_HIGH_MAX=$(( R_HIGH_BASE + ($(get_true_random) % 401) + 300 ))

ensure_min_max() {
  local min=$1
  local max=$2
  if [ "$min" -gt "$max" ]; then
    echo "${max}-${min}"
  else
    echo "${min}-${max}"
  fi
}

PAD_0="stop=${STOP_VAL}"
PAD_1="0=${R0_FIXED}-${R0_FIXED}"
PAD_2="1=${R0_FIXED2}-${R0_FIXED2}"
PAD_3="2=${R0_FIXED3}-${R0_FIXED3}"
PAD_4="3=${R0_FIXED4}-${R0_FIXED4}"
PAD_5="4=${R1_MIN}-${R1_MAX}"
PAD_6="5=$(ensure_min_max ${R2_BASE} $((R2_BASE+120))),c,$(ensure_min_max ${R2_GAP1} $((R2_GAP1+180))),c,$(ensure_min_max ${R2_GAP2} $((R2_GAP2+220)))"
PAD_7="6=9-9,$(ensure_min_max ${R_HIGH_BASE} $((R_HIGH_BASE+250)))"
PAD_8="7=$(ensure_min_max $((R_HIGH_BASE+100)) $((R_HIGH_BASE+400)))"
PAD_9="8=$(ensure_min_max $((R_HIGH_BASE+200)) $((R_HIGH_BASE+500))),c,$(ensure_min_max ${R_HIGH_MID} $((R_HIGH_MID+300)))"
PAD_10="9=$(ensure_min_max $((R_HIGH_BASE+300)) $((R_HIGH_BASE+600))),c,$(ensure_min_max $((R_HIGH_MID+200)) ${R_HIGH_MAX})"
PAD_11="10=12-12,$(ensure_min_max $((R_HIGH_BASE+400)) $((R_HIGH_BASE+800)))"
PAD_12="11=50-150,c,$(ensure_min_max $((R2_BASE+100)) $((R2_BASE+400))),c,700-1100"

PADDING_SCHEME_JSON=$(jq -n --argjson pads "[\"$PAD_0\",\"$PAD_1\",\"$PAD_2\",\"$PAD_3\",\"$PAD_4\",\"$PAD_5\",\"$PAD_6\",\"$PAD_7\",\"$PAD_8\",\"$PAD_9\",\"$PAD_10\",\"$PAD_11\",\"$PAD_12\"]" '$pads | .[:12]')

echo $PADDING_SCHEME_JSON

# ╔═════════════════════════════════════════════════╗
# ║  共享变量 — 客户端 JSON 与 分享链接 URI 强统一配置区  ║
# ╚═════════════════════════════════════════════════╝

# 指纹特征
FINGERPRINT_TYPE="${FINGERPRINT_TYPE:-firefox}"

# ================= 安全性配置 (按场景区分) =================
# REALITY 节点：必须为 false / 0
INSECURE_REALITY_JSON="false"
INSECURE_REALITY_LINK="0"

# tuic/hy2 自签临时证书节点测试 false / 0
INSECURE_HY2_TUIC_JSON="false"

# TLS：需要 true / 1
INSECURE_SELFSIGNED_JSON="false"
INSECURE_SELFSIGNED_LINK="1"

# 正规证书 / Cloudflare 节点：必须为 false / 0
INSECURE_VALID_JSON="false"
INSECURE_VALID_LINK="0"

# ALPN 设置：JSON 需要带引号的字符串，链接直接写裸字符串
ALPN_WS_JSON='"http/1.1"'
ALPN_WS_LINK="http/1.1"
ALPN_QUIC_JSON='"h3"'
ALPN_QUIC_LINK="h3"

# 数据包编码
PACKET_ENCODING='xudp'

# ── 广告屏蔽域名（DNS rules + route rules，原来重复6次）────────
_AD_DOMAINS='"books-analytics-events.apple.com",
          "pagead2.googlesyndication.com",
          "pagead2.googleadservices.com",
          "afs.googlesyndication.com",
          "stats.g.doubleclick.net",
          "ad.doubleclick.net",
          "stats.wp.com",
          "trk.pinterest.com",
          "ads.yahoo.com",
          "analytics.query.yahoo.com",
          "partnerads.ysm.yahoo.com",
          "api.ad.xiaomi.com",
          "data.mistat.xiaomi.com",
          "sdkconfig.ad.xiaomi.com",
          "business-api.tiktok.com",
          "grs.hicloud.com"'

# ── 地区 urltest 组（原来重复3次）────────────────────────────
# 占位标记，可能未来替换等作用？
_REGIONAL_URLTEST='    { "type": "urltest", "tag": "台湾_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "新加坡_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "日本_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "美国_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "韩国_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "香港_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "英国_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "加拿大_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "澳大利亚_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "法国_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "荷兰_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "urltest", "tag": "德国_469138946ba5fa", "outbounds": ["直连_469138946ba5fa"], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },'

# ── 最新版本 route rule_sets（client.json + openwrt 共用）────────
_ROUTE_RULESETS='      { "type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-private", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-geolocation-!cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "megamori", "format": "binary", "url": "https://raw.githubusercontent.com/neomikanagi/megamori/main/megamori.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "category-ai-!cn", "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-duolingo", "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/duolingo.srs", "http_client": "全局HTTP客户端路由代理", "update_interval": "24h0m0s" }'

# ── 1.11.4 专属 route rule_sets 配置块 ─────────────────────────────────────
_ROUTE_RULESETS_1114='      { "type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-private", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-geolocation-!cn", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "megamori", "format": "binary", "url": "https://raw.githubusercontent.com/neomikanagi/megamori/main/megamori.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "category-ai-!cn", "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "geosite-duolingo", "format": "binary", "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/duolingo.srs", "download_detour": "代理_469138946ba5fa", "update_interval": "24h0m0s" }'

# ── 1.11.4 专属 DNS 配置块 ─────────────────────────────────────
_DNS_BLOCK_1114='    "servers": [
      { "tag": "解析223555_469138946ba5fa", "address": "223.5.5.5" },
      { "tag": "解析ALIDNS_469138946ba5fa", "address_resolver": "解析223555_469138946ba5fa", "address": "https://dns.alidns.com/dns-query" },
      { "tag": "解析CLOUDFLAREDNS_469138946ba5fa", "detour": "代理_469138946ba5fa", "address_resolver": "解析223555_469138946ba5fa", "address": "https://cloudflare-dns.com/dns-query" },
      { "tag": "dns_block", "address": "rcode://name_error" }
    ],
    "rules": [
      { "rule_set": "geosite-duolingo", "server": "解析CLOUDFLAREDNS_469138946ba5fa" },
      { "rule_set": [ "geosite-category-ads-all", "megamori" ], "server": "dns_block", "disable_cache": true },
      {
        "domain": [
          '"${_AD_DOMAINS}"'
        ], "server": "dns_block", "disable_cache": true },
      { "rule_set": "category-ai-!cn", "server": "解析CLOUDFLAREDNS_469138946ba5fa" },
      { "rule_set": [ "geosite-private", "geoip-cn" ], "server": "解析ALIDNS_469138946ba5fa" },
      { "rule_set": "geosite-geolocation-!cn", "server": "解析CLOUDFLAREDNS_469138946ba5fa" }
    ],
    "final": "解析CLOUDFLAREDNS_469138946ba5fa",
    "independent_cache": true'

# ── 1.11.4 专属 Inbounds 配置块 ────────────────────────────────
_INBOUNDS_1114='    { "type": "mixed", "tag": "混合入站_469138946ba5fa", "listen": "127.0.0.1", "listen_port": 7890 },
    {
      "type": "tun",
      "tag": "TUN入站_469138946ba5fa",
      "endpoint_independent_nat": true,
      "address": [ "172.19.0.1/28", "fdfe:dcba:9876::1/126" ],
      "auto_route": true,
      "strict_route": false,
      "platform": { "http_proxy": { "enabled": true, "server": "127.0.0.1", "server_port": 7890 } }
    }'

# ── 1.11.4 专属 Experimental 配置块 ────────────────────────────
#https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip
#https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/main.zip
_EXP_BLOCK_1114='    "cache_file": { "enabled": true, "path": "sing-box-cache.db", "store_rdrc": true },
    "clash_api": { "external_controller": "127.0.0.1:9999", "external_ui": "ui", "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip", "external_ui_download_detour": "代理_469138946ba5fa" }'

# ── 最新版本 DNS servers（client.json + openwrt 完全相同）────────
_DNS_SERVERS='    "servers": [
      {
        "type": "hosts",
        "tag": "解析HOSTS_469138946ba5fa",
        "predefined": {
          "dns.google": [ "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844" ],
          "dns.alidns.com": [ "223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1" ],
          "one.one.one.one": [ "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" ],
          "1dot1dot1dot1.cloudflare-dns.com": [ "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" ],
          "cloudflare-dns.com": [ "1.1.1.1", "1.0.0.1", "104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9" ],
          "dns.cloudflare.com": [ "104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5" ],
          "dot.pub": [ "1.12.12.12", "120.53.53.53" ],
          "doh.pub": [ "1.12.12.12", "120.53.53.53" ],
          "dns.quad9.net": [ "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9" ],
          "dns.yandex.net": [ "77.88.8.8", "77.88.8.1", "2a02:6b8::feed:ff", "2a02:6b8:0:1::feed:ff" ],
          "dns.sb": [ "185.222.222.222", "2a09::" ],
          "dns.umbrella.com": [ "208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53" ],
          "dns.sse.cisco.com": [ "208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53" ],
          "engage.cloudflareclient.com": [ "162.159.192.1", "2606:4700:d0::a29f:c001" ]
        }
      },
      { "type": "https", "tag": "解析ALIDNS_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "dns.alidns.com", "path": "/dns-query" },
      { "type": "https", "tag": "解析DOH_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "doh.pub", "path": "/dns-query" },
      { "type": "https", "tag": "解析CLOUDFLAREDNS_469138946ba5fa", "detour": "代理_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "cloudflare-dns.com", "path": "/dns-query" },
      { "type": "https", "tag": "解析GOOGLE_469138946ba5fa", "detour": "代理_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "dns.google", "path": "/dns-query" },
      { "type": "fakeip", "tag": "解析FAKEIP_469138946ba5fa", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18" }
    ],'

# ── NTP + http_clients（两个最新版本配置完全相同）──────────────
_NTP_HTTP_CLIENTS='  "ntp": { "enabled": true, "interval": "30m0s", "server": "ntp.aliyun.com", "server_port": 123 },
  "http_clients": [
    { "tag": "全局HTTP客户端路由DEFAULT" },
    { "tag": "全局HTTP客户端路由DIRECT", "detour": "direct" },
    { "tag": "全局HTTP客户端路由直连", "detour": "直连_469138946ba5fa" },
    { "tag": "全局HTTP客户端路由代理", "detour": "代理_469138946ba5fa" }
  ],'

# ── 共用协议 outbound 节点（7个，三个最新版本配置相同）──────────
get_shared_outbounds() {
# 注意：这里 469138946ba5fa 没有任何引号，这意味着 Bash 会对内部的 $变量 进行求值
  #    { "type": "vmess", "tag": "${OUTBOUND_VMESS_WS}", "server": "${SERVER_IP}", "server_port": ${PORT_VMESS_WS}, "uuid": "${UUID_VMESS_WS}", "security": "auto", "packet_encoding": "xudp", "transport": { "type": "ws", "path": "/${PATH_VMESS_WS}", "headers": { "Host": "${BEST_DOMAIN}" } } }
  #    { "type": "vless", "tag": "${OUTBOUND_VLESS_WS}", "server": "${SERVER_IP}", "server_port": ${PORT_VLESS_WS}, "uuid": "${UUID_VLESS_WS}", "packet_encoding": "xudp", "transport": { "type": "ws", "path": "/${PATH_VLESS_WS}", "headers": { "Host": "${BEST_DOMAIN}" } } }
  cat <<469138946ba5fa
    { "type": "tuic", "tag": "${OUTBOUND_TUIC}", "server": "${SERVER_IP}", "server_port": ${PORT_TUIC}, "uuid": "${UUID_TUIC}", "password": "${PASSWORD_TUIC}", "congestion_control": "bbr", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_HY2_TUIC_JSON}, "certificate": $CERT, "alpn": [${ALPN_QUIC_JSON}] } },
    { "type": "hysteria2", "tag": "${OUTBOUND_HYSTERIA2}", "server": "${SERVER_IP}", "server_port": ${PORT_HYSTERIA2}, "password": "${PASSWORD_HYSTERIA2}", "obfs": { "type": "${HY2_OBFS_TYPE}", "password": "${HY2_OBFS_PASSWORD}" }, "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_HY2_TUIC_JSON}, "certificate": $CERT, "alpn": [${ALPN_QUIC_JSON}] } },
    { "type": "vless", "tag": "${OUTBOUND_VLESS}", "server": "${SERVER_IP}", "server_port": ${PORT_VLESS}, "uuid": "${UUID_VLESS}", "flow": "xtls-rprx-vision", "packet_encoding": "${PACKET_ENCODING}", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_REALITY_JSON}, "utls": { "enabled": true, "fingerprint": "${FINGERPRINT_TYPE}" }, "reality": { "enabled": true, "public_key": "${PUBLIC_KEY}", "short_id": "${SHORT_ID_VLESS}" } } },
    { "type": "trojan", "tag": "${OUTBOUND_TROJAN}", "server": "${SERVER_IP}", "server_port": ${PORT_TROJAN}, "password": "${PASSWORD_TROJAN}", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_REALITY_JSON}, "utls": { "enabled": true, "fingerprint": "${FINGERPRINT_TYPE}" }, "reality": { "enabled": true, "public_key": "${PUBLIC_KEY}", "short_id": "${SHORT_ID_TROJAN}" } } },
    { "type": "vmess", "tag": "${OUTBOUND_VMESS_REALITY}", "server": "${SERVER_IP}", "server_port": ${PORT_VMESS_REALITY}, "uuid": "${UUID_VMESS_REALITY}", "security": "auto", "packet_encoding": "${PACKET_ENCODING}", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_REALITY_JSON}, "utls": { "enabled": true, "fingerprint": "${FINGERPRINT_TYPE}" }, "reality": { "enabled": true, "public_key": "${PUBLIC_KEY}", "short_id": "${SHORT_ID_VMESS_REALITY}" } } },
    { "type": "vmess", "tag": "${OUTBOUND_VMESS_WS_TLS}", "server": "${SERVER_IP}", "server_port": ${PORT_VMESS_WS_TLS}, "uuid": "${UUID_VMESS_WS_TLS}", "security": "auto", "packet_encoding": "${PACKET_ENCODING}", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_SELFSIGNED_JSON}, "alpn": [${ALPN_WS_JSON}], "certificate": $CERT }, "transport": { "type": "ws", "path": "/${PATH_VMESS_WS_TLS}", "headers": { "Host": "${BEST_DOMAIN}" }, "early_data_header_name": "Sec-WebSocket-Protocol" } },
    { "type": "vless", "tag": "${OUTBOUND_VLESS_WS}", "server": "${SERVER_IP}", "server_port": ${PORT_VLESS_WS}, "uuid": "${UUID_VLESS_WS}", "packet_encoding": "${PACKET_ENCODING}", "transport": { "type": "ws", "path": "/${PATH_VLESS_WS}", "headers": { "Host": "${BEST_DOMAIN}" } } }
469138946ba5fa
}

# ── 共用协议 outbound anytls 节点（1个，两个最新版本配置相同）──────────
get_shared_outbounds_anytls() {
# 注意：这里 469138946ba5fa 没有任何引号，这意味着 Bash 会对内部的 $变量 进行求值
  cat <<469138946ba5fa
    { "type": "anytls", "tag": "${OUTBOUND_ANYTLS}", "server": "${SERVER_IP}", "server_port": ${PORT_ANYTLS}, "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "insecure": ${INSECURE_REALITY_JSON}, "utls": { "enabled": true, "fingerprint": "${FINGERPRINT_TYPE}" }, "reality": { "enabled": true, "public_key": "${PUBLIC_KEY}", "short_id": "${SHORT_ID_ANYTLS}" } }, "password": "${PASSWORD_ANYTLS}" },
469138946ba5fa
}

# ==================== 生成服务端 config ====================
#    { "type": "vmess", "tag": "${INBOUND_VMESS_WS}", "listen": "::", "listen_port": $PORT_VMESS_WS, "tcp_fast_open": true, "users": [{"name": "","uuid": "${UUID_VMESS_WS}"}], "transport": { "type": "ws", "path": "/${PATH_VMESS_WS}", "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol" } }
#    { "type": "vless", "tag": "${INBOUND_VLESS_WS}", "listen": "::", "listen_port": $PORT_VLESS_WS, "users": [{"name": "","uuid": "${UUID_VLESS_WS}"}], "transport": { "type": "ws", "path": "/${PATH_VLESS_WS}", "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol" } }
#          "${INBOUND_VMESS_WS}"
#          "${INBOUND_VLESS_WS}"
cat > ${WORKDIR}/config.json <<469138946ba5fa
{
  "log": { "level": "info", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "hosts", "tag": "解析HOSTS_469138946ba5fa",
        "predefined": {
          "dns.google": [ "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844" ],
          "dns.alidns.com": [ "223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1" ],
          "one.one.one.one": [ "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" ],
          "1dot1dot1dot1.cloudflare-dns.com": [ "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001" ],
          "cloudflare-dns.com": [ "104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9" ],
          "dns.cloudflare.com": [ "104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5" ],
          "dot.pub": [ "1.12.12.12", "120.53.53.53" ],
          "doh.pub": [ "1.12.12.12", "120.53.53.53" ],
          "dns.quad9.net": [ "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9" ],
          "dns.yandex.net": [ "77.88.8.8", "77.88.8.1", "2a02:6b8::feed:ff", "2a02:6b8:0:1::feed:ff" ],
          "dns.sb": [ "185.222.222.222", "2a09::" ],
          "dns.umbrella.com": [ "208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53" ],
          "dns.sse.cisco.com": [ "208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53" ],
          "engage.cloudflareclient.com": [ "162.159.192.1", "2606:4700:d0::a29f:c001" ]
        }
      },
      { "type": "https", "tag": "解析CLOUDFLAREDNS_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "cloudflare-dns.com", "path": "/dns-query" },
      { "type": "https", "tag": "解析GOOGLE_469138946ba5fa", "domain_resolver": "解析HOSTS_469138946ba5fa", "server": "dns.google" }
    ],
    "rules": [
      { "action": "evaluate", "server": "解析HOSTS_469138946ba5fa" },
      { "match_response": true, "response_rcode": "NOERROR", "action": "respond" },
      { "rule_set": [ "geosite-category-ads-all", "megamori" ], "action": "predefined", "rcode": "NXDOMAIN" },
      {
        "domain": [
          ${_AD_DOMAINS}
        ], "action": "predefined", "rcode": "NXDOMAIN"
      }
    ],
    "final": "解析CLOUDFLAREDNS_469138946ba5fa"
  },
  "ntp": { "enabled": true, "interval": "30m0s", "server": "time.cloudflare.com", "server_port": 123 },
  "http_clients": [
    { "tag": "全局HTTP客户端路由DEFAULT" },
    { "tag": "全局HTTP客户端路由DIRECT", "detour": "direct" },
    { "tag": "全局HTTP客户端路由直连", "detour": "直连_469138946ba5fa" },
    { "tag": "全局HTTP客户端路由代理", "detour": "代理_469138946ba5fa" }
  ],
  "inbounds": [
    { "type": "hysteria2", "tag": "${INBOUND_HYSTERIA2}", "listen": "::", "listen_port": ${PORT_HYSTERIA2}, "users": [{"password": "${PASSWORD_HYSTERIA2}"}], "obfs": { "type": "${HY2_OBFS_TYPE}", "password": "${HY2_OBFS_PASSWORD}" }, "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "alpn": [${ALPN_QUIC_JSON}], "certificate": $CERT, "key": $KEY } }, 
    { "type": "tuic", "tag": "${INBOUND_TUIC}", "listen": "::", "listen_port": ${PORT_TUIC}, "users": [{"uuid": "${UUID_TUIC}","password": "${PASSWORD_TUIC}"}], "congestion_control": "bbr", "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "alpn": [${ALPN_QUIC_JSON}], "certificate": $CERT, "key": $KEY } }, 
    { "type": "vless", "tag": "${INBOUND_VLESS}", "listen": "::", "listen_port": ${PORT_VLESS}, "users": [{"name": "","uuid": "${UUID_VLESS}","flow": "xtls-rprx-vision"}], "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "reality": { "enabled": true, "handshake": {"server": "${BEST_DOMAIN}","server_port": 443}, "private_key": "${PRIVATE_KEY}", "short_id": ${SHORT_IDS_VLESS} } } }, 
    { "type": "trojan", "tag": "${INBOUND_TROJAN}", "listen": "::", "listen_port": ${PORT_TROJAN}, "users": [{"name": "","password": "${PASSWORD_TROJAN}"}], "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "reality": { "enabled": true, "handshake": {"server": "${BEST_DOMAIN}","server_port": 443}, "private_key": "${PRIVATE_KEY}", "short_id": ${SHORT_IDS_TROJAN} } } }, 
    { "type": "anytls", "tag": "${INBOUND_ANYTLS}", "listen": "::", "listen_port": ${PORT_ANYTLS}, "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "reality": { "enabled": true, "handshake": {"server": "${BEST_DOMAIN}","server_port": 443}, "private_key": "${PRIVATE_KEY}", "short_id": ${SHORT_IDS_ANYTLS} } }, "users": [{"name": "anyuser","password": "${PASSWORD_ANYTLS}"}], "padding_scheme": $PADDING_SCHEME_JSON }, 
    { "type": "vmess", "tag": "${INBOUND_VMESS_REALITY}", "listen": "::", "listen_port": $PORT_VMESS_REALITY, "users": [{"name": "","uuid": "${UUID_VMESS_REALITY}"}], "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "reality": { "enabled": true, "handshake": {"server": "${BEST_DOMAIN}","server_port": 443}, "private_key": "${PRIVATE_KEY}", "short_id": ${SHORT_IDS_VMESS_REALITY} } } }, 
    { "type": "vmess", "tag": "${INBOUND_VMESS_WS_TLS}", "listen": "::", "listen_port": $PORT_VMESS_WS_TLS, "users": [{"name": "","uuid": "${UUID_VMESS_WS_TLS}"}], "tls": { "enabled": true, "server_name": "${BEST_DOMAIN}", "alpn": [${ALPN_WS_JSON}], "certificate": $CERT, "key": $KEY }, "transport": { "type": "ws", "path": "/${PATH_VMESS_WS_TLS}", "headers": {"Host": "${BEST_DOMAIN}"}, "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol" } }, 
    { "type": "vless", "tag": "${INBOUND_VLESS_WS}", "listen": "::", "listen_port": $PORT_VLESS_WS, "users": [{"name": "","uuid": "${UUID_VLESS_WS}"}], "transport": { "type": "ws", "path": "/${PATH_VLESS_WS}", "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol" } }
  ],
  "outbounds": [
    { "type": "direct", "tag": "直连_469138946ba5fa" },
    { "type": "selector", "tag": "代理_469138946ba5fa", "outbounds": [ "直连_469138946ba5fa" ] }
  ],
  "route": {
    "rules": [
      { "protocol": "dns", "action": "hijack-dns" },
      { "port": 53, "action": "hijack-dns" },
      {
        "process_name": [
          "sing-box.exe",
          "sing-box",
          "io.nekohasekai.sfa"
        ],
        "outbound": "代理_469138946ba5fa"
      },
      {
        "rule_set": [ "geosite-category-ads-all", "megamori" ],
        "action": "reject"
      },
      {
        "domain": [
          ${_AD_DOMAINS}
        ], "action": "reject"
      },
      {
        "inbound": [
          "${INBOUND_HYSTERIA2}",
          "${INBOUND_TUIC}",
          "${INBOUND_VLESS}",
          "${INBOUND_TROJAN}",
          "${INBOUND_ANYTLS}",
          "${INBOUND_VMESS_REALITY}",
          "${INBOUND_VMESS_WS_TLS}",
          "${INBOUND_VLESS_WS}"
        ], "action": "sniff"
      }
    ],
    "rule_set": [
      { "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ads-all.srs", "http_client": "全局HTTP客户端路由DEFAULT", "update_interval": "24h0m0s" },
      { "type": "remote", "tag": "megamori", "format": "binary", "url": "https://github.com/neomikanagi/megamori/raw/refs/heads/main/megamori.srs", "http_client": "全局HTTP客户端路由DEFAULT", "update_interval": "24h0m0s" }
    ],
    "final": "代理_469138946ba5fa",
    "auto_detect_interface": true,
    "default_domain_resolver": "解析GOOGLE_469138946ba5fa",
    "default_http_client": "全局HTTP客户端路由DEFAULT"
  }
}
469138946ba5fa

# =====================================================================
# 启动 sing-box：先验证配置，再后台运行
#  pkill 改为先 SIGTERM，再 SIGKILL，给进程清理机会
# =====================================================================
# =====================================================================
# 启动验证函数：确认 sing-box 真正运行起来，而不是静默失败
# =====================================================================
verify_singbox_running() {
  local retries=5
  local i=0
  while [ $i -lt $retries ]; do
    sleep 1
    if pgrep -f "sing-box.*run" > /dev/null 2>&1; then
      echo "✔︎ sing-box 启动成功"
      return 0
    fi
    i=$((i+1))
  done
  echo "✗ sing-box 启动失败，最近日志："
  tail -30 "${WORKDIR}/sing-box.log" 2>/dev/null || echo "（无日志文件）"
  return 1
}

mkdir -p "${WORKDIR}/config"
if ! "${WORKDIR}/sing-boxs/sing-box" check -D "${WORKDIR}/config" -c "${WORKDIR}/config.json"; then
  echo "✘ sing-box config check 失败，停止启动。" >&2
  exit 1
fi
nohup ${WORKDIR}/sing-boxs/sing-box -D ${WORKDIR}/config -c ${WORKDIR}/config.json run > ${WORKDIR}/sing-box.log 2>&1 & disown

sleep 1 ; cat ${WORKDIR}/sing-box.log
rm -fv ${WORKDIR}/sing-box.log

# 优雅停止：先 TERM，等 2s，再 KILL
pkill -TERM -f "${WORKDIR}/sing-boxs/sing-box" 2>/dev/null || true
sleep 2
pkill -9 -f "${WORKDIR}/sing-boxs/sing-box" 2>/dev/null || true

# 再次启动
nohup ${WORKDIR}/sing-boxs/sing-box -D ${WORKDIR}/config -c ${WORKDIR}/config.json run > ${WORKDIR}/sing-box.log 2>&1 & disown
set +e
verify_singbox_running
set -e

# Cloudflared
#nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VMESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log 2>&1 & disown
nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VLESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log 2>&1 & disown
#sleep 1 ; cat ${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log
sleep 1 ; cat ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log
#rm -fv "${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log"
#rm -fv "${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log"
rm -fv ${WORKDIR}/cloudflared_*.log

pkill -TERM -f "${WORKDIR}/cloudflared" 2>/dev/null || true
sleep 2
pkill -9 -f "${WORKDIR}/cloudflared" 2>/dev/null || true
sleep 1

#nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VMESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log 2>&1 & disown
nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VLESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log 2>&1 & disown
sleep 10

# =====================================================================
#  去掉 eval，直接安全提取 cloudflared 域名
# 原版: eval CLOUDFLARED_DOMAIN_VMESS_WS="$(grep...)"
#   若日志中含特殊字符或 shell 元字符，eval 会执行任意代码
# =====================================================================
#CLOUDFLARED_DOMAIN_VMESS_WS=$(grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare\.com" "${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log" 2>/dev/null | head -n 1 | sed 's|https://||')
CLOUDFLARED_DOMAIN_VLESS_WS=$(grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare\.com" "${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log" 2>/dev/null | head -n 1 | sed 's|https://||')

#if [ -z "$CLOUDFLARED_DOMAIN_VMESS_WS" ]; then
if [ -z "$CLOUDFLARED_DOMAIN_VLESS_WS" ]; then
  #echo "警告：Cloudflared 域名提取失败，手动检查日志: ${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log"
  echo "警告：Cloudflared 域名提取失败，手动检查日志: ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log"
fi
#echo "Cloudflared 域名: ${CLOUDFLARED_DOMAIN_VMESS_WS}"
echo "Cloudflared 域名: ${CLOUDFLARED_DOMAIN_VLESS_WS}"

# 变量配置区
SERVER_CFNAT="127.0.0.1"
PORT_CFNAT="1234"
CLOUDFLARED_PROXYIP="cloudflare.182682.xyz"
CLOUDFLARED_PROXYIP_PORT="443"

# ── Cloudflare CDN 节点（数据驱动循环，新增/删除只改数组）────
# 格式: "标签名|服务器|端口|TLS(tls或空)"
# ── CF 节点数据表（唯一数据源）────────────────────────────────
# 格式: "显示名|服务器|端口|tls"（tls=有TLS，空=无TLS）
# 增删节点只改这里，outbound/selector引用/订阅链接/result.txt 全部自动同步
#CF-Domain-443|${CLOUDFLARED_DOMAIN_VMESS_WS}|443|tls
#CF-Domain-443|${CLOUDFLARED_DOMAIN_VLESS_WS}|443|tls
#CF-Domain-80|${CLOUDFLARED_DOMAIN_VMESS_WS}|80|
#CF-Domain-80|${CLOUDFLARED_DOMAIN_VLESS_WS}|80|
CF_NODES="CF-104.16-443|104.16.0.0|443|tls
CF-104.16-443-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-104.17-8443|104.17.0.0|8443|tls
CF-104.17-8443-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-104.18-2053|104.18.0.0|2053|tls
CF-104.18-2053-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-104.19-2083|104.19.0.0|2083|tls
CF-104.19-2083-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-104.20-2087|104.20.0.0|2087|tls
CF-104.20-2087-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-104.21-80|104.21.0.0|80|
CF-104.21-80-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|
CF-104.22-8080|104.22.0.0|8080|
CF-104.22-8080-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|
CF-104.24-8880|104.24.0.0|8880|
CF-104.24-8880-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|
CF-Domain-443|${CLOUDFLARED_DOMAIN_VLESS_WS}|443|tls
CF-Domain-443-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|tls
CF-Domain-80|${CLOUDFLARED_DOMAIN_VLESS_WS}|80|
CF-Domain-80-NAT|${SERVER_CFNAT}|${PORT_CFNAT}|
CF-ProxyIP|${CLOUDFLARED_PROXYIP}|${CLOUDFLARED_PROXYIP_PORT}|tls"

# 工具函数：生成 vmess:// 链接
# 参数: ps add port id net mhost mpath tls sni [pbk] [sid] [fp]
make_vmess() {
  local ps=$1
  local add=$2
  local port=$3
  local id=$4
  local net=$5
  local mhost=$6
  local mpath=$7
  local tls=$8
  local sni=$9
  local pbk=${10:-}
  local sid=${11:-}
  local fp=${12:-$FINGERPRINT_TYPE}
  local allowInsecure=${13:-$INSECURE_REALITY_LINK}
  local alpn=${14:-}

  local json
  if [ "$tls" = "reality" ]; then
    json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"%s","type":"none","host":"%s","path":"%s","tls":"reality","sni":"%s","pbk":"%s","sid":"%s","fp":"%s","allowInsecure":"%s"}' \
      "$ps" "$add" "$port" "$id" "$net" "$mhost" "$mpath" "$sni" "$pbk" "$sid" "$fp" "$allowInsecure")
  elif [ -n "$tls" ] && [ "$tls" != "none" ]; then
    if [ -n "$alpn" ]; then
      json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"%s","type":"none","host":"%s","path":"%s","tls":"%s","sni":"%s","allowInsecure":"%s","alpn":"%s"}' \
        "$ps" "$add" "$port" "$id" "$net" "$mhost" "$mpath" "$tls" "$sni" "$allowInsecure" "$alpn")
    else
      json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"%s","type":"none","host":"%s","path":"%s","tls":"%s","sni":"%s","allowInsecure":"%s"}' \
        "$ps" "$add" "$port" "$id" "$net" "$mhost" "$mpath" "$tls" "$sni" "$allowInsecure")
    fi
  else
    json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","scy":"auto","net":"%s","type":"none","host":"%s","path":"%s","tls":"%s","sni":"%s"}' \
      "$ps" "$add" "$port" "$id" "$net" "$mhost" "$mpath" "$tls" "$sni")
  fi
  local b64
  b64=$(printf '%s' "${json}" | base64 | tr -d '\n')
  printf 'vmess://%s' "${b64}"
}

# 生成 VLESS WS 链接的工具函数
make_vless_ws() {
  local ps=$1
  local add=$2
  local port=$3
  local id=$4
  local host=$5
  local path=$6
  local tls=$7     # tls 或空
  local sni=$8     # 只有开启 tls 才生效
  
  # 引入全局共享变量作为默认值，彻底解决客户端与链接不一致
  local allowInsecure=${9:-$INSECURE_SELFSIGNED_LINK}
  local alpn=${10:-$ALPN_WS_LINK}
  local fp=${11:-$FINGERPRINT_TYPE}

  if [ "$tls" = "tls" ]; then
    # 增加 alpn 和 fp 参数的输出
    printf "vless://%s@%s:%s?encryption=none&security=tls&allowInsecure=%s&sni=%s&alpn=%s&fp=%s&type=ws&host=%s&path=%s#%s\n" \
      "$id" "$add" "$port" "$allowInsecure" "$sni" "$alpn" "$fp" "$host" "${path}" "$ps"
  else
    printf "vless://%s@%s:%s?encryption=none&security=none&type=ws&host=%s&path=%s#%s\n" \
      "$id" "$add" "$port" "$host" "${path}" "$ps"
  fi
}

# ── build_cf_data：从 CF_NODES 生成三样衍生数据 ───────────────
# 产出：
#   _CF_OB_JSON    → outbound 节点 JSON 体（逗号分隔，头部有逗号）
#   _CF_TAGS_CSV   → tag 列表（格式: , "tag1", "tag2"...，头部有逗号）
#   CF_LINKS       → 订阅链接字符串（make_vmess 生成）
#   CF_RESULT_LINES → result.txt 显示行
build_cf_data() {
  _CF_OB_JSON=""
  _CF_TAGS_CSV=""
  CF_LINKS=""
  CF_RESULT_LINES=""
  local _idx=9

  while IFS='|' read -r _cf_name _cf_server _cf_port _cf_tls; do
    [ -z "$_cf_name" ] && continue
    local _cf_tag="${NODE_REGION_TAG}cf-ob-${_cf_name}-$(gen_uuid | tr -d '-')"

    # outbound JSON（头部带逗号，直接拼接到 $(get_shared_outbounds) 后面）
    #    { \"type\": \"vmess\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VMESS_WS}\", \"security\": \"auto\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": true, \"server_name\": \"${CLOUDFLARED_DOMAIN_VMESS_WS}\", \"insecure\": false, \"alpn\": [${ALPN_WS_JSON}] }, \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VMESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VMESS_WS}\" } } }"
    #    { \"type\": \"vless\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VLESS_WS}\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": true, \"server_name\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\", \"insecure\": false, \"alpn\": [${ALPN_WS_JSON}] }, \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VLESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\" } } }"
    #    { \"type\": \"vmess\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VMESS_WS}\", \"security\": \"auto\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": false }, \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VMESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VMESS_WS}\" } } }"
    #    { \"type\": \"vless\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VLESS_WS}\", \"packet_encoding\": \"xudp\", \"tls\": { \"enabled\": false }, \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VLESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\" } } }"
    if [ "$_cf_tls" = "tls" ]; then
      _CF_OB_JSON="${_CF_OB_JSON},
    { \"type\": \"vless\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VLESS_WS}\", \"packet_encoding\": \"${PACKET_ENCODING}\", \"tls\": { \"enabled\": true, \"server_name\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\", \"insecure\": ${INSECURE_VALID_JSON}, \"alpn\": [${ALPN_WS_JSON}], \"utls\": { \"enabled\": true, \"fingerprint\": \"${FINGERPRINT_TYPE}\" } }, \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VLESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\" } } }"
    else
      _CF_OB_JSON="${_CF_OB_JSON},
    { \"type\": \"vless\", \"tag\": \"${_cf_tag}\", \"server\": \"${_cf_server}\", \"server_port\": ${_cf_port}, \"uuid\": \"${UUID_VLESS_WS}\", \"packet_encoding\": \"${PACKET_ENCODING}\", \"transport\": { \"type\": \"ws\", \"path\": \"/${PATH_VLESS_WS}\", \"headers\": { \"Host\": \"${CLOUDFLARED_DOMAIN_VLESS_WS}\" } } }"
    fi

    # selector 引用（头部带逗号）
    _CF_TAGS_CSV="${_CF_TAGS_CSV}, \"${_cf_tag}\""

    # 订阅链接
    #_lnk=$(make_vmess "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VMESS_WS}" "ws" "${CLOUDFLARED_DOMAIN_VMESS_WS}" "/${PATH_VMESS_WS}" "tls" "${CLOUDFLARED_DOMAIN_VMESS_WS}" "${INSECURE_VALID_LINK}")
    #_lnk=$(make_vless_ws "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VLESS_WS}" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "/${PATH_VLESS_WS}" "tls" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "${INSECURE_VALID_LINK}")
    #_lnk=$(make_vmess "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VMESS_WS}" "ws" "${CLOUDFLARED_DOMAIN_VMESS_WS}" "/${PATH_VMESS_WS}" "" "")
    #_lnk=$(make_vless_ws "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VLESS_WS}" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "/${PATH_VLESS_WS}" "" "")
    local _lnk
    if [ "$_cf_tls" = "tls" ]; then
      # 传入我们在顶部定好的共享变量
      _lnk=$(make_vless_ws "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VLESS_WS}" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "/${PATH_VLESS_WS}" "tls" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "${INSECURE_VALID_LINK}" "${ALPN_WS_LINK}" "${FINGERPRINT_TYPE}")
    else
      _lnk=$(make_vless_ws "${_cf_tag}" "${_cf_server}" "${_cf_port}" "${UUID_VLESS_WS}" "${CLOUDFLARED_DOMAIN_VLESS_WS}" "/${PATH_VLESS_WS}" "" "")
    fi
    CF_LINKS="${CF_LINKS}${_lnk}
"
# 使用 printf -v 生成固定 65 字符宽度的左对齐字符串
    printf -v _formatted_name "%-65s" "${_cf_tag}:"
    CF_RESULT_LINES="${CF_RESULT_LINES}[${_idx}] ${_formatted_name} ${_lnk}
"
    _idx=$((_idx+1))
  done << __CF_DATA__
${CF_NODES}
__CF_DATA__
}

# cloudflared 域名确定后立即调用
build_cf_data
_CF_COUNT=$(echo "$CF_NODES" | grep -c '|')
_TOTAL_NODES=$((8 + _CF_COUNT))

# ══════════════════════════════════════════════════════════════
# gen_client - 模板函数，生成两个最新版本客户端配置
# 5处差异全部通过参数控制：
#   $1 输出文件名
#   $2 TUN interface_name 行（openwrt传'      "interface_name": "tun0",'，其余传空）
#   $3 自动组 outbounds 引用列表
#   $4 手动组 outbounds 引用列表
#   $5 额外 outbound 节点体（client.json传${_CF_OUTBOUNDS}，openwrt传空）
#   $6 geosite-private 路由规则行（client.json传实际行，openwrt传空）
# ══════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════
# gen_client - 模板函数，动态隔离差异
# ══════════════════════════════════════════════════════════════
gen_client() {
  local _OUTFILE="$1"
  local _TUN_IFACE_LINE="$2"
  local _EXTRA_CF_TAGS="$3"
  local _EXTRA_OBS="$4"
  local _PRIVATE_RULE="$5"
  local _ANYTLS_BLOCK="$6"

  local _D_DNS
  local _D_INBOUNDS
  local _D_RULESETS
  local _D_EXP
  local _ANYTLS_REF
  local _D_NTP_HTTP     # 新增：隔离 1.11+ 专属的 http_clients
  local _D_ROUTE_TAIL   # 新增：隔离 1.11+ 专属的 default_domain_resolver

  if [ -z "$_ANYTLS_BLOCK" ]; then
    _ANYTLS_REF=""
  else
    _ANYTLS_REF="\"${OUTBOUND_ANYTLS}\", "
  fi

  if [ "$_OUTFILE" = "client_1.11.4.json" ]; then
    _D_DNS="${_DNS_BLOCK_1114}"
    _D_INBOUNDS="${_INBOUNDS_1114}"
    _D_RULESETS="${_ROUTE_RULESETS_1114}"
    _D_EXP="${_EXP_BLOCK_1114}"
    # 1.11.4 专修：完全去除 http_clients 数组，只保留基础 ntp
    _D_NTP_HTTP='  "ntp": { "enabled": true, "interval": "30m0s", "server": "ntp.aliyun.com", "server_port": 123 },'
    # 1.11.4 专修：去除 default_domain_resolver 和 default_http_client
    _D_ROUTE_TAIL='    "final": "代理_469138946ba5fa",
    "auto_detect_interface": true'
    else
    # 最新版（client.json / OpenWrt）— 对齐 sing-box 1.14 DNS schema
    _D_DNS="${_DNS_SERVERS}
    \"rules\": [
      { \"action\": \"evaluate\", \"server\": \"解析HOSTS_469138946ba5fa\" },
      { \"match_response\": true, \"response_rcode\": \"NOERROR\", \"action\": \"respond\" },
      { \"rule_set\": [ \"geosite-category-ads-all\", \"megamori\" ], \"action\": \"predefined\", \"rcode\": \"NXDOMAIN\" },
      { \"domain\": [ ${_AD_DOMAINS} ], \"action\": \"predefined\", \"rcode\": \"NXDOMAIN\" },
      { \"rule_set\": [ \"geosite-private\", \"geosite-cn\" ], \"server\": \"解析ALIDNS_469138946ba5fa\" },
      { \"rule_set\": \"geosite-duolingo\", \"server\": \"解析CLOUDFLAREDNS_469138946ba5fa\" },
      { \"rule_set\": \"category-ai-!cn\", \"server\": \"解析CLOUDFLAREDNS_469138946ba5fa\" },
      { \"rule_set\": \"geosite-geolocation-!cn\", \"server\": \"解析CLOUDFLAREDNS_469138946ba5fa\" },
      { \"query_type\": [ \"A\", \"AAAA\" ], \"server\": \"解析FAKEIP_469138946ba5fa\" }
    ],
    \"final\": \"解析CLOUDFLAREDNS_469138946ba5fa\",
    \"strategy\": \"prefer_ipv4\",
    \"reverse_mapping\": true,
    \"cache_capacity\": 4096"

    _D_INBOUNDS="    { \"type\": \"mixed\", \"tag\": \"混合入站_469138946ba5fa\", \"listen\": \"0.0.0.0\", \"listen_port\": 7890 },
    {
      \"type\": \"tun\",
      \"tag\": \"TUN入站_469138946ba5fa\",
      ${_TUN_IFACE_LINE}
      \"auto_route\": true,
      \"strict_route\": false,
      \"address\": [ \"172.19.0.1/30\", \"fdfe:dcba:9876::1/126\" ],
      \"platform\": { \"http_proxy\": { \"enabled\": true, \"server\": \"0.0.0.0\", \"server_port\": 7890 } },
      \"endpoint_independent_nat\": true
    }"

    _D_RULESETS="${_ROUTE_RULESETS}"

    _D_EXP="    \"cache_file\": { \"enabled\": true, \"path\": \"sing-box-cache.db\", \"store_fakeip\": true, \"store_dns\": true },
    \"clash_api\": { \"external_controller\": \":9999\", \"external_ui\": \"ui\", \"external_ui_download_url\": \"https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip\", \"external_ui_download_detour\": \"代理_469138946ba5fa\" }"

    _D_NTP_HTTP="${_NTP_HTTP_CLIENTS}"

    # FakeIP 二次解析走代理 Cloudflare，避免默认走阿里被污染
    _D_ROUTE_TAIL='    "final": "代理_469138946ba5fa",
    "auto_detect_interface": true,
    "default_domain_resolver": "解析CLOUDFLAREDNS_469138946ba5fa",
    "default_http_client": "全局HTTP客户端路由DEFAULT"'
  fi

#    { "type": "urltest", "tag": "自动_469138946ba5fa", "outbounds": [ "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS}", "${OUTBOUND_VMESS_WS_TLS}"${_EXTRA_CF_TAGS} ], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
#    { "type": "urltest", "tag": "自动_469138946ba5fa", "outbounds": [ "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS_TLS}", "${OUTBOUND_VLESS_WS}"${_EXTRA_CF_TAGS} ], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
#    { "type": "selector", "tag": "手动_469138946ba5fa", "outbounds": [ "${OUTBOUND_TUIC}", "${OUTBOUND_HYSTERIA2}", "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS}", "${OUTBOUND_VMESS_WS_TLS}"${_EXTRA_CF_TAGS} ] },
#    { "type": "selector", "tag": "手动_469138946ba5fa", "outbounds": [ "${OUTBOUND_TUIC}", "${OUTBOUND_HYSTERIA2}", "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS_TLS}, "${OUTBOUND_VLESS_WS}""${_EXTRA_CF_TAGS} ] },
cat > "${WORKDIR}/${_OUTFILE}" <<469138946ba5fa
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
${_D_DNS}
  },
${_D_NTP_HTTP}
  "inbounds": [
${_D_INBOUNDS}
  ],
  "outbounds": [
    { "type": "direct", "tag": "直连_469138946ba5fa" },
    { "type": "selector", "tag": "代理_469138946ba5fa", "outbounds": ["自动_469138946ba5fa","手动_469138946ba5fa","直连_469138946ba5fa","台湾_469138946ba5fa","新加坡_469138946ba5fa","日本_469138946ba5fa","美国_469138946ba5fa","韩国_469138946ba5fa","香港_469138946ba5fa","德国_469138946ba5fa", "英国_469138946ba5fa", "加拿大_469138946ba5fa", "澳大利亚_469138946ba5fa", "法国_469138946ba5fa", "荷兰_469138946ba5fa"] },
    { "type": "urltest", "tag": "自动_469138946ba5fa", "outbounds": [ "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS_TLS}", "${OUTBOUND_VLESS_WS}"${_EXTRA_CF_TAGS} ], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m0s", "tolerance": 100 },
    { "type": "selector", "tag": "手动_469138946ba5fa", "outbounds": [ "${OUTBOUND_TUIC}", "${OUTBOUND_HYSTERIA2}", "${OUTBOUND_VLESS}", "${OUTBOUND_TROJAN}", ${_ANYTLS_REF}"${OUTBOUND_VMESS_REALITY}", "${OUTBOUND_VMESS_WS_TLS}", "${OUTBOUND_VLESS_WS}"${_EXTRA_CF_TAGS} ] },
    { "type": "selector", "tag": "智能_469138946ba5fa", "outbounds": ["自动_469138946ba5fa","手动_469138946ba5fa","直连_469138946ba5fa","台湾_469138946ba5fa","新加坡_469138946ba5fa","日本_469138946ba5fa","美国_469138946ba5fa","韩国_469138946ba5fa","香港_469138946ba5fa","德国_469138946ba5fa", "英国_469138946ba5fa", "加拿大_469138946ba5fa", "澳大利亚_469138946ba5fa", "法国_469138946ba5fa", "荷兰_469138946ba5fa"] },
${_REGIONAL_URLTEST}
${_ANYTLS_BLOCK}
$(get_shared_outbounds)${_EXTRA_OBS}
  ],
  "route": {
    "rules": [
      { "port": [110, 143, 25, 465, 587, 993, 994, 995], "outbound": "代理_469138946ba5fa" },
      { "package_name": ["com.duolingo"], "outbound": "代理_469138946ba5fa" },
      { "rule_set": "geosite-duolingo", "outbound": "代理_469138946ba5fa" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "port": 53, "action": "hijack-dns" },
      { "process_name": [ "sing-box.exe", "sing-box", "io.nekohasekai.sfa" ], "outbound": "直连_469138946ba5fa" },
      { "rule_set": [ "geosite-category-ads-all", "megamori" ], "action": "reject" },
      { "domain": [ ${_AD_DOMAINS} ], "action": "reject" },
      { "inbound": [ "混合入站_469138946ba5fa", "TUN入站_469138946ba5fa" ], "action": "sniff" },
      { "ip_is_private": true, "outbound": "直连_469138946ba5fa" },
      ${_PRIVATE_RULE}
      { "rule_set": "geosite-cn", "outbound": "直连_469138946ba5fa" },
      { "rule_set": "geoip-cn", "outbound": "直连_469138946ba5fa" },
      { "rule_set": "category-ai-!cn", "outbound": "智能_469138946ba5fa" },
      { "rule_set": "geosite-geolocation-!cn", "outbound": "代理_469138946ba5fa" }
    ],
    "rule_set": [
${_D_RULESETS}
    ],
${_D_ROUTE_TAIL}
  },
  "experimental": {
${_D_EXP}
  }
}
469138946ba5fa
}

# ── 最新版客户端 ─────────────────────────────────────────────
gen_client "client.json" \
  "" \
  "${_CF_TAGS_CSV}" \
  "${_CF_OB_JSON}" \
  '{ "rule_set": "geosite-private", "outbound": "直连_469138946ba5fa" },' \
  "$(get_shared_outbounds_anytls)"

# ── OpenWrt 版 ───────────────────────────────────────────────
gen_client "client_openwrt_sing-box.json" \
  '"interface_name": "tun0",' \
  "" \
  "" \
  "" \
  "$(get_shared_outbounds_anytls)"

# ── 1.11.4 版 ────────────────────────────────────────────────
gen_client "client_1.11.4.json" \
  "" \
  "${_CF_TAGS_CSV}" \
  "${_CF_OB_JSON}" \
  '{ "rule_set": "geosite-private", "outbound": "直连_469138946ba5fa" },' \
  ""  # 留空，解决 1.11.4 不支持 AnyTLS 的报错

# 全部节点分享链接
# =====================================================================
echo "正在生成全部节点分享链接..."

# ── 直连节点 ─────────────────────────────────────────────────
LINK_VLESS="vless://${UUID_VLESS}@${SERVER_IP}:${PORT_VLESS}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${BEST_DOMAIN}&insecure=${INSECURE_REALITY_LINK}&fp=${FINGERPRINT_TYPE}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID_VLESS}&type=tcp#${OUTBOUND_VLESS}"
LINK_TROJAN="trojan://${PASSWORD_TROJAN}@${SERVER_IP}:${PORT_TROJAN}?security=reality&sni=${BEST_DOMAIN}&insecure=${INSECURE_REALITY_LINK}&fp=${FINGERPRINT_TYPE}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID_TROJAN}&type=tcp#${OUTBOUND_TROJAN}"
LINK_ANYTLS="anytls://${PASSWORD_ANYTLS}@${SERVER_IP}:${PORT_ANYTLS}?security=reality&sni=${BEST_DOMAIN}&insecure=${INSECURE_REALITY_LINK}&fp=${FINGERPRINT_TYPE}&pbk=${PUBLIC_KEY}&sid=${SHORT_ID_ANYTLS}&type=tcp#${OUTBOUND_ANYTLS}"
LINK_HYSTERIA2="hysteria2://${PASSWORD_HYSTERIA2}@${SERVER_IP}:${PORT_HYSTERIA2}?obfs=${HY2_OBFS_TYPE}&obfs-password=${HY2_OBFS_PASSWORD}&alpn=${ALPN_QUIC_LINK}&sni=${BEST_DOMAIN}&insecure=${INSECURE_SELFSIGNED_LINK}#${OUTBOUND_HYSTERIA2}"
LINK_TUIC="tuic://${UUID_TUIC}:${PASSWORD_TUIC}@${SERVER_IP}:${PORT_TUIC}?congestion_control=bbr&alpn=${ALPN_QUIC_LINK}&sni=${BEST_DOMAIN}&insecure=${INSECURE_SELFSIGNED_LINK}&version=5&udp_relay_mode=native#${OUTBOUND_TUIC}"
LINK_VMESS_REALITY=$(make_vmess "${OUTBOUND_VMESS_REALITY}" "${SERVER_IP}" "${PORT_VMESS_REALITY}" "${UUID_VMESS_REALITY}" "tcp" "" "" "reality" "${BEST_DOMAIN}" "${PUBLIC_KEY}" "${SHORT_ID_VMESS_REALITY}" "${FINGERPRINT_TYPE}" "${INSECURE_REALITY_LINK}")
LINK_VMESS_WS_TLS=$(make_vmess "${OUTBOUND_VMESS_WS_TLS}" "${SERVER_IP}" "${PORT_VMESS_WS_TLS}" "${UUID_VMESS_WS_TLS}" "ws" "${BEST_DOMAIN}" "/${PATH_VMESS_WS_TLS}" "tls" "${BEST_DOMAIN}" "" "" "" "${INSECURE_SELFSIGNED_LINK}" "${ALPN_WS_LINK}")
#LINK_VMESS_WS=$(make_vmess    "${OUTBOUND_VMESS_WS}"     "${SERVER_IP}" "${PORT_VMESS_WS}"     "${UUID_VMESS_WS}"     "ws" "${BEST_DOMAIN}"  "/${PATH_VMESS_WS}"     ""    "")
LINK_VLESS_WS=$(make_vless_ws    "${OUTBOUND_VLESS_WS}"     "${SERVER_IP}" "${PORT_VLESS_WS}"     "${UUID_VLESS_WS}"     "${BEST_DOMAIN}"  "/${PATH_VLESS_WS}"     ""    "")

# ── 拼合订阅并 base64 ────────────────────────────────────────
#${LINK_VMESS_WS}
#${LINK_VLESS_WS}
SUBSCRIPTION_CONTENT="${LINK_VLESS}
${LINK_TROJAN}
${LINK_ANYTLS}
${LINK_HYSTERIA2}
${LINK_TUIC}
${LINK_VMESS_REALITY}
${LINK_VMESS_WS_TLS}
${LINK_VLESS_WS}
${CF_LINKS}"

SUBSCRIPTION_BASE64=$(printf "%s" "${SUBSCRIPTION_CONTENT}" | base64 | tr -d "\n")
printf "%s\n" "${SUBSCRIPTION_CONTENT}" > "${WORKDIR}/subscription.txt"
printf "%s\n" "${SUBSCRIPTION_BASE64}"  > "${WORKDIR}/subscription_base64.txt"


# =====================================================================
# 订阅 URI ↔ client.json 一致性检查
# 说明：检查所有“可以由 URI 表达”的语义字段；JSON-only 参数（例如
# Hysteria2/TUIC 的 certificate）只报告 INFO，不当成错误。服务器私钥
#（Reality private_key / TLS key）属于 SERVER_ONLY，也不会要求出现在 URI。
# =====================================================================
check_subscription_consistency() {
  local cfg="${WORKDIR}/client.json"
  local sub="${WORKDIR}/subscription.txt"
  local errors=0
  local warnings=0

  if [ ! -s "$cfg" ] || [ ! -s "$sub" ]; then
    echo "⚠ 一致性检查跳过：client.json 或 subscription.txt 不存在"
    return 0
  fi

  local uri_get_param
  uri_get_param() {
    local uri="$1" key="$2"
    printf '%s\n' "$uri" | sed -n "s#.*[?&]${key}=\([^&#]*\).*#\1#p"
  }

  local uri_fragment
  uri_fragment() {
    local uri="$1"
    printf '%s\n' "$uri" | sed 's/.*#//'
  }

  local b64_decode
  b64_decode() {
    printf '%s' "$1" | base64 -d 2>/dev/null || true
  }

  local bool_to_link
  bool_to_link() {
    case "$1" in
      true) printf '1' ;;
      false) printf '0' ;;
      *) printf '%s' "$1" ;;
    esac
  }

  local json_field
  json_field() {
    local obj="$1" filter="$2"
    jq -r "($filter) | if . == null then \"\" else tostring end" <<<"$obj" 2>/dev/null
  }

  local find_uri_for_tag
  find_uri_for_tag() {
    local tag="$1" line decoded fragment
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in
        vmess://*)
          decoded=$(b64_decode "${line#vmess://}")
          if [ -n "$decoded" ] && [ "$(jq -r '.ps // empty' <<<"$decoded" 2>/dev/null)" = "$tag" ]; then
            printf '%s\n' "$line"
            return 0
          fi
          ;;
        *)
          fragment=$(uri_fragment "$line")
          if [ "$fragment" = "$tag" ]; then
            printf '%s\n' "$line"
            return 0
          fi
          ;;
      esac
    done < "$sub"
    return 1
  }

  check_eq() {
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
      echo "  [OK] ${name}: ${actual}"
    else
      echo "  [ERROR] ${name}: client=${actual:-<空>} uri=${expected:-<空>}"
      errors=$((errors+1))
    fi
  }

  check_optional_eq() {
    local name="$1" actual="$2" expected="$3"
    if [ -z "$actual" ] && [ -z "$expected" ]; then
      return 0
    fi
    check_eq "$name" "$actual" "$expected"
  }

  echo "===================================="
  echo "  订阅 URI ↔ client.json 一致性检查"
  echo "===================================="

  # 先确认 client.json 本身能被 jq 完整解析。
  if ! jq -e . "$cfg" >/dev/null 2>&1; then
    echo "  [ERROR] client.json 不是有效 JSON"
    echo "===================================="
    return 0
  fi

  # ── Hysteria2 / TUIC / VLESS / Trojan / AnyTLS / VMess ───────────────
  local obj tag type uri
  while IFS= read -r obj; do
    [ -z "$obj" ] && continue
    tag=$(json_field "$obj" '.tag')
    type=$(json_field "$obj" '.type')
    [ -z "$tag" ] && continue

    case "$type" in
      hysteria2|tuic|vless|trojan|anytls|vmess)
        uri=$(find_uri_for_tag "$tag" || true)
        if [ -z "$uri" ]; then
          echo "  [ERROR] ${type} ${tag}: subscription.txt 未找到对应 URI"
          errors=$((errors+1))
          continue
        fi
        ;;
      *)
        continue
        ;;
    esac

    echo "  ├─ ${type}: ${tag}"

    case "$type" in
      hysteria2)
        check_eq "    server" "$(json_field "$obj" '.server')" "$(printf '%s\n' "$uri" | sed -n 's#^[^@]*@\([^:]*\):.*#\1#p')"
        check_eq "    port" "$(json_field "$obj" '.server_port')" "$(printf '%s\n' "$uri" | sed -n 's#^[^@]*@[^:]*:\([^?]*\).*#\1#p')"
        check_eq "    password" "$(json_field "$obj" '.password')" "$(printf '%s\n' "$uri" | sed -n 's#^hysteria2://\([^@]*\)@.*#\1#p')"
        check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(uri_get_param "$uri" 'sni')"
        check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(uri_get_param "$uri" 'insecure')"
        check_eq "    ALPN" "$(json_field "$obj" '.tls.alpn[0]')" "$(uri_get_param "$uri" 'alpn')"
        check_optional_eq "    obfs.type" "$(json_field "$obj" '.obfs.type')" "$(uri_get_param "$uri" 'obfs')"
        check_optional_eq "    obfs.password" "$(json_field "$obj" '.obfs.password')" "$(uri_get_param "$uri" 'obfs-password')"
        if jq -e '.tls.certificate != null' <<<"$obj" >/dev/null 2>&1; then
          echo "  [INFO]     certificate: JSON-only（URI 无需携带）"
          warnings=$((warnings+1))
        fi
        ;;

      tuic)
        check_eq "    server" "$(json_field "$obj" '.server')" "$(printf '%s\n' "$uri" | sed -n 's#^[^@]*@\([^:]*\):.*#\1#p')"
        check_eq "    port" "$(json_field "$obj" '.server_port')" "$(printf '%s\n' "$uri" | sed -n 's#^[^@]*@[^:]*:\([^?]*\).*#\1#p')"
        check_eq "    UUID" "$(json_field "$obj" '.uuid')" "$(printf '%s\n' "$uri" | sed -n 's#^tuic://\([^:]*\):.*#\1#p')"
        check_eq "    password" "$(json_field "$obj" '.password')" "$(printf '%s\n' "$uri" | sed -n 's#^tuic://[^:]*:\([^@]*\)@.*#\1#p')"
        check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(uri_get_param "$uri" 'sni')"
        check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(uri_get_param "$uri" 'insecure')"
        check_eq "    ALPN" "$(json_field "$obj" '.tls.alpn[0]')" "$(uri_get_param "$uri" 'alpn')"
        check_eq "    congestion_control" "$(json_field "$obj" '.congestion_control // ""')" "$(uri_get_param "$uri" 'congestion_control')"
        check_eq "    version" "$(json_field "$obj" '.version // 5')" "$(uri_get_param "$uri" 'version')"
        check_eq "    udp_relay_mode" "$(json_field "$obj" '.udp_relay_mode // "native"')" "$(uri_get_param "$uri" 'udp_relay_mode')"
        if jq -e '.tls.certificate != null' <<<"$obj" >/dev/null 2>&1; then
          echo "  [INFO]     certificate: JSON-only（URI 无需携带）"
          warnings=$((warnings+1))
        fi
        ;;

      vless)
        check_eq "    server" "$(json_field "$obj" '.server')" "$(printf '%s\n' "$uri" | sed -n 's#^vless://[^@]*@\([^:]*\):.*#\1#p')"
        check_eq "    port" "$(json_field "$obj" '.server_port')" "$(printf '%s\n' "$uri" | sed -n 's#^vless://[^@]*@[^:]*:\([^?]*\).*#\1#p')"
        check_eq "    UUID" "$(json_field "$obj" '.uuid')" "$(printf '%s\n' "$uri" | sed -n 's#^vless://\([^@]*\)@.*#\1#p')"
        check_optional_eq "    flow" "$(json_field "$obj" '.flow')" "$(uri_get_param "$uri" 'flow')"
        check_optional_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(uri_get_param "$uri" 'sni')"
        if jq -e '.tls != null and .tls.reality != null and .tls.reality.enabled == true' <<<"$obj" >/dev/null 2>&1; then
          check_eq "    security" "reality" "$(uri_get_param "$uri" 'security')"
          check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(uri_get_param "$uri" 'insecure')"
          check_eq "    fingerprint" "$(json_field "$obj" '.tls.utls.fingerprint')" "$(uri_get_param "$uri" 'fp')"
          check_eq "    public_key" "$(json_field "$obj" '.tls.reality.public_key')" "$(uri_get_param "$uri" 'pbk')"
          check_eq "    short_id" "$(json_field "$obj" '.tls.reality.short_id')" "$(uri_get_param "$uri" 'sid')"
          check_eq "    type" "tcp" "$(uri_get_param "$uri" 'type')"
        else
          check_eq "    type" "ws" "$(uri_get_param "$uri" 'type')"
          check_optional_eq "    host" "$(json_field "$obj" '.transport.headers.Host')" "$(uri_get_param "$uri" 'host')"
          check_optional_eq "    path" "$(json_field "$obj" '.transport.path')" "$(uri_get_param "$uri" 'path')"
          if jq -e '.tls != null and .tls.enabled == true' <<<"$obj" >/dev/null 2>&1; then
            check_eq "    security" "tls" "$(uri_get_param "$uri" 'security')"
            check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(uri_get_param "$uri" 'allowInsecure')"
            check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(uri_get_param "$uri" 'sni')"
            check_optional_eq "    ALPN" "$(json_field "$obj" '.tls.alpn[0]')" "$(uri_get_param "$uri" 'alpn')"
            check_optional_eq "    fingerprint" "$(json_field "$obj" '.tls.utls.fingerprint')" "$(uri_get_param "$uri" 'fp')"
          else
            check_optional_eq "    security" "none" "$(uri_get_param "$uri" 'security')"
          fi
        fi
        ;;

      trojan|anytls)
        check_eq "    server" "$(json_field "$obj" '.server')" "$(printf '%s\n' "$uri" | sed -n "s#^${type}://[^@]*@\([^:]*\):.*#\1#p")"
        check_eq "    port" "$(json_field "$obj" '.server_port')" "$(printf '%s\n' "$uri" | sed -n "s#^${type}://[^@]*@[^:]*:\([^?]*\).*#\1#p")"
        check_eq "    password" "$(json_field "$obj" '.password')" "$(printf '%s\n' "$uri" | sed -n "s#^${type}://\([^@]*\)@.*#\1#p")"
        check_eq "    security" "reality" "$(uri_get_param "$uri" 'security')"
        check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(uri_get_param "$uri" 'sni')"
        check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(uri_get_param "$uri" 'insecure')"
        check_eq "    fingerprint" "$(json_field "$obj" '.tls.utls.fingerprint')" "$(uri_get_param "$uri" 'fp')"
        check_eq "    public_key" "$(json_field "$obj" '.tls.reality.public_key')" "$(uri_get_param "$uri" 'pbk')"
        check_eq "    short_id" "$(json_field "$obj" '.tls.reality.short_id')" "$(uri_get_param "$uri" 'sid')"
        ;;

      vmess)
        # VMess 分享 URI 使用 Base64 JSON；按 ps 已经在 find_uri_for_tag() 对上节点。
        local vm_decoded
        vm_decoded=$(b64_decode "${uri#vmess://}")
        check_eq "    server" "$(json_field "$obj" '.server')" "$(json_field "$vm_decoded" '.add')"
        check_eq "    port" "$(json_field "$obj" '.server_port')" "$(json_field "$vm_decoded" '.port')"
        check_eq "    UUID" "$(json_field "$obj" '.uuid')" "$(json_field "$vm_decoded" '.id')"
        if jq -e '.tls != null and .tls.reality != null and .tls.reality.enabled == true' <<<"$obj" >/dev/null 2>&1; then
          check_eq "    TLS" "reality" "$(json_field "$vm_decoded" '.tls')"
          check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(json_field "$vm_decoded" '.sni')"
          check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(json_field "$vm_decoded" '.allowInsecure')"
          check_eq "    fingerprint" "$(json_field "$obj" '.tls.utls.fingerprint')" "$(json_field "$vm_decoded" '.fp')"
          check_eq "    public_key" "$(json_field "$obj" '.tls.reality.public_key')" "$(json_field "$vm_decoded" '.pbk')"
          check_eq "    short_id" "$(json_field "$obj" '.tls.reality.short_id')" "$(json_field "$vm_decoded" '.sid')"
        elif jq -e '.tls != null and .tls.enabled == true' <<<"$obj" >/dev/null 2>&1; then
          check_eq "    TLS" "true" "$(if [ "$(json_field "$vm_decoded" '.tls')" = "tls" ]; then printf true; else printf false; fi)"
          check_optional_eq "    network" "$(json_field "$obj" '.transport.type')" "$(json_field "$vm_decoded" '.net')"
          check_eq "    SNI" "$(json_field "$obj" '.tls.server_name')" "$(json_field "$vm_decoded" '.sni')"
          check_eq "    insecure" "$(bool_to_link "$(json_field "$obj" '.tls.insecure')")" "$(json_field "$vm_decoded" '.allowInsecure')"
          check_optional_eq "    ALPN" "$(json_field "$obj" '.tls.alpn[0]')" "$(json_field "$vm_decoded" '.alpn')"
          check_optional_eq "    path" "$(json_field "$obj" '.transport.path')" "$(json_field "$vm_decoded" '.path')"
          check_optional_eq "    host" "$(json_field "$obj" '.transport.headers.Host')" "$(json_field "$vm_decoded" '.host')"
        fi
        ;;
    esac
  done < <(jq -c '.outbounds[] | select(.server != null and .server != "")' "$cfg")

  echo "------------------------------------"
  if [ "$errors" -eq 0 ]; then
    echo "✔ 一致性检查通过：全部真实节点没有发现明确的 URI/JSON 参数冲突"
  else
    echo "✘ 一致性检查发现 ${errors} 个明确冲突"
  fi
  echo "ℹ JSON-only 参数提示 ${warnings} 个；这些不是错误"
  echo "------------------------------------"
  return 0
}

check_subscription_consistency

#  VMESS_WS → ${UUID_VMESS_WS}
#  VLESS_WS → ${UUID_VLESS_WS}
#Cloudflare Domain: ${CLOUDFLARED_DOMAIN_VMESS_WS}
#Cloudflare Domain: ${CLOUDFLARED_DOMAIN_VLESS_WS}
#  VMESS_WS       : ${PORT_VMESS_WS}
#  VLESS_WS       : ${PORT_VLESS_WS}
#  nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VMESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VMESS_WS}.log 2>&1 & disown
#  nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VLESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log 2>&1 & disown
cat > ${WORKDIR}/result.txt <<469138946ba5fa
====================================
       Reality Sing-box 生成报告
====================================

服务器 IP: ${SERVER_IP}

sing-box 版本: ${SING_BOX_ACTUAL_VERSION}

Public Key: ${PUBLIC_KEY}
Private Key: ${PRIVATE_KEY}

UUID (独立)：
  VLESS → ${UUID_VLESS}
  TUIC  → ${UUID_TUIC}
  VMESS_REALITY → ${UUID_VMESS_REALITY}
  VMESS_WS_TLS → ${UUID_VMESS_WS_TLS}
  VLESS_WS → ${UUID_VLESS_WS}

Password (hysteria2 用): ${PASSWORD_HYSTERIA2}
Password (tuic 用): ${PASSWORD_TUIC}
Password (trojan 用): ${PASSWORD_TROJAN}
Password (anytls 用): ${PASSWORD_ANYTLS}
Hysteria2 obfs: ${HY2_OBFS_TYPE}
Hysteria2 obfs-password: ${HY2_OBFS_PASSWORD}

Fake SNI / server_name: ${BEST_DOMAIN}

Handshake Domain: ${BEST_DOMAIN}

Cloudflare Domain: ${CLOUDFLARED_DOMAIN_VLESS_WS}
Cloudflare Proxy Domain: ${CLOUDFLARED_PROXYIP}:${CLOUDFLARED_PROXYIP_PORT}
CFNAT PROXYIP: ${SERVER_CFNAT}:${PORT_CFNAT}

端口：
  VLESS          : ${PORT_VLESS}
  Trojan         : ${PORT_TROJAN}
  AnyTLS         : ${PORT_ANYTLS}
  Hysteria2      : ${PORT_HYSTERIA2}
  TUIC           : ${PORT_TUIC}
  VMESS_REALITY  : ${PORT_VMESS_REALITY}
  VMESS_WS_TLS   : ${PORT_VMESS_WS_TLS}
  VLESS_WS       : ${PORT_VLESS_WS}

Short IDs（多组）：
  VLESS  : ${SHORT_IDS_VLESS}
  Trojan : ${SHORT_IDS_TROJAN}
  AnyTLS : ${SHORT_IDS_ANYTLS}
  VMESS : ${SHORT_IDS_VMESS_REALITY}
469138946ba5fa

#[5]  VMess WS:             ${LINK_VMESS_WS}
#[5]  VLess WS:             ${LINK_VLESS_WS}
cat >> ${WORKDIR}/result.txt <<469138946ba5fa
====================================
  节点分享链接（全部 ${_TOTAL_NODES} 条）
====================================

--- 直连协议（推荐优先使用）---
[1]  VLESS Reality:        ${LINK_VLESS}
[2]  Trojan Reality:       ${LINK_TROJAN}
[3]  VMess Reality:        ${LINK_VMESS_REALITY}
[4]  VMess WS TLS:         ${LINK_VMESS_WS_TLS}
[5]  VLess WS:             ${LINK_VLESS_WS}
[6]  Hysteria2 (UDP):      ${LINK_HYSTERIA2}
[7]  TUIC (UDP):           ${LINK_TUIC}
[8]  AnyTLS (仅sing-box):  ${LINK_ANYTLS}

--- Cloudflare CDN 中转（抗封锁备用）---
${CF_RESULT_LINES}

====================================
  Base64 订阅码（全部 ${_TOTAL_NODES} 条）
  Shadowrocket / V2RayN / NekoBox 直接粘贴导入
====================================

${SUBSCRIPTION_BASE64}

后台运行所用命令：
  nohup ${WORKDIR}/sing-boxs/sing-box -D ${WORKDIR}/config -c ${WORKDIR}/config.json run > ${WORKDIR}/sing-box.log 2>&1 & disown
  nohup ${WORKDIR}/cloudflared tunnel --url http://127.0.0.1:$PORT_VLESS_WS --no-autoupdate --edge-ip-version auto --protocol http2 > ${WORKDIR}/cloudflared_${PORT_VLESS_WS}.log 2>&1 & disown

证书已内嵌，无需额外文件。
====================================
469138946ba5fa

# =====================================================================
#  限制 result.txt 权限，避免同机其他用户读取所有密钥/密码
# =====================================================================
chmod 600 "${WORKDIR}/result.txt"
chmod 600 "${WORKDIR}/subscription.txt"
chmod 600 "${WORKDIR}/subscription_base64.txt"

# 最后统一处理生成的 client json：按 tag 内容自动归类到对应国家分组。
# 这段只是"锦上添花"的自动分类，即便中途出错也只让对应分组保持占位
# 指向 直连_（不影响前面已经装好、已经在跑的 sing-box 服务）。
GROUPS_PATTERNS=$(cat <<'469138946ba5fa'
德国_469138946ba5fa|德国|德|\bDE\b|Germany|Frankfurt|Frankfurt am Main|Berlin|Munich|München|Hamburg|Dusseldorf|Düsseldorf|Cologne|Köln|Stuttgart|法兰克福|柏林|慕尼黑|汉堡|杜塞尔多夫|科隆|斯图加特|🇩🇪
日本_469138946ba5fa|日本|日|\bJP\b|Japan|Tokyo|Osaka|Nagoya|Yokohama|Sapporo|Fukuoka|东京|大阪|名古屋|横滨|札幌|福冈|🇯🇵
新加坡_469138946ba5fa|新加坡|坡|\bSG\b|Singapore|Singapore City|Lion City|狮城|🇸🇬
香港_469138946ba5fa|香港|港|\bHK\b|Hong Kong|HongKong|HKG|🇭🇰
台湾_469138946ba5fa|台湾|台|\bTW\b|Taiwan|Taipei|Taichung|Kaohsiung|Tainan|Hsinchu|Changhua|New Taipei|台北|台中|高雄|台南|新竹|彰化|新北|🇹🇼
韩国_469138946ba5fa|韩国|韩|\bKR\b|Korea|South Korea|Seoul|Busan|Incheon|首尔|釜山|仁川|🇰🇷
英国_469138946ba5fa|英国|英|\bUK\b|GB|United Kingdom|England|London|Manchester|伦敦|曼彻斯特|🇬🇧
加拿大_469138946ba5fa|加拿大|加|\bCA\b|Canada|Toronto|Vancouver|Montreal|多伦多|温哥华|蒙特利尔|🇨🇦
澳大利亚_469138946ba5fa|澳大利亚|澳|\bAU\b|Australia|Sydney|Melbourne|Brisbane|Perth|悉尼|墨尔本|布里斯班|珀斯|🇦🇺
法国_469138946ba5fa|法国|法|\bFR\b|France|Paris|Marseille|巴黎|马赛|🇫🇷
荷兰_469138946ba5fa|荷兰|荷|\bNL\b|Netherlands|Amsterdam|阿姆斯特丹|🇳🇱
美国_469138946ba5fa|美国|美|\bUS\b|USA|United States|America|Los Angeles|LA|San Francisco|SF|Silicon Valley|San Jose|Seattle|Chicago|Dallas|New York|NY|Miami|Atlanta|Ashburn|Phoenix|Las Vegas|Denver|洛杉矶|旧金山|硅谷|圣何塞|西雅图|芝加哥|达拉斯|纽约|迈阿密|亚特兰大|阿什本|凤凰城|拉斯维加斯|丹佛|🇺🇸
469138946ba5fa
)
# ↑ 所有 ≤3 字母的短代码（DE/JP/US/USA/SG/HK/TW/KR/UK/GB/CA/AU/FR/NL/LA/SF/NY）
# 统一加了 \b 词边界，长单词/城市名/中文/emoji 不受影响。原因是实测发现两类真实碰撞：
#   1) DE、CA 恰好是合法的16进制字符组合，32位随机 UUID 里大概率（约11%/个）会偶然
#      带出"de"或"ca"子串，误判进德国/加拿大；
#   2) 更严重的是"NY"：AnyTLS 协议固定 tag 前缀"anytls-out-"本身就包含"ny"，不管
#      服务器在哪、不管有没有设置地区前缀，每次生成都会 100% 把 AnyTLS 节点误分类进
#      美国组。这个是必现 bug，不是概率性的。

NODES="${WORKDIR}/.filtered_nodes.json"
NODES_CONFIG_TMP="${WORKDIR}/.tmp_client.json"

configs=(
  "${WORKDIR}/client_1.11.4.json"
  "${WORKDIR}/client.json"
  "${WORKDIR}/client_openwrt_sing-box.json"
)

set +e  # 分类失败不该让已经跑通的安装以非零状态退出
for NODES_CONFIG in "${configs[@]}"; do
  if [ ! -f "${NODES_CONFIG}" ]; then
    echo "  ⚠ 跳过：${NODES_CONFIG} 不存在"
    continue
  fi

  # 从生成好的 client json 里提取真实协议节点（用是否带 server 字段
  # 区分"真实节点" vs "selector/urltest 分组壳子"）
  jq '[.outbounds[] | select(.server != null and .server != "")]' "${NODES_CONFIG}" > "${NODES}" 2>/dev/null
  if [ $? -ne 0 ] || [ ! -s "${NODES}" ]; then
    echo "  ⚠ 跳过：${NODES_CONFIG} 节点提取失败（jq 解析出错或结果为空）"
    continue
  fi
  chmod 600 "${NODES}"

  # 遍历分组定义，每行格式：tag|pattern
  # 已匹配过的节点集合（互斥用）
  matched_all='[]'
  while IFS='|' read -r tag pattern; do
    echo "处理分组：$tag"
  
    # 只匹配「还没有被任何分组抢走」的节点
    matched=$(jq --arg pattern "$pattern" --argjson already "$matched_all" '
      [.[]
       | select(.tag | test($pattern; "i"))
       | select(.tag as $t | ($already | index($t) | not))
       | .tag]
    ' "${NODES}" 2>/dev/null)

    if [ $? -ne 0 ]; then
      echo "  ⚠ 正则匹配出错，跳过该分组（检查 pattern 里是否有特殊字符没转义）"
      continue
    fi

    # 如果没有匹配结果，跳过
    if [ "$(echo "$matched" | jq 'length')" -eq 0 ]; then
      echo "  ➤ 无匹配节点，跳过"
      continue
    fi
  
    # 把本轮匹配到的节点加入总集合
    matched_all=$(jq -n --argjson new "$matched" --argjson old "$matched_all" '
      $old + $new | unique
    ')

    exists=$(jq --arg tag "$tag" '.outbounds[] | select(.tag == $tag)' "${NODES_CONFIG}")

    if [ -z "$exists" ]; then
      echo "  ➤ 分组不存在，创建新 selector"
      jq --arg tag "$tag" --argjson outbounds "$matched" '
        .outbounds += [{
          type: "selector",
          tag: $tag,
          outbounds: $outbounds
        }]
      ' "${NODES_CONFIG}" > "${NODES_CONFIG_TMP}" && mv "${NODES_CONFIG_TMP}" "${NODES_CONFIG}"
    else
      echo "  ➤ 分组已存在，更新节点列表"
      jq --arg tag "$tag" --argjson outbounds "$matched" '
        .outbounds |= map(
          if .tag == $tag and (.type == "selector" or .type == "urltest") then
            . + {outbounds: $outbounds}
          else
            .
          end
        )
      ' "${NODES_CONFIG}" > "${NODES_CONFIG_TMP}" && mv "${NODES_CONFIG_TMP}" "${NODES_CONFIG}"
    fi
  done <<< "${GROUPS_PATTERNS}"

  chmod 600 "${NODES_CONFIG}"
done
rm -f "${NODES}" "${NODES_CONFIG_TMP}"
set -e

echo "cat ${WORKDIR}/client_1.11.4.json"
cat ${WORKDIR}/client_1.11.4.json
echo "cat ${WORKDIR}/client.json"
cat ${WORKDIR}/client.json
echo "cat ${WORKDIR}/client_openwrt_sing-box.json"
cat ${WORKDIR}/client_openwrt_sing-box.json
echo "cat ${WORKDIR}/subscription.txt"
cat ${WORKDIR}/subscription.txt
echo "cat ${WORKDIR}/subscription_base64.txt"
cat ${WORKDIR}/subscription_base64.txt
echo "cat ${WORKDIR}/result.txt"
cat ${WORKDIR}/result.txt

echo "服务端最新版配置文件已生成在：${WORKDIR}/config.json"
echo "客户端1.11.4版配置文件已生成在：${WORKDIR}/client_1.11.4.json"
echo "客户端配置文件已生成在：${WORKDIR}/client.json"
echo "客户端openwrt-sing-box版本配置文件已生成在：${WORKDIR}/client_openwrt_sing-box.json"
echo "节点明文链接已生成在：${WORKDIR}/subscription.txt"
echo "节点Base64已生成在：${WORKDIR}/subscription_base64.txt"
echo "总结信息：${WORKDIR}/result.txt"
echo "下次运行会生成全新随机值"