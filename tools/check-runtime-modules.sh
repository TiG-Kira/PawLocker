#!/usr/bin/env bash
#
# 用「打包出的那份 runtime 实际保留的模块集」去跑一遍运行时能力检查。
#
# 解决的问题：Gradle 测试跑在完整 JDK 上，装进 MSI 的应用跑在 jlink 裁剪过的
# runtime 上。两者不等价，而差异只在安装版暴露。这个脚本把那个风险提前到构建期。
#
# 用法：
#     tools/check-runtime-modules.sh
#
# 前置：先跑过一次 MSI 打包，让 runtime 生成出来
#     ./gradlew :windowsApp:packageMsi
#
# 模块清单不是写死的，而是从 runtime/release 文件里读——这样它永远和实际
# 打包结果一致，不会因为 Compose 升级改了默认模块集而悄悄失效。

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$(pwd)"

RELEASE="$ROOT/windowsApp/build/compose/tmp/main/runtime/release"
PROBE_SRC="$ROOT/tools/RuntimeModuleCheck.java"
VERSIONS="$ROOT/gradle/libs.versions.toml"

if [ ! -f "$RELEASE" ]; then
  echo "找不到打包出的 runtime：$RELEASE" >&2
  echo "先跑一次： ./gradlew :windowsApp:packageMsi" >&2
  exit 2
fi

# ── 1. 读出裁剪后实际保留的模块 ──────────────────────────────────────────
MODULES_SPACE="$(sed -n 's/^MODULES="\(.*\)"$/\1/p' "$RELEASE" | tr -d '\r')"
if [ -z "$MODULES_SPACE" ]; then
  echo "无法从 $RELEASE 解析 MODULES" >&2
  exit 2
fi
MODULES_CSV="${MODULES_SPACE// /,}"

echo "runtime 保留的模块（共 $(echo "$MODULES_SPACE" | wc -w) 个）："
for m in $MODULES_SPACE; do echo "    $m"; done
echo

# ── 2. 找 JDK ────────────────────────────────────────────────────────────
JAVA_HOME="${JAVA_HOME:-}"
# Windows 上 JAVA_HOME 常写成 D:\Programs\... —— 反斜杠换成斜杠，
# 让后面的路径拼接在 Git Bash 下也能被正确识别（虽然 Windows API 两种都认）。
JAVA_HOME="${JAVA_HOME//\\//}"

EXE=""
[ -f "$JAVA_HOME/bin/java.exe" ] && EXE=".exe"
JAVAC="$JAVA_HOME/bin/javac${EXE}"
JAVA="$JAVA_HOME/bin/java${EXE}"

if [ ! -f "$JAVAC" ]; then
  echo "JAVA_HOME 未指向可用的 JDK（当前：${JAVA_HOME:-<未设置>}）" >&2
  exit 2
fi

# ── 3. 找 JNA 的两个 jar ─────────────────────────────────────────────────
# 版本从 libs.versions.toml 读，避免硬编码后随升级漂移。
JNA_VERSION="$(sed -n 's/^[[:space:]]*jna[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$VERSIONS" | head -1)"
if [ -z "$JNA_VERSION" ]; then
  echo "无法从 $VERSIONS 读出 jna 版本" >&2
  exit 2
fi

CACHE="${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2"
JNA="$(find "$CACHE" -name "jna-$JNA_VERSION.jar" 2>/dev/null | head -1)"
JNA_PLATFORM="$(find "$CACHE" -name "jna-platform-$JNA_VERSION.jar" 2>/dev/null | head -1)"

if [ -z "$JNA" ] || [ -z "$JNA_PLATFORM" ]; then
  echo "在 Gradle 缓存里找不到 jna-$JNA_VERSION / jna-platform-$JNA_VERSION" >&2
  echo "先跑一次构建把依赖拉下来： ./gradlew :core:desktopTest" >&2
  exit 2
fi

# 这两个 jar 位于 POSIX 形式路径下；Windows 版的 javac/java 需要盘符形式。
to_win() { printf '%s' "$1" | sed -e 's#^/\([a-zA-Z]\)/#\1:/#' ; }
CP="$(to_win "$JNA");$(to_win "$JNA_PLATFORM")"

# ── 4. 编译探针 ──────────────────────────────────────────────────────────
# 不用 mktemp：MSYS 会给出 /tmp/... 这种 POSIX 路径，而 Windows 版的 javac
# 不认它，转盘符形式又没规律。落在项目 build/ 下最省事，那里本来就已被忽略。
TMP="$ROOT/build/runtime-module-check"
rm -rf "$TMP"
mkdir -p "$TMP"

echo "编译探针…"
MSYS_NO_PATHCONV=1 "$JAVAC" -nowarn -cp "$CP" -d "$(to_win "$TMP")" "$(to_win "$PROBE_SRC")"

# ── 5. 以裁剪后的模块集运行 ──────────────────────────────────────────────
echo "以 --limit-modules 模拟同等的裁剪条件运行："
echo
MSYS_NO_PATHCONV=1 "$JAVA" \
  -Dstdout.encoding=UTF-8 -Dstderr.encoding=UTF-8 \
  --limit-modules "$MODULES_CSV" \
  -cp "$(to_win "$TMP");$CP" \
  RuntimeModuleCheck
