#!/bin/zsh
# ============================================================================
# 从源码构建“IDA 9.3 中文”启动器壳（macOS / Apple Silicon）
# ----------------------------------------------------------------------------
# 用法：
#   ./build.sh                            # 构建“IDA Professional 9.3 中文.app”
#   IDA_APP=/path/to/IDA.app ./build.sh   # 指定非默认位置的官方 IDA
#
# 依赖：本机已安装官方 IDA 9.3（用它的 Qt6 框架与图标，不修改它）、Xcode 命令行工具(clang)。
# 产物：当前目录下的 .app；它运行时用 open --env 把汉化库注入官方 IDA。
# ============================================================================
set -e

HERE="${0:A:h}"                                   # 本脚本所在目录
IDA_APP="${IDA_APP:-/Applications/IDA Professional 9.3.app}"
FW="$IDA_APP/Contents/Frameworks"

# --- 前置检查 ---
if [[ ! -d "$IDA_APP" ]]; then
  echo "✗ 未找到官方 IDA：$IDA_APP" >&2
  echo "  请先安装，或用 IDA_APP=/your/path/IDA.app ./build.sh 指定。" >&2
  exit 1
fi
for f in QtCore QtGui QtWidgets; do
  [[ -f "$FW/$f.framework/Versions/A/$f" ]] || { echo "✗ 缺少框架 $f" >&2; exit 1; }
done

echo "▶ 用的 IDA：$IDA_APP"

# --- 1) 编译注入库（必须链接 IDA 的 Qt 三框架，保证加载顺序与符号绑定）---
echo "▶ 编译 ida_lang_hook.dylib ..."
clang++ -std=c++17 -arch arm64 -dynamiclib -O2 \
  "$FW/QtCore.framework/Versions/A/QtCore" \
  "$FW/QtGui.framework/Versions/A/QtGui" \
  "$FW/QtWidgets.framework/Versions/A/QtWidgets" \
  -Wl,-rpath,"$FW" \
  -o "$HERE/ida_lang_hook.dylib" "$HERE/src/ida_zh_hook_mac.cpp"
codesign --force --sign - "$HERE/ida_lang_hook.dylib"

# --- 2) 编译启动器（Mach-O；脚本充当 app 主程序会被 LaunchServices 拒绝）---
echo "▶ 编译 ida-zh-launcher ..."
clang -arch arm64 -O2 -o "$HERE/ida-zh-launcher" "$HERE/src/ida-zh-launcher.c"

# --- 组装一个 .app 的函数：assemble <显示名> <bundleId> ---
assemble() {
  local name="$1" bid="$2"
  local app="$HERE/$name.app"
  echo "▶ 组装 $name.app ..."
  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$HERE/ida-zh-launcher"      "$app/Contents/MacOS/ida-zh-launcher"
  chmod +x "$app/Contents/MacOS/ida-zh-launcher"
  cp "$HERE/ida_lang_hook.dylib"  "$app/Contents/Resources/ida_lang_hook.dylib"
  cp "$HERE/ida_lang.txt"         "$app/Contents/Resources/ida_lang.txt"
  # 图标从本机 IDA 复制（不随仓库分发）
  cp "$IDA_APP/Contents/Resources/appico.icns" "$app/Contents/Resources/appico.icns" 2>/dev/null || true
  # Info.plist
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>ida-zh-launcher</string>
  <key>CFBundleName</key><string>$name</string>
  <key>CFBundleDisplayName</key><string>$name</string>
  <key>CFBundleIdentifier</key><string>$bid</string>
  <key>CFBundleIconFile</key><string>appico.icns</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>9.3-zh</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
  codesign --force --deep --sign - "$app"
  echo "  ✓ $app"
}

# --- 3) 组装 ---
assemble "IDA Professional 9.3 中文" "com.hexrays.ida.zh"

# --- 4) 刷新 LaunchServices 注册，让 Finder 立刻认出 ---
LSREG=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSREG" -f "$HERE/IDA Professional 9.3 中文.app" 2>/dev/null || true

echo ""
echo "✅ 完成。双击「IDA Professional 9.3 中文.app」即可启动中文版 IDA。"
