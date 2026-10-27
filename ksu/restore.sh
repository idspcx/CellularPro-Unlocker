#!/system/bin/sh
# restore.sh -- 还原官方 lib: 优先用备份, 否则从已安装 APK 内解出
MODDIR=${0%/*}
[ -f "$MODDIR/config.sh" ] || MODDIR=/data/adb/modules/cellularpro_df
. "$MODDIR/config.sh"

apk=$(pm path "$PKG" 2>/dev/null | sed -n 's/^package://p' | head -1)
[ -n "$apk" ] || { echo "未安装 $PKG"; exit 1; }
LIB=$(dirname "$apk")/lib/arm64
TGT=$LIB/$SO_NAME

bak=$(ls -1 "$MODDIR"/backup/"$SO_NAME".*.so 2>/dev/null | head -1)
if [ -n "$bak" ] && [ "$(md5sum "$bak" | awk '{print $1}')" = "$STOCK_MD5" ]; then
  cp -f "$bak" "$TGT"; chmod 755 "$TGT"
  echo "已从备份还原: $bak"
else
  tmp=/data/local/tmp/cp_stock.$$
  rm -rf "$tmp"; mkdir -p "$tmp"
  unzip -o -q "$apk" "lib/arm64-v8a/$SO_NAME" -d "$tmp" || { echo "解包失败"; exit 1; }
  cp -f "$tmp/lib/arm64-v8a/$SO_NAME" "$TGT"; chmod 755 "$TGT"
  rm -rf "$tmp"
  echo "已从 APK 内解出官方 lib 还原"
fi
md5sum "$TGT"
echo "期望(官方): $STOCK_MD5"