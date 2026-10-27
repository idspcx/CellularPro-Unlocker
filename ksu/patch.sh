#!/system/bin/sh
# patch.sh -- 解析已安装 lib, 校验 md5/锚点后补入 df
# 用法: sh patch.sh [--quiet] [--force]
MODDIR=${0%/*}
[ -f "$MODDIR/config.sh" ] || MODDIR=/data/adb/modules/cellularpro_df
. "$MODDIR/config.sh"

LOGF=/data/adb/cellularpro_df.log
QUIET=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --quiet) QUIET=1 ;;
    --force) FORCE=1 ;;
  esac
done

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOGF"
  [ "$QUIET" -eq 1 ] || echo "$*"
}

md5of() { md5sum "$1" 2>/dev/null | awk '{print $1}'; }

find_lib() {
  apk=$(pm path "$PKG" 2>/dev/null | sed -n 's/^package://p' | head -1)
  if [ -n "$apk" ] && [ -f "$apk" ]; then
    d=$(dirname "$apk")/lib/arm64
    [ -d "$d" ] && { echo "$d"; return; }
  fi
  ls -d /data/app/*/"$PKG"-*/lib/arm64 2>/dev/null | head -1
}

LIB=$(find_lib)
[ -n "$LIB" ] || { log "跳过: 未找到 $PKG 的安装目录"; exit 1; }
TGT=$LIB/$SO_NAME
[ -f "$TGT" ] || { log "跳过: 缺 $TGT"; exit 1; }

cur=$(md5of "$TGT")
log "目标 $TGT 当前 $cur"

if [ "$cur" = "$PATCH_MD5" ] && [ "$FORCE" -eq 0 ]; then
  log "已解锁, 无需动作"
  exit 0
fi

if [ "$cur" = "$STOCK_MD5" ] || [ "$FORCE" -eq 1 ]; then
  cp -f "$MODDIR/payload/libQA.df.so" "$TGT" || { log "失败: 写入 $TGT"; exit 2; }
  chmod 755 "$TGT"
  new=$(md5of "$TGT")
  if [ "$new" = "$PATCH_MD5" ]; then
    log "已打补丁(整库替换) $new"
  else
    log "失败: 写入后 md5=$new"
    exit 2
  fi
else
  # 库变了(应用升级) -- 先验锚点, 对得上就就地改 8 字节, 对不上绝不写
  anchor=$(dd if="$TGT" bs=1 skip="$OFF" count=4 2>/dev/null | md5sum | awk '{print $1}')
  if [ "$anchor" != "$ANCHOR_MD5" ]; then
    log "库已变化且锚点不匹配(偏移 0x$(printf %X $OFF) 失效), 未写入。需要用 mkdf.py 重新定位后更新模块 payload。"
    exit 3
  fi
  mkdir -p "$MODDIR/backup"
  [ -f "$MODDIR/backup/$SO_NAME.$cur.so" ] || cp -f "$TGT" "$MODDIR/backup/$SO_NAME.$cur.so"
  dd if="$MODDIR/payload/df8.bin" of="$TGT" bs=1 seek="$OFF" conv=notrunc 2>/dev/null \
    || { log "失败: dd 写入"; exit 2; }
  new=$(md5of "$TGT")
  log "已打补丁(新版库就地修补) $cur -> $new, 原库备份于 backup/$SO_NAME.$cur.so"
fi

[ "$RESTART_APP" = "1" ] && am force-stop "$PKG" 2>/dev/null
exit 0