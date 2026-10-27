#!/system/bin/sh
# boot-completed 后自动修补; 之后按 WATCH_INTERVAL 巡检(应用被升级时会自动重打)
MODDIR=${0%/*}
[ -f "$MODDIR/config.sh" ] || MODDIR=/data/adb/modules/cellularpro_df
. "$MODDIR/config.sh"

until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 3; done
sleep 5
sh "$MODDIR/patch.sh" --quiet

[ "$WATCH_INTERVAL" = "0" ] && exit 0
while true; do
  sleep "$WATCH_INTERVAL"
  sh "$MODDIR/patch.sh" --quiet
done