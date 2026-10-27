#!/system/bin/sh
SKIPUNZIP=0
ui_print "*********************************************"
ui_print " CellularPro 2.0.16.1 会员解锁 (lib 补丁)"
ui_print " 开机自动修补 / 应用升级后锚点校验重打"
ui_print " 日志: /data/adb/cellularpro_df.log"
ui_print "*********************************************"
command -v set_perm_recursive >/dev/null 2>&1 && set_perm_recursive "$MODPATH" 0 0 0755 0644
chmod 755 "$MODPATH"/*.sh 2>/dev/null
mkdir -p "$MODPATH/backup"
ui_print "- 安装完成, 重启设备后补丁自动生效"
ui_print "- 手动执行: su -c sh /data/adb/modules/cellularpro_df/patch.sh"