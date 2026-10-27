# 模块配置 (改完重启生效, 或手动跑一次 patch.sh)
PKG=make.more.r2d2.play.cellular_pro
SO_NAME=libQualcommAdapter.so

# A0B0.ge.df() VM 包装体入口: 文件偏移 0xF0ED4 = 986836
OFF=986836
# 原始 4 字节 sub sp,sp,#0x60 的 md5, 用于新版库的就地修补前校验
ANCHOR_MD5=16e6c7fcfee229650cd64fd41eeecaca
# 官方库 / 补丁库 md5
STOCK_MD5=a1a7e57ed83a83256715601d4e48640d
PATCH_MD5=ab3c665552712bbf2f54f8a8fa2dc77f

# 巡检间隔(秒): 检测到应用被升级/覆盖时自动重打; 0 = 只开机打一次
WATCH_INTERVAL=300
# 补完后是否强停应用让补丁立即生效(0=下次自开应用时生效)
RESTART_APP=0