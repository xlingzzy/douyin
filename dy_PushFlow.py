import os
import sys
from datetime import datetime
from shutil import which

def check_wireshark():
    """智能检测Wireshark安装（仅用户运行时生效）"""
    # 仅在非构建环境执行检测
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][INFO] 构建环境跳过依赖检测")
        return

    # 全路径扫描策略
    search_paths = [
        os.path.join(os.environ.get("ProgramFiles", ""), "Wireshark", "tshark.exe"),
        os.path.join(os.environ.get("ProgramW6432", ""), "Wireshark", "tshark.exe"),
        os.path.expandvars(r"%LocalAppData%\Programs\Wireshark\tshark.exe"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]

    # 路径存在性检查
    if any(os.path.exists(p) for p in search_paths):
        return

    # 环境变量检测
    if which("tshark") is not None:
        return

    # 友好错误提示
    err_msg = """
⚠️ 未检测到Wireshark组件，请执行以下操作：

1. 访问官网下载: https://www.wireshark.org/download.html
2. 安装时务必勾选以下选项：
   [√] Install WinPcap
   [√] Add Wireshark to the system PATH
3. 完成安装后重启电脑
4. 重新运行本程序
"""
    raise RuntimeError(err_msg)

def main():
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][INFO] 启动程序")
        check_wireshark()
        
        # 主业务逻辑
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][INFO] 所有依赖检测通过")
        # [在此添加核心功能代码]

    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][ERROR] 运行失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
