import os
import sys
import subprocess
from datetime import datetime
from shutil import which

def check_dependencies():
    """增强版依赖检测"""
    # Wireshark检测逻辑（覆盖所有可能路径）
    wireshark_paths = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Wireshark", "tshark.exe"),
        os.path.join(os.environ.get("ProgramW6432", "C:\\Program Files"), "Wireshark", "tshark.exe"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    
    tshark_found = any(os.path.exists(p) for p in wireshark_paths)
    
    if not tshark_found:
        # 环境变量检测
        tshark_path = which("tshark")
        if not tshark_path or not os.path.isfile(tshark_path):
            raise RuntimeError(
                "未检测到Wireshark，请访问 https://www.wireshark.org/ 下载安装\n"
                "安装时务必勾选 'Add Wireshark to the system PATH' 选项"
            )

def main():
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][INFO] 启动检测...")
        check_dependencies()
        
        # 以下是您的业务逻辑
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][INFO] 所有依赖检测通过")
        # 添加您的核心功能代码
        
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}][ERROR] 程序运行失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
