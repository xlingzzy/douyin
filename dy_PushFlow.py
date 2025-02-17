import os
import re
import sys
import json
import time
import ctypes
import psutil
import logging
import pyshark
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s][%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("rtmp_auto.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def is_admin() -> bool:
    """检查管理员权限"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

class SoftwareDetector:
    @staticmethod
    def get_process_path(process_name: str) -> Optional[str]:
        """获取正在运行的可执行文件完整路径"""
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError) as e:
                logging.debug("进程信息获取失败: %s", str(e))
        return None

    @classmethod
    def find_tshark_path(cls) -> str:
        """通过注册表查找tshark路径"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Wireshark",
                access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            )
            install_dir = winreg.QueryValueEx(key, "InstallDir")[0]
            tshark_path = Path(install_dir) / "tshark.exe"
            if tshark_path.exists():
                return str(tshark_path)
        except Exception as e:
            logging.debug("注册表查找失败: %s", str(e))

        # 环境变量查找
        tshark_path = shutil.which("tshark")
        if tshark_path and Path(tshark_path).exists():
            return tshark_path
        
        raise FileNotFoundError("未找到tshark，请确认Wireshark是否正确安装")

    @classmethod
    def wait_for_software(cls, process_name: str, timeout=300) -> str:
        """等待指定软件启动并返回路径"""
        logger = logging.getLogger()
        logger.info(f"请启动 {process_name}...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            path = cls.get_process_path(process_name)
            if path and os.path.exists(path):
                logger.info(f"检测到 {process_name} 路径: {path}")
                return path
            time.sleep(2)
        
        raise TimeoutError(f"等待 {process_name} 启动超时")

class RTMPHunter:
    RTMP_REGEX = re.compile(
        r"rtmp[s]?://([a-z0-9\-._~%]+(:\d+)?(/[a-z0-9\-._~%]*)*)",
        re.IGNORECASE
    )
    KEY_REGEX = re.compile(
        r'(live_?key=|/live/|/stream/|key=)(?P<key>[\w\-~!@#$%^&*()+={}[\]|\\;:"<>,.?/]+)',
        re.IGNORECASE
    )

    def __init__(self, tshark_path: str):
        self.tshark_path = tshark_path
        self.interface = self._get_active_interface()

    def _get_active_interface(self) -> str:
        """获取活动网络接口"""
        interfaces = psutil.net_if_addrs()
        active_interfaces = []
        
        for intf, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == psutil.AF_INET and not addr.address.startswith('127.'):
                    active_interfaces.append(intf)
                    break

        priorities = ['eth', 'wifi', 'ethernet', '无线']
        for kw in priorities:
            for intf in active_interfaces:
                if kw.lower() in intf.lower():
                    return intf
        
        return active_interfaces[0] if active_interfaces else "eth0"

    def capture_stream_info(self, timeout=600) -> Tuple[str, str]:
        """抓取推流信息"""
        server, stream_key = None, None
        start_time = time.time()
        packet_count = 0

        logging.info(f"使用网络接口: {self.interface}")
        capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter="rtmp || http || tls",
            tshark_path=self.tshark_path
        )

        try:
            for packet in capture.sniff_continuously():
                packet_count += 1
                elapsed = time.time() - start_time
                packet_str = str(packet).lower()

                # RTMP服务器匹配
                if not server:
                    match = self.RTMP_REGEX.search(packet_str)
                    if match:
                        server = match.group(0).replace('///', '//')  # 修复双斜杠问题
                        logging.info(f"检测到服务器地址: {server}")

                # 推流密钥匹配
                if not stream_key:
                    match = self.KEY_REGEX.search(packet_str)
                    if match:
                        stream_key = match.group('key')
                        logging.info(f"检测到推流密钥: {stream_key}")

                # 状态提示
                if packet_count % 50 == 0:
                    logging.info(f"已分析 {packet_count} 个数据包，持续监测中...")

                # 退出条件
                if server and stream_key:
                    break
                if elapsed > timeout:
                    raise TimeoutError("抓包超时，未检测到有效推流信息")

        except KeyboardInterrupt:
            logging.warning("用户终止抓包过程")
        finally:
            capture.close()

        if not server or not stream_key:
            raise ValueError("缺少推流信息（服务器地址或密钥）")

        return server, stream_key

class OBSManager:
    @staticmethod
    def write_stream_info(server: str, key: str):
        """安全保存推流信息"""
        content = f"服务器地址: {server}\n推流密钥: {key}"
        path = Path("推流信息.txt").absolute()
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        
        logging.warning(f"推流信息已保存至: {path}\n警告：此文件包含敏感信息，请妥善保管！")

    @classmethod
    def configure_obs(cls, server: str, key: str):
        """智能配置OBS"""
        obs_path = SoftwareDetector.wait_for_software("obs64.exe", timeout=120)
        
        # 生成唯一配置文件
        profile_id = f"RTMP_{int(time.time() % 1e6)}"
        config_dir = Path(os.getenv('APPDATA')) / "obs-studio" / "basic" / "profiles" / profile_id
        config_dir.mkdir(parents=True, exist_ok=True)

        # 创建服务配置
        service_config = {
            "key": key,
            "server": server,
            "service": "自定义RTMP服务器",
            "stream_type": "rtmp_custom"
        }
        
        (config_dir / "service.json").write_text(
            json.dumps({"settings": service_config}, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        # 创建场景配置
        scenes_config = {
            "current_scene": "自动捕获场景",
            "scenes": [{
                "name": "自动捕获场景",
                "sources": []
            }]
        }
        (config_dir / "scenes.json").write_text(
            json.dumps(scenes_config, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        # 启动OBS
        subprocess.Popen([
            obs_path,
            "--profile", profile_id,
            "--scene", "自动捕获场景"
        ], shell=True)
        
        logging.info(f"OBS已配置启动，使用配置文件: {profile_id}")

def check_dependencies():
    """检查必要依赖"""
    try:
        subprocess.run(
            ["wireshark", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
    except FileNotFoundError:
        raise RuntimeError(
            "未检测到Wireshark，请访问 https://www.wireshark.org/ 下载安装"
        )

def main():
    try:
        if not is_admin():
            logging.warning("部分功能可能需要管理员权限，建议以管理员身份重新运行")

        check_dependencies()  # 前置依赖检查
        
        # 阶段1：获取tshark路径
        tshark_path = SoftwareDetector.find_tshark_path()
        logging.info(f"TSHARK路径确认: {tshark_path}")
        
        # 阶段2：捕获RTMP信息
        hunter = RTMPHunter(tshark_path)
        server, key = hunter.capture_stream_info()
        
        # 阶段3：处理推流信息
        OBSManager.write_stream_info(server, key)
        OBSManager.configure_obs(server, key)

        logging.info("自动化配置完成，请在OBS中检查推流设置")

    except Exception as e:
        logging.error("程序运行失败: %s", str(e), exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    if os.name != "nt":
        logging.critical("本程序仅支持Windows操作系统")
        sys.exit(1)

    main()