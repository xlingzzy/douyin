import os
import re
import sys
import time
import psutil
import logging
import winreg
import pyshark
import subprocess
from pathlib import Path
from typing import Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    handlers=[
        logging.FileHandler("rtmp_auto.log"),
        logging.StreamHandler()
    ]
)

class SoftwareDetector:
    @staticmethod
    def get_process_path(process_name: str) -> Optional[str]:
        """获取正在运行的可执行文件完整路径"""
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return proc.info['exe']
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
        return None

    @classmethod
    def wait_for_software(cls, process_name: str, timeout=300) -> str:
        """等待指定软件启动并返回路径"""
        logging.info(f"请启动 {process_name}...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            path = cls.get_process_path(process_name)
            if path and os.path.exists(path):
                logging.info(f"检测到 {process_name} 路径: {path}")
                return path
            time.sleep(2)
        
        raise TimeoutError(f"等待 {process_name} 启动超时")

class RTMPHunter:
    def __init__(self, tshark_path: str):
        self.tshark_path = tshark_path
        self.interface = self._get_network_interface()

    def _get_network_interface(self) -> str:
        """获取最佳网络接口"""
        try:
            result = subprocess.run(
                [self.tshark_path, '-D'],
                capture_output=True,
                text=True,
                check=True
            )
            interfaces = []
            for line in result.stdout.splitlines():
                if '. ' in line and '(' in line:
                    desc = line.split('(', 1)[1].rstrip(')').strip()
                    interfaces.append(desc)

            # 优先级排序
            priorities = ['wi-fi', 'wireless', 'eth', 'ethernet', '以太网']
            exclude = ['loopback', 'bluetooth', 'virtual']
            
            for kw in priorities:
                for intf in interfaces:
                    if kw in intf.lower() and not any(e in intf.lower() for e in exclude):
                        return intf
            
            return interfaces[0] if interfaces else "eth0"
        except Exception as e:
            logging.error(f"获取网络接口失败: {str(e)}")
            return "eth0"

    def capture_stream_info(self) -> Tuple[str, str]:
        """抓取推流信息"""
        filter_expr = "rtmp || http || tls"
        server, stream_key = None, None
        start_time = time.time()

        logging.info(f"开始网络抓包，使用接口: {self.interface}")
        
        capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter=filter_expr,
            tshark_path=self.tshark_path
        )

        try:
            for packet in capture.sniff_continuously():
                # 保持抓包时间在30分钟以内
                if time.time() - start_time > 1800:
                    break

                packet_str = str(packet).lower()
                
                # 匹配服务器地址
                if not server:
                    server_match = re.search(
                        r"rtmp[s]?://([a-z0-9\-._~%]+(/[a-z0-9\-._~%]*)*)",
                        packet_str,
                        re.IGNORECASE
                    )
                    if server_match:
                        server = server_match.group(0)
                        logging.info(f"检测到服务器地址: {server}")

                # 匹配推流秘钥
                if not stream_key:
                    key_match = re.search(
                        r'(live_?key=|/live/|/stream/|key=)(?P<key>[a-z0-9_\-]{8,})',
                        packet_str,
                        re.IGNORECASE
                    )
                    if key_match:
                        stream_key = key_match.group('key')
                        logging.info(f"检测到推流秘钥: {stream_key}")

                # 两者都找到时退出
                if server and stream_key:
                    break

                # 10秒提示一次
                if int(time.time() - start_time) % 10 == 0:
                    logging.info("正在监听网络流量...")

        except KeyboardInterrupt:
            logging.warning("用户中断抓包过程")
        finally:
            capture.close()

        if not server or not stream_key:
            raise ValueError("未能捕获完整的推流信息")

        return server, stream_key

class OBSManager:
    @staticmethod
    def write_stream_info(server: str, key: str):
        """写入推流信息到当前目录"""
        content = f"服务器地址: {server}\n推流秘钥: {key}"
        with open("推流信息.txt", "w", encoding="utf-8") as f:
            f.write(content)
        logging.info("推流信息已保存到: 推流信息.txt")

    @classmethod
    def configure_obs(cls, server: str, key: str):
        """配置OBS推流设置"""
        obs_path = SoftwareDetector.wait_for_software("obs64.exe", timeout=120)
        
        config_dir = Path(os.getenv('APPDATA')) / "obs-studio" / "basic" / "profiles" / "RTMP_Profile"
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建新的配置文件
        service_config = {
            "key": key,
            "server": server,
            "service": "自定义流媒体服务器",
            "stream_type": "rtmp_custom"
        }
        
        config_path = config_dir / "service.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump({"settings": service_config}, f, indent=2, ensure_ascii=False)
        
        # 启动OBS并使用新配置
        subprocess.Popen([
            obs_path,
            "--profile", "RTMP_Profile",
            "--collection", "RTMP_Scene"
        ])
        logging.info(f"OBS已配置并启动，使用服务器: {server}")

def main():
    try:
        # 阶段1：等待Wireshark/tShark启动
        tshark_path = SoftwareDetector.wait_for_software("tshark.exe")
        
        # 阶段2：抓取推流信息
        hunter = RTMPHunter(tshark_path)
        server, key = hunter.capture_stream_info()
        
        # 保存推流信息
        OBSManager.write_stream_info(server, key)
        
        # 阶段3：配置OBS
        OBSManager.configure_obs(server, key)

    except Exception as e:
        logging.error(f"运行错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if os.name != 'nt':
        logging.error("本脚本仅支持Windows系统")
        sys.exit(1)
    
    if not psutil.Process(os.getpid()).parent().username() == 'NT AUTHORITY\\SYSTEM':
        logging.warning("建议以管理员权限运行以获得完整功能")

    main()