#!/usr/bin/env python3
"""
跨设备攻击溯源系统 - 数据处理模块

该模块提供多字段IP提取、事件标准化和数据处理功能
"""

import re
import json
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Set, Optional
from sz_config import system_config, path_config

class MultiFieldIPExtractor:
    """多字段IP提取器 - 解决受限视角下攻击者IP识别问题"""
    
    def __init__(self):
        # 内部可信设备IP范围
        self.internal_ranges = system_config.INTERNAL_IP_RANGES
        
        # IP提取正则模式
        self.extraction_patterns = {
            "socket_path": r"(\d+\.\d+\.\d+\.\d+):(\d+)",
            "command_line": r"@([\d\.]+):",
            "url_pattern": r"https?://([\d\.]+)",
            "scp_pattern": r"\w+@([\d\.]+):/",
            "ssh_pattern": r"ssh\s+\w*@?([\d\.]+)",
            "ip_only": r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        }
    
    def extract_all_ips(self, event: Dict[str, Any]) -> Dict[str, List[str]]:
        """从事件的多个字段提取所有IP地址"""
        extracted_ips = set()
        
        # 1. 从subject.host提取（传统方法）
        subject_host = event.get("subject", {}).get("host", "")
        if self._is_valid_ip(subject_host):
            extracted_ips.add(subject_host)
        
        # 2. 从object.path提取（网络事件关键）
        if event.get("type") in ["NETWORK_RECEIVE", "NETWORK_CONNECTION", "NETWORK_SEND"]:
            object_path = event.get("object", {}).get("path", "")
            ip_matches = re.findall(self.extraction_patterns["socket_path"], object_path)
            for match in ip_matches:
                ip = match[0] if isinstance(match, tuple) else match
                if self._is_valid_ip(ip):
                    extracted_ips.add(ip)
        
        # 3. 从cmdLine提取（命令行事件）
        cmd_line = event.get("subject", {}).get("cmdLine", "")
        if cmd_line:
            for pattern_name, pattern in self.extraction_patterns.items():
                matches = re.findall(pattern, cmd_line)
                for match in matches:
                    ip = match if isinstance(match, str) else match[0]
                    if self._is_valid_ip(ip):
                        extracted_ips.add(ip)
        
        # 4. 从其他字段提取IP（增强提取）
        self._extract_from_additional_fields(event, extracted_ips)
        
        return {
            "all_ips": list(extracted_ips),
            "external_ips": [ip for ip in extracted_ips if self._is_external_ip(ip)],
            "internal_ips": [ip for ip in extracted_ips if not self._is_external_ip(ip)]
        }
    
    def _extract_from_additional_fields(self, event: Dict[str, Any], extracted_ips: Set[str]):
        """从其他字段提取IP地址"""
        # 从object字段的其他属性提取
        obj = event.get("object", {})
        for key, value in obj.items():
            if isinstance(value, str):
                ips = re.findall(self.extraction_patterns["ip_only"], value)
                for ip in ips:
                    if self._is_valid_ip(ip):
                        extracted_ips.add(ip)
        
        # 从subject字段的其他属性提取
        subject = event.get("subject", {})
        for key, value in subject.items():
            if isinstance(value, str) and key != "host":  # host已经处理过
                ips = re.findall(self.extraction_patterns["ip_only"], value)
                for ip in ips:
                    if self._is_valid_ip(ip):
                        extracted_ips.add(ip)
    
    def _is_external_ip(self, ip: str) -> bool:
        """判断是否为外部攻击者IP"""
        return ip not in self.internal_ranges and self._is_valid_ip(ip)
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """验证IP地址格式"""
        if not ip_str:
            return False
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def get_attacker_ips(self, event: Dict[str, Any]) -> List[str]:
        """获取事件中的攻击者IP（外部IP）"""
        ip_info = self.extract_all_ips(event)
        return ip_info["external_ips"]

class EventStandardizer:
    """事件标准化器 - 将原始日志转换为标准事件格式"""
    
    def __init__(self):
        self.ip_extractor = MultiFieldIPExtractor()
        self.event_counter = 0
    
    def standardize_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """标准化单个事件"""
        self.event_counter += 1
        
        # 提取IP信息
        ip_info = self.ip_extractor.extract_all_ips(raw_event)
        
        # 构建标准事件对象
        standard_event = {
            "event_id": f"evt_{self.event_counter:06d}",
            "timestamp": self._parse_timestamp(raw_event.get("timestamp")),
            "source_device": raw_event.get("subject", {}).get("host", "unknown"),
            "event_type": raw_event.get("type", "UNKNOWN"),
            "subject": raw_event.get("subject", {}),
            "object": raw_event.get("object", {}),
            "extracted_ips": ip_info,
            "is_external_event": len(ip_info["external_ips"]) > 0,
            "causal_attributes": self._extract_causal_attributes(raw_event),
            "raw_event": raw_event
        }
        
        return standard_event
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """解析时间戳"""
        if not timestamp_str:
            return datetime.now()
        
        try:
            # 尝试多种时间格式
            timestamp_formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f"
            ]
            
            for fmt in timestamp_formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # 如果都失败，尝试解析为Unix时间戳
            try:
                return datetime.fromtimestamp(float(timestamp_str))
            except (ValueError, TypeError):
                pass
            
            print(f"[WARNING] 无法解析时间戳: {timestamp_str}，使用当前时间")
            return datetime.now()
            
        except Exception as e:
            print(f"[ERROR] 时间戳解析错误: {str(e)}，使用当前时间")
            return datetime.now()
    
    def _extract_causal_attributes(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """提取因果关系相关属性"""
        return {
            "process_id": event.get("subject", {}).get("pid"),
            "parent_process_id": event.get("subject", {}).get("ppid"),
            "file_path": event.get("object", {}).get("path"),
            "command_line": event.get("subject", {}).get("cmdLine"),
            "user_id": event.get("subject", {}).get("uid"),
            "session_id": event.get("subject", {}).get("sessionId"),
            "thread_id": event.get("subject", {}).get("tid")
        }
    
    def standardize_events_batch(self, raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """批量标准化事件"""
        standardized_events = []
        
        for raw_event in raw_events:
            try:
                standard_event = self.standardize_event(raw_event)
                standardized_events.append(standard_event)
            except Exception as e:
                print(f"[ERROR] 事件标准化失败: {str(e)}")
                continue
        
        return standardized_events

class DataProcessor:
    """数据处理器 - 主要的数据处理入口"""
    
    def __init__(self):
        self.event_standardizer = EventStandardizer()
        self.ip_extractor = MultiFieldIPExtractor()
    
    def process_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """处理日志文件"""
        print(f"[INFO] 开始处理日志文件: {file_path}")
        
        try:
            # 读取JSON文件
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
            
            # 确保数据是列表格式
            if isinstance(raw_data, dict):
                raw_events = [raw_data]
            elif isinstance(raw_data, list):
                raw_events = raw_data
            else:
                raise ValueError(f"不支持的数据格式: {type(raw_data)}")
            
            print(f"[INFO] 读取到 {len(raw_events)} 个原始事件")
            
            # 标准化事件
            standardized_events = self.event_standardizer.standardize_events_batch(raw_events)
            
            print(f"[INFO] 成功标准化 {len(standardized_events)} 个事件")
            
            # 统计外部事件
            external_events = [e for e in standardized_events if e["is_external_event"]]
            print(f"[INFO] 检测到 {len(external_events)} 个包含外部IP的事件")
            
            # 统计攻击者IP
            attacker_ips = set()
            for event in external_events:
                attacker_ips.update(event["extracted_ips"]["external_ips"])
            
            if attacker_ips:
                print(f"[INFO] 发现潜在攻击者IP: {', '.join(attacker_ips)}")
            
            return standardized_events
            
        except FileNotFoundError:
            print(f"[ERROR] 文件不存在: {file_path}")
            return []
        except json.JSONDecodeError as e:
            print(f"[ERROR] JSON解析错误: {str(e)}")
            return []
        except Exception as e:
            print(f"[ERROR] 数据处理错误: {str(e)}")
            return []
    
    def filter_events_by_timerange(self, events: List[Dict[str, Any]], 
                                   start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """按时间范围过滤事件"""
        filtered_events = []
        
        for event in events:
            event_time = event["timestamp"]
            if start_time <= event_time <= end_time:
                filtered_events.append(event)
        
        print(f"[INFO] 时间范围过滤: {len(filtered_events)}/{len(events)} 个事件")
        return filtered_events
    
    def filter_events_by_device(self, events: List[Dict[str, Any]], 
                               device_list: List[str]) -> List[Dict[str, Any]]:
        """按设备过滤事件"""
        filtered_events = []
        
        for event in events:
            if event["source_device"] in device_list:
                filtered_events.append(event)
        
        print(f"[INFO] 设备过滤: {len(filtered_events)}/{len(events)} 个事件")
        return filtered_events
    
    def get_event_statistics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取事件统计信息"""
        stats = {
            "total_events": len(events),
            "external_events": len([e for e in events if e["is_external_event"]]),
            "event_types": {},
            "devices": set(),
            "attacker_ips": set(),
            "time_range": {"start": None, "end": None}
        }
        
        for event in events:
            # 统计事件类型
            event_type = event["event_type"]
            stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
            
            # 统计设备
            stats["devices"].add(event["source_device"])
            
            # 统计攻击者IP
            stats["attacker_ips"].update(event["extracted_ips"]["external_ips"])
            
            # 统计时间范围
            event_time = event["timestamp"]
            if stats["time_range"]["start"] is None or event_time < stats["time_range"]["start"]:
                stats["time_range"]["start"] = event_time
            if stats["time_range"]["end"] is None or event_time > stats["time_range"]["end"]:
                stats["time_range"]["end"] = event_time
        
        # 转换集合为列表以便JSON序列化
        stats["devices"] = list(stats["devices"])
        stats["attacker_ips"] = list(stats["attacker_ips"])
        
        return stats
    
    def save_processed_data(self, events: List[Dict[str, Any]], output_path: str):
        """保存处理后的数据"""
        try:
            # 转换datetime对象为字符串以便JSON序列化
            serializable_events = []
            for event in events:
                serializable_event = event.copy()
                serializable_event["timestamp"] = event["timestamp"].isoformat()
                serializable_events.append(serializable_event)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_events, f, ensure_ascii=False, indent=2)
            
            print(f"[INFO] 处理后的数据已保存到: {output_path}")
            
        except Exception as e:
            print(f"[ERROR] 保存数据失败: {str(e)}")

# 测试函数
def test_ip_extraction():
    """测试IP提取功能"""
    print("=== IP提取功能测试 ===")
    
    extractor = MultiFieldIPExtractor()
    
    # 测试事件
    test_events = [
        {
            "type": "NETWORK_RECEIVE",
            "subject": {"host": "192.168.1.101"},
            "object": {"path": "192.168.1.200:45678"}
        },
        {
            "type": "PROCESS_LAUNCH",
            "subject": {
                "host": "192.168.1.106",
                "cmdLine": "scp user@192.168.1.200:/tmp/file.txt /home/"
            }
        }
    ]
    
    for i, event in enumerate(test_events):
        print(f"\n测试事件 {i+1}:")
        ip_info = extractor.extract_all_ips(event)
        print(f"  所有IP: {ip_info['all_ips']}")
        print(f"  外部IP: {ip_info['external_ips']}")
        print(f"  内部IP: {ip_info['internal_ips']}")

if __name__ == "__main__":
    # 运行测试
    test_ip_extraction()
    
    # 测试数据处理
    processor = DataProcessor()
    
    # 尝试处理默认测试文件
    test_file = path_config.get_input_file_path()
    if test_file:
        events = processor.process_log_file(test_file)
        if events:
            stats = processor.get_event_statistics(events)
            print(f"\n=== 数据处理统计 ===")
            print(f"总事件数: {stats['total_events']}")
            print(f"外部事件数: {stats['external_events']}")
            print(f"设备数量: {len(stats['devices'])}")
            print(f"攻击者IP: {stats['attacker_ips']}")
            print(f"事件类型分布: {stats['event_types']}")
