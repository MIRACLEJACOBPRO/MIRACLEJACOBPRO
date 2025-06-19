#!/usr/bin/env python3
"""
跨设备攻击溯源系统 - 控制台输出管理模块

该模块提供实时状态显示、攻击链可视化和彩色输出功能
"""

import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from sz_config import system_config

class ConsoleOutputManager:
    """控制台输出管理器 - 负责格式化和彩色输出"""
    
    def __init__(self):
        self.colors = system_config.CONSOLE_COLORS
        self.start_time = datetime.now()
        self.current_step = 0
        self.total_steps = 7  # 总处理步骤数
        
        # 事件类型图标
        self.event_icons = {
            "NETWORK_CONNECTION": "🌐",
            "NETWORK_SEND": "📤",
            "NETWORK_RECEIVE": "📥",
            "PROCESS_LAUNCH": "⚡",
            "FILE_READ": "📖",
            "FILE_WRITE": "✏️",
            "FILE_CREATE": "📄",
            "FILE_DELETE": "🗑️",
            "REGISTRY_WRITE": "📝",
            "USER_LOGIN": "👤",
            "PRIVILEGE_ESCALATION": "⬆️",
            "UNKNOWN": "❓"
        }
        
        # 威胁等级图标
        self.threat_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵"
        }
    
    def print_system_banner(self):
        """打印系统启动横幅"""
        banner = f"""
{self.colors['header']}╔══════════════════════════════════════════════════════════════════════════════╗
║                          跨设备攻击溯源系统 v1.0                              ║
║                     Cross-Device Attack Tracing System                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  🎯 智能攻击检测  │  🔗 跨设备关联  │  🧠 意图推理  │  📊 威胁评估           ║
╚══════════════════════════════════════════════════════════════════════════════╝{self.colors['reset']}
"""
        print(banner)
        print(f"{self.colors['info']}[INFO] 系统启动时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}{self.colors['reset']}")
        print(f"{self.colors['info']}[INFO] 开始跨设备攻击溯源分析...{self.colors['reset']}\n")
    
    def print_step_header(self, step_name: str, description: str = ""):
        """打印处理步骤标题"""
        self.current_step += 1
        progress = (self.current_step / self.total_steps) * 100
        
        print(f"{self.colors['header']}{'='*80}{self.colors['reset']}")
        print(f"{self.colors['header']}步骤 {self.current_step}/{self.total_steps}: {step_name}{self.colors['reset']}")
        if description:
            print(f"{self.colors['info']}描述: {description}{self.colors['reset']}")
        print(f"{self.colors['info']}进度: [{progress:5.1f}%] {'█' * int(progress/5):<20}{self.colors['reset']}")
        print(f"{self.colors['header']}{'='*80}{self.colors['reset']}\n")
    
    def print_processing_status(self, message: str, status: str = "INFO"):
        """打印处理状态信息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        color = self.colors.get(status.lower(), self.colors['info'])
        icon = self.threat_icons.get(status, "ℹ️")
        
        print(f"{color}[{timestamp}] {icon} {message}{self.colors['reset']}")
    
    def print_data_summary(self, total_events: int, devices: List[str], 
                          time_range: tuple, external_ips: List[str]):
        """打印数据摘要"""
        print(f"{self.colors['success']}📊 数据摘要:{self.colors['reset']}")
        print(f"   • 总事件数: {self.colors['highlight']}{total_events:,}{self.colors['reset']}")
        print(f"   • 涉及设备: {self.colors['highlight']}{len(devices)}{self.colors['reset']} 个")
        
        if devices:
            device_list = ", ".join(devices[:5])
            if len(devices) > 5:
                device_list += f" 等{len(devices)}个设备"
            print(f"     └─ {device_list}")
        
        if time_range[0] and time_range[1]:
            duration = (time_range[1] - time_range[0]).total_seconds()
            print(f"   • 时间跨度: {self.colors['highlight']}{duration/3600:.1f}{self.colors['reset']} 小时")
            print(f"     └─ {time_range[0].strftime('%Y-%m-%d %H:%M:%S')} 至 {time_range[1].strftime('%Y-%m-%d %H:%M:%S')}")
        
        if external_ips:
            print(f"   • 外部IP: {self.colors['warning']}{len(external_ips)}{self.colors['reset']} 个")
            ip_list = ", ".join(external_ips[:3])
            if len(external_ips) > 3:
                ip_list += f" 等{len(external_ips)}个"
            print(f"     └─ {ip_list}")
        
        print()
    
    def print_graph_statistics(self, stats: Dict[str, Any]):
        """打印图统计信息"""
        print(f"{self.colors['success']}🔗 因果图统计:{self.colors['reset']}")
        print(f"   • 节点数量: {self.colors['highlight']}{stats.get('nodes', 0):,}{self.colors['reset']}")
        print(f"   • 边数量: {self.colors['highlight']}{stats.get('edges', 0):,}{self.colors['reset']}")
        print(f"   • 设备组数: {self.colors['highlight']}{stats.get('device_groups', 0)}{self.colors['reset']}")
        print(f"   • 跨设备边: {self.colors['highlight']}{stats.get('cross_device_edges', 0)}{self.colors['reset']}")
        
        if stats.get('avg_causal_strength'):
            print(f"   • 平均因果强度: {self.colors['highlight']}{stats['avg_causal_strength']:.3f}{self.colors['reset']}")
        
        print()
    
    def print_entry_point_detection(self, entry_points: List[Dict[str, Any]]):
        """打印入口点检测结果"""
        if not entry_points:
            print(f"{self.colors['info']}🔍 未检测到明确的攻击入口点{self.colors['reset']}\n")
            return
        
        print(f"{self.colors['warning']}🚨 检测到 {len(entry_points)} 个攻击入口点:{self.colors['reset']}")
        
        for i, entry in enumerate(entry_points, 1):
            severity = entry.get('severity', 'MEDIUM')
            confidence = entry.get('confidence', 0.0)
            device = entry.get('device', 'Unknown')
            attacker_ips = entry.get('attacker_ips', [])
            
            severity_color = self._get_severity_color(severity)
            icon = self.threat_icons.get(severity, "⚠️")
            
            print(f"\n   {icon} {self.colors['bold']}入口点 #{i}{self.colors['reset']}")
            print(f"      └─ 设备: {self.colors['highlight']}{device}{self.colors['reset']}")
            print(f"      └─ 威胁等级: {severity_color}{severity}{self.colors['reset']}")
            print(f"      └─ 置信度: {self.colors['highlight']}{confidence:.2f}{self.colors['reset']}")
            
            if attacker_ips:
                ip_str = ", ".join(attacker_ips)
                print(f"      └─ 攻击者IP: {self.colors['error']}{ip_str}{self.colors['reset']}")
            
            # 显示相关事件
            if 'related_events' in entry:
                events = entry['related_events'][:3]  # 只显示前3个
                for event in events:
                    event_icon = self.event_icons.get(event.get('event_type', 'UNKNOWN'), "❓")
                    print(f"      └─ {event_icon} {event.get('description', '')[:60]}...")
        
        print()
    
    def print_attack_path_summary(self, attack_paths: List[Dict[str, Any]]):
        """打印攻击路径摘要"""
        if not attack_paths:
            print(f"{self.colors['info']}🔍 未发现明确的攻击路径{self.colors['reset']}\n")
            return
        
        print(f"{self.colors['error']}⚠️  发现 {len(attack_paths)} 条攻击路径:{self.colors['reset']}")
        
        # 统计信息
        total_devices = set()
        total_techniques = set()
        cross_device_count = 0
        
        for path in attack_paths:
            total_devices.update(path.get('devices', []))
            total_techniques.update(path.get('techniques', []))
            if path.get('cross_device', False):
                cross_device_count += 1
        
        print(f"   • 受影响设备: {self.colors['highlight']}{len(total_devices)}{self.colors['reset']} 个")
        print(f"   • 使用技术: {self.colors['highlight']}{len(total_techniques)}{self.colors['reset']} 种")
        print(f"   • 跨设备路径: {self.colors['warning']}{cross_device_count}{self.colors['reset']} 条")
        
        print()
    
    def print_attack_chain_tree(self, attack_paths: List[Dict[str, Any]], max_paths: int = 3):
        """打印攻击链树状结构"""
        if not attack_paths:
            return
        
        print(f"{self.colors['header']}🌳 攻击链详细分析:{self.colors['reset']}")
        
        # 按得分排序，只显示前几条
        sorted_paths = sorted(attack_paths, key=lambda x: x.get('score', 0), reverse=True)
        display_paths = sorted_paths[:max_paths]
        
        for i, path in enumerate(display_paths, 1):
            self._print_single_attack_path(path, i)
        
        if len(attack_paths) > max_paths:
            remaining = len(attack_paths) - max_paths
            print(f"   {self.colors['info']}... 还有 {remaining} 条攻击路径 (详见报告文件){self.colors['reset']}")
        
        print()
    
    def _print_single_attack_path(self, path: Dict[str, Any], path_number: int):
        """打印单条攻击路径"""
        path_id = path.get('path_id', f'path_{path_number}')
        score = path.get('score', 0.0)
        devices = path.get('devices', [])
        cross_device = path.get('cross_device', False)
        
        # 路径标题
        cross_device_icon = "🔗" if cross_device else "📱"
        print(f"\n   {cross_device_icon} {self.colors['bold']}攻击路径 #{path_number}{self.colors['reset']}")
        print(f"      ├─ ID: {self.colors['highlight']}{path_id}{self.colors['reset']}")
        print(f"      ├─ 威胁得分: {self._get_score_colored(score)}")
        print(f"      ├─ 涉及设备: {self.colors['highlight']}{' → '.join(devices)}{self.colors['reset']}")
        
        # 攻击技术
        techniques = path.get('techniques', [])
        if techniques:
            print(f"      ├─ 攻击技术: {self.colors['warning']}{', '.join(techniques[:3])}{self.colors['reset']}")
            if len(techniques) > 3:
                print(f"      │           {self.colors['info']}等{len(techniques)}种技术{self.colors['reset']}")
        
        # 攻击阶段
        stages = path.get('attack_stages', [])
        if stages:
            print(f"      ├─ 攻击阶段: {self.colors['info']}{' → '.join(stages)}{self.colors['reset']}")
        
        # 时间线（显示关键事件）
        timeline = path.get('timeline', [])
        if timeline:
            print(f"      └─ 关键事件:")
            
            # 只显示前5个事件
            display_events = timeline[:5]
            for j, event in enumerate(display_events):
                is_last = (j == len(display_events) - 1) and len(timeline) <= 5
                connector = "└─" if is_last else "├─"
                
                event_icon = self.event_icons.get(event.get('event_type', 'UNKNOWN'), "❓")
                timestamp = event.get('timestamp', datetime.now())
                device = event.get('device', 'Unknown')
                description = event.get('description', '')[:50]
                
                time_str = timestamp.strftime('%H:%M:%S') if hasattr(timestamp, 'strftime') else str(timestamp)
                
                print(f"         {connector} {event_icon} [{time_str}] {self.colors['info']}{device}{self.colors['reset']}: {description}...")
            
            if len(timeline) > 5:
                print(f"         └─ {self.colors['info']}... 还有 {len(timeline) - 5} 个事件{self.colors['reset']}")
    
    def print_threat_assessment(self, threat_score: Dict[str, Any], intent_analysis: Dict[str, Any]):
        """打印威胁评估结果"""
        print(f"{self.colors['header']}🎯 威胁评估结果:{self.colors['reset']}")
        
        # 总体威胁等级
        risk_level = threat_score.get('risk_level', 'UNKNOWN')
        total_score = threat_score.get('total_score', 0.0)
        
        risk_color = self._get_severity_color(risk_level)
        risk_icon = self.threat_icons.get(risk_level, "❓")
        
        print(f"   {risk_icon} {self.colors['bold']}总体威胁等级: {risk_color}{risk_level}{self.colors['reset']}")
        print(f"   📊 威胁得分: {self._get_score_colored(total_score)} / 1.0")
        
        # 攻击意图
        primary_intent = intent_analysis.get('primary_intent', 'Unknown')
        confidence = intent_analysis.get('confidence', 0.0)
        
        intent_desc = {
            "data_exfiltration": "数据窃取",
            "lateral_movement": "横向移动",
            "privilege_escalation": "权限提升",
            "persistence": "持久化驻留",
            "reconnaissance": "侦察探测",
            "defense_evasion": "防御规避"
        }.get(primary_intent, primary_intent)
        
        print(f"   🧠 主要攻击意图: {self.colors['warning']}{intent_desc}{self.colors['reset']}")
        print(f"   🎯 意图置信度: {self._get_score_colored(confidence)}")
        
        # 详细得分
        print(f"\n   {self.colors['info']}详细评分:{self.colors['reset']}")
        score_components = threat_score.get('score_breakdown', {})
        
        for component, score in score_components.items():
            component_name = {
                'entry_confidence': '入口点置信度',
                'path_complexity': '路径复杂度',
                'cross_device': '跨设备传播',
                'technique_diversity': '技术多样性',
                'temporal_factor': '时间因素'
            }.get(component, component)
            
            print(f"      • {component_name}: {self._get_score_colored(score)}")
        
        print()
    
    def print_analysis_summary(self, 
                             total_events: int,
                             processing_time: float,
                             entry_points: List[Dict[str, Any]],
                             attack_paths: List[Dict[str, Any]],
                             threat_score: Dict[str, Any]):
        """打印分析总结"""
        print(f"{self.colors['header']}{'='*80}{self.colors['reset']}")
        print(f"{self.colors['header']}📋 分析总结{self.colors['reset']}")
        print(f"{self.colors['header']}{'='*80}{self.colors['reset']}")
        
        # 处理统计
        print(f"{self.colors['success']}✅ 分析完成!{self.colors['reset']}")
        print(f"   • 处理事件: {self.colors['highlight']}{total_events:,}{self.colors['reset']} 个")
        print(f"   • 处理时间: {self.colors['highlight']}{processing_time:.2f}{self.colors['reset']} 秒")
        print(f"   • 平均速度: {self.colors['highlight']}{total_events/processing_time:.0f}{self.colors['reset']} 事件/秒")
        
        # 检测结果
        print(f"\n{self.colors['info']}🔍 检测结果:{self.colors['reset']}")
        print(f"   • 攻击入口点: {self.colors['warning']}{len(entry_points)}{self.colors['reset']} 个")
        print(f"   • 攻击路径: {self.colors['error']}{len(attack_paths)}{self.colors['reset']} 条")
        
        # 威胁等级
        risk_level = threat_score.get('risk_level', 'UNKNOWN')
        risk_color = self._get_severity_color(risk_level)
        risk_icon = self.threat_icons.get(risk_level, "❓")
        
        print(f"   • 威胁等级: {risk_icon} {risk_color}{risk_level}{self.colors['reset']}")
        
        # 建议行动
        if risk_level in ['CRITICAL', 'HIGH']:
            print(f"\n{self.colors['error']}🚨 紧急建议:{self.colors['reset']}")
            print(f"   • 立即隔离受影响设备")
            print(f"   • 重置相关账户密码")
            print(f"   • 启动事件响应流程")
            print(f"   • 通知安全团队和管理层")
        elif risk_level == 'MEDIUM':
            print(f"\n{self.colors['warning']}⚠️  建议行动:{self.colors['reset']}")
            print(f"   • 加强监控和日志记录")
            print(f"   • 验证安全控制措施")
            print(f"   • 进行深度分析")
        
        print(f"\n{self.colors['header']}{'='*80}{self.colors['reset']}")
    
    def print_output_files(self, output_files: Dict[str, str]):
        """打印输出文件信息"""
        print(f"{self.colors['success']}📁 输出文件:{self.colors['reset']}")
        
        for file_type, file_path in output_files.items():
            file_desc = {
                'attack_chain': '攻击链报告',
                'threat_report': '威胁评估报告',
                'graph_data': '因果图数据',
                'timeline': '时间线分析'
            }.get(file_type, file_type)
            
            print(f"   📄 {file_desc}: {self.colors['highlight']}{file_path}{self.colors['reset']}")
        
        print()
    
    def _get_severity_color(self, severity: str) -> str:
        """获取威胁等级对应的颜色"""
        color_map = {
            'CRITICAL': self.colors['error'],
            'HIGH': self.colors['error'],
            'MEDIUM': self.colors['warning'],
            'LOW': self.colors['success'],
            'INFO': self.colors['info']
        }
        return color_map.get(severity, self.colors['info'])
    
    def _get_score_colored(self, score: float) -> str:
        """获取得分的彩色显示"""
        if score >= 0.8:
            color = self.colors['error']
        elif score >= 0.6:
            color = self.colors['warning']
        elif score >= 0.4:
            color = self.colors['info']
        else:
            color = self.colors['success']
        
        return f"{color}{score:.3f}{self.colors['reset']}"
    
    def print_progress_bar(self, current: int, total: int, prefix: str = "", suffix: str = ""):
        """打印进度条"""
        if total == 0:
            return
        
        percent = (current / total) * 100
        filled_length = int(50 * current // total)
        bar = '█' * filled_length + '-' * (50 - filled_length)
        
        print(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}', end='', flush=True)
        
        if current == total:
            print()  # 换行
    
    def clear_line(self):
        """清除当前行"""
        print('\r' + ' ' * 80 + '\r', end='', flush=True)
    
    def print_error(self, message: str, exception: Exception = None):
        """打印错误信息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{self.colors['error']}[{timestamp}] ❌ 错误: {message}{self.colors['reset']}")
        
        if exception:
            print(f"{self.colors['error']}   详细信息: {str(exception)}{self.colors['reset']}")
    
    def print_warning(self, message: str):
        """打印警告信息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{self.colors['warning']}[{timestamp}] ⚠️  警告: {message}{self.colors['reset']}")
    
    def print_success(self, message: str):
        """打印成功信息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"{self.colors['success']}[{timestamp}] ✅ {message}{self.colors['reset']}")
    
    def print_debug(self, message: str):
        """打印调试信息"""
        if system_config.debug_mode:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"{self.colors['info']}[{timestamp}] 🐛 调试: {message}{self.colors['reset']}")

class ProgressTracker:
    """进度跟踪器"""
    
    def __init__(self, console: ConsoleOutputManager):
        self.console = console
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, current: int, total: int, message: str = ""):
        """更新进度"""
        current_time = time.time()
        
        # 限制更新频率（每0.1秒最多更新一次）
        if current_time - self.last_update < 0.1 and current < total:
            return
        
        self.last_update = current_time
        
        # 计算速度和预估时间
        elapsed = current_time - self.start_time
        if elapsed > 0 and current > 0:
            speed = current / elapsed
            eta = (total - current) / speed if speed > 0 else 0
            suffix = f"({speed:.0f}/s, ETA: {eta:.0f}s) {message}"
        else:
            suffix = message
        
        self.console.print_progress_bar(current, total, "处理进度", suffix)

# 测试函数
def test_console_output():
    """测试控制台输出功能"""
    console = ConsoleOutputManager()
    
    # 测试系统横幅
    console.print_system_banner()
    
    # 测试步骤标题
    console.print_step_header("数据加载与预处理", "加载原始日志数据并进行标准化处理")
    
    # 测试状态信息
    console.print_processing_status("正在加载日志文件...", "INFO")
    console.print_processing_status("发现可疑活动", "WARNING")
    console.print_processing_status("检测到攻击行为", "CRITICAL")
    
    # 测试数据摘要
    from datetime import datetime, timedelta
    start_time = datetime.now() - timedelta(hours=2)
    end_time = datetime.now()
    
    console.print_data_summary(
        total_events=15420,
        devices=["192.168.1.101", "192.168.1.106", "192.168.1.108"],
        time_range=(start_time, end_time),
        external_ips=["192.168.1.200", "10.0.0.50"]
    )
    
    # 测试入口点检测
    test_entry_points = [
        {
            "device": "192.168.1.101",
            "severity": "HIGH",
            "confidence": 0.85,
            "attacker_ips": ["192.168.1.200"],
            "related_events": [
                {"event_type": "NETWORK_CONNECTION", "description": "SSH连接从192.168.1.200"}
            ]
        }
    ]
    
    console.print_entry_point_detection(test_entry_points)
    
    print("\n控制台输出测试完成!")

if __name__ == "__main__":
    test_console_output()
