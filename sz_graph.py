# -*- coding: utf-8 -*-
"""
跨设备攻击溯源系统 - 因果图构建模块

该模块提供多维因果关系建模和图构建功能
"""

import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Set, Optional
from collections import defaultdict
import json
from sz_config import system_config

class CausalGraphBuilder:
    """因果图构建器 - 构建多维因果关系图"""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()  # 使用多重有向图支持多种因果关系
        self.events = {}  # 事件ID到事件对象的映射
        self.device_events = defaultdict(list)  # 设备到事件列表的映射
        self.time_window = system_config.CAUSAL_TIME_WINDOW
        self.causal_weights = system_config.CAUSAL_WEIGHTS
    
    def add_events(self, events: List[Dict[str, Any]]):
        """添加事件到图中"""
        print(f"[INFO] 开始构建因果图，添加 {len(events)} 个事件")
        
        for event in events:
            event_id = event["event_id"]
            
            # 添加事件节点
            self.graph.add_node(event_id, **event)
            self.events[event_id] = event
            
            # 按设备分组事件
            device = event["source_device"]
            self.device_events[device].append(event)
        
        # 按时间排序设备事件
        for device in self.device_events:
            self.device_events[device].sort(key=lambda x: x["timestamp"])
        
        print(f"[INFO] 事件节点添加完成，涉及 {len(self.device_events)} 个设备")
    
    def build_causal_relationships(self):
        """构建三维因果关系"""
        print("[INFO] 开始构建因果关系...")
        
        # 1. 时间因果关系
        self._build_temporal_causality()
        
        # 2. 空间因果关系（跨设备传播）
        self._build_spatial_causality()
        
        # 3. 逻辑因果关系
        self._build_logical_causality()
        
        print(f"[INFO] 因果关系构建完成，图包含 {self.graph.number_of_nodes()} 个节点，{self.graph.number_of_edges()} 条边")
    
    def _build_temporal_causality(self):
        """构建时间因果关系 - 同设备内的时序关系"""
        temporal_edges = 0
        
        for device, events in self.device_events.items():
            for i in range(len(events) - 1):
                current_event = events[i]
                next_event = events[i + 1]
                
                # 计算时间差
                time_diff = (next_event["timestamp"] - current_event["timestamp"]).total_seconds()
                
                # 在时间窗口内的事件建立因果关系
                if 0 < time_diff <= self.time_window:
                    strength = self._calculate_temporal_strength(current_event, next_event, time_diff)
                    
                    if strength > 0:
                        self.graph.add_edge(
                            current_event["event_id"],
                            next_event["event_id"],
                            causality_type="temporal",
                            strength=strength,
                            time_diff=time_diff,
                            device=device
                        )
                        temporal_edges += 1
        
        print(f"[INFO] 时间因果关系: {temporal_edges} 条边")
    
    def _build_spatial_causality(self):
        """构建空间因果关系 - 跨设备传播关系"""
        spatial_edges = 0
        all_events = list(self.events.values())
        
        for i, event1 in enumerate(all_events):
            for j, event2 in enumerate(all_events[i+1:], i+1):
                # 跳过同设备事件（已在时间因果中处理）
                if event1["source_device"] == event2["source_device"]:
                    continue
                
                # 检查是否存在跨设备传播关系
                strength = self._calculate_spatial_strength(event1, event2)
                
                if strength > 0:
                    # 确定因果方向（时间早的为因）
                    if event1["timestamp"] < event2["timestamp"]:
                        cause_event, effect_event = event1, event2
                    else:
                        cause_event, effect_event = event2, event1
                    
                    time_diff = (effect_event["timestamp"] - cause_event["timestamp"]).total_seconds()
                    
                    # 在合理时间窗口内
                    if 0 < time_diff <= self.time_window * 2:  # 跨设备允许更长时间窗口
                        self.graph.add_edge(
                            cause_event["event_id"],
                            effect_event["event_id"],
                            causality_type="spatial",
                            strength=strength,
                            time_diff=time_diff,
                            source_device=cause_event["source_device"],
                            target_device=effect_event["source_device"]
                        )
                        spatial_edges += 1
        
        print(f"[INFO] 空间因果关系: {spatial_edges} 条边")
    
    def _build_logical_causality(self):
        """构建逻辑因果关系 - 基于进程、文件等逻辑关系"""
        logical_edges = 0
        
        # 按进程ID分组事件
        process_events = defaultdict(list)
        for event in self.events.values():
            pid = event.get("causal_attributes", {}).get("process_id")
            if pid:
                process_events[pid].append(event)
        
        # 构建进程内因果关系
        for pid, events in process_events.items():
            events.sort(key=lambda x: x["timestamp"])
            
            for i in range(len(events) - 1):
                current_event = events[i]
                next_event = events[i + 1]
                
                strength = self._calculate_logical_strength(current_event, next_event)
                
                if strength > 0:
                    time_diff = (next_event["timestamp"] - current_event["timestamp"]).total_seconds()
                    
                    self.graph.add_edge(
                        current_event["event_id"],
                        next_event["event_id"],
                        causality_type="logical",
                        strength=strength,
                        time_diff=time_diff,
                        process_id=pid
                    )
                    logical_edges += 1
        
        # 构建文件操作因果关系
        file_events = defaultdict(list)
        for event in self.events.values():
            file_path = event.get("causal_attributes", {}).get("file_path")
            if file_path:
                file_events[file_path].append(event)
        
        for file_path, events in file_events.items():
            events.sort(key=lambda x: x["timestamp"])
            
            for i in range(len(events) - 1):
                current_event = events[i]
                next_event = events[i + 1]
                
                # 文件操作序列的因果关系
                if self._is_file_causality(current_event, next_event):
                    strength = 0.8  # 文件操作因果关系较强
                    time_diff = (next_event["timestamp"] - current_event["timestamp"]).total_seconds()
                    
                    self.graph.add_edge(
                        current_event["event_id"],
                        next_event["event_id"],
                        causality_type="logical",
                        strength=strength,
                        time_diff=time_diff,
                        file_path=file_path
                    )
                    logical_edges += 1
        
        print(f"[INFO] 逻辑因果关系: {logical_edges} 条边")
    
    def _calculate_temporal_strength(self, event1: Dict, event2: Dict, time_diff: float) -> float:
        """计算时间因果强度"""
        # 基础时间衰减
        time_strength = max(0, 1 - (time_diff / self.time_window))
        
        # 事件类型权重
        type1_weight = self.causal_weights.get(event1["event_type"], 0.5)
        type2_weight = self.causal_weights.get(event2["event_type"], 0.5)
        
        # 综合强度
        strength = time_strength * (type1_weight + type2_weight) / 2
        
        # 特殊模式增强
        if self._is_attack_sequence(event1, event2):
            strength *= 1.5
        
        return min(1.0, strength)
    
    def _calculate_spatial_strength(self, event1: Dict, event2: Dict) -> float:
        """计算空间因果强度（跨设备传播）"""
        strength = 0.0
        
        # 1. 共享外部IP
        external_ips1 = set(event1["extracted_ips"]["external_ips"])
        external_ips2 = set(event2["extracted_ips"]["external_ips"])
        
        if external_ips1 & external_ips2:  # 有交集
            strength += 0.8
        
        # 2. 网络传播模式
        if self._is_network_propagation(event1, event2):
            strength += 0.6
        
        # 3. 文件传播模式
        if self._is_file_propagation(event1, event2):
            strength += 0.7
        
        # 4. 命令传播模式
        if self._is_command_propagation(event1, event2):
            strength += 0.5
        
        return min(1.0, strength)
    
    def _calculate_logical_strength(self, event1: Dict, event2: Dict) -> float:
        """计算逻辑因果强度"""
        strength = 0.0
        
        # 进程父子关系
        if self._is_process_parent_child(event1, event2):
            strength += 0.9
        
        # 同进程操作
        if self._is_same_process(event1, event2):
            strength += 0.7
        
        # 文件依赖关系
        if self._is_file_dependency(event1, event2):
            strength += 0.6
        
        return min(1.0, strength)
    
    def _is_attack_sequence(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为攻击序列"""
        # 网络连接后的进程启动
        if (event1["event_type"] in ["NETWORK_RECEIVE", "NETWORK_CONNECTION"] and
            event2["event_type"] == "PROCESS_LAUNCH"):
            return True
        
        # 文件下载后的执行
        if (event1["event_type"] == "FILE_WRITE" and
            event2["event_type"] == "PROCESS_LAUNCH"):
            return True
        
        return False
    
    def _is_network_propagation(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为网络传播"""
        # 一个设备的网络发送对应另一个设备的网络接收
        if (event1["event_type"] == "NETWORK_SEND" and
            event2["event_type"] == "NETWORK_RECEIVE"):
            return True
        
        # 网络连接模式
        if (event1["event_type"] == "NETWORK_CONNECTION" and
            event2["event_type"] in ["NETWORK_RECEIVE", "PROCESS_LAUNCH"]):
            return True
        
        return False
    
    def _is_file_propagation(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为文件传播"""
        # 文件传输模式（scp, rsync等）
        cmd1 = event1.get("causal_attributes", {}).get("command_line", "")
        cmd2 = event2.get("causal_attributes", {}).get("command_line", "")
        
        if cmd1 and any(tool in cmd1.lower() for tool in ["scp", "rsync", "wget", "curl"]):
            if event2["event_type"] == "FILE_WRITE":
                return True
        
        return False
    
    def _is_command_propagation(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为命令传播"""
        # SSH连接后的命令执行
        cmd1 = event1.get("causal_attributes", {}).get("command_line", "")
        
        if cmd1 and "ssh" in cmd1.lower() and event2["event_type"] == "PROCESS_LAUNCH":
            return True
        
        return False
    
    def _is_process_parent_child(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为进程父子关系"""
        pid1 = event1.get("causal_attributes", {}).get("process_id")
        ppid2 = event2.get("causal_attributes", {}).get("parent_process_id")
        
        return pid1 and ppid2 and pid1 == ppid2
    
    def _is_same_process(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为同进程事件"""
        pid1 = event1.get("causal_attributes", {}).get("process_id")
        pid2 = event2.get("causal_attributes", {}).get("process_id")
        
        return pid1 and pid2 and pid1 == pid2
    
    def _is_file_dependency(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为文件依赖关系"""
        # 文件写入后读取
        if (event1["event_type"] == "FILE_WRITE" and
            event2["event_type"] == "FILE_READ"):
            
            path1 = event1.get("causal_attributes", {}).get("file_path")
            path2 = event2.get("causal_attributes", {}).get("file_path")
            
            return path1 and path2 and path1 == path2
        
        return False
    
    def _is_file_causality(self, event1: Dict, event2: Dict) -> bool:
        """判断是否为文件操作因果关系"""
        # 文件创建/写入 -> 文件读取/执行
        if (event1["event_type"] in ["FILE_WRITE", "FILE_CREATE"] and
            event2["event_type"] in ["FILE_READ", "PROCESS_LAUNCH"]):
            return True
        
        # 文件下载 -> 文件执行
        if (event1["event_type"] == "NETWORK_RECEIVE" and
            event2["event_type"] == "PROCESS_LAUNCH"):
            return True
        
        return False
    
    def get_attack_entry_points(self) -> List[str]:
        """获取攻击入口点（包含外部IP的事件）"""
        entry_points = []
        
        for event_id, event in self.events.items():
            if event["is_external_event"]:
                # 检查是否为真正的入口点（没有前驱或前驱很少）
                predecessors = list(self.graph.predecessors(event_id))
                
                if len(predecessors) == 0:  # 没有前驱，明确的入口点
                    entry_points.append(event_id)
                elif len(predecessors) <= 2:  # 前驱很少，可能的入口点
                    # 检查前驱是否也是外部事件
                    external_predecessors = [p for p in predecessors 
                                           if self.events[p]["is_external_event"]]
                    if len(external_predecessors) == 0:
                        entry_points.append(event_id)
        
        print(f"[INFO] 发现 {len(entry_points)} 个攻击入口点")
        return entry_points
    
    def get_cross_device_paths(self, start_event: str, max_depth: int = 10) -> List[List[str]]:
        """获取跨设备攻击路径"""
        paths = []
        
        def dfs_cross_device(current_event: str, path: List[str], visited_devices: Set[str], depth: int):
            if depth > max_depth:
                return
            
            current_device = self.events[current_event]["source_device"]
            
            # 获取后继事件
            successors = list(self.graph.successors(current_event))
            
            for successor in successors:
                successor_device = self.events[successor]["source_device"]
                
                # 如果是跨设备传播
                if successor_device != current_device:
                    new_path = path + [successor]
                    new_visited = visited_devices | {successor_device}
                    
                    # 如果路径足够长，添加到结果
                    if len(new_visited) >= 2:
                        paths.append(new_path)
                    
                    # 继续搜索
                    if successor_device not in visited_devices:
                        dfs_cross_device(successor, new_path, new_visited, depth + 1)
                else:
                    # 同设备内继续
                    dfs_cross_device(successor, path + [successor], visited_devices, depth + 1)
        
        start_device = self.events[start_event]["source_device"]
        dfs_cross_device(start_event, [start_event], {start_device}, 0)
        
        return paths
    
    def calculate_path_score(self, path: List[str]) -> float:
        """计算攻击路径得分"""
        if len(path) < 2:
            return 0.0
        
        total_score = 0.0
        
        # 1. 路径长度得分
        length_score = min(1.0, len(path) / 10)  # 最多10个事件得满分
        total_score += length_score * 0.3
        
        # 2. 跨设备传播得分
        devices = set(self.events[event_id]["source_device"] for event_id in path)
        cross_device_score = min(1.0, len(devices) / 5)  # 最多5个设备得满分
        total_score += cross_device_score * 0.4
        
        # 3. 因果关系强度得分
        causality_scores = []
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                # 可能有多条边，取最强的
                max_strength = max(data.get("strength", 0) for data in edge_data.values())
                causality_scores.append(max_strength)
        
        if causality_scores:
            avg_causality = sum(causality_scores) / len(causality_scores)
            total_score += avg_causality * 0.3
        
        return total_score
    
    def export_graph(self, output_path: str):
        """导出图结构"""
        try:
            # 准备导出数据
            graph_data = {
                "nodes": [],
                "edges": [],
                "statistics": {
                    "total_nodes": self.graph.number_of_nodes(),
                    "total_edges": self.graph.number_of_edges(),
                    "devices": len(self.device_events),
                    "external_events": len([e for e in self.events.values() if e["is_external_event"]])
                }
            }
            
            # 导出节点
            for node_id in self.graph.nodes():
                node_data = self.graph.nodes[node_id].copy()
                # 转换datetime为字符串
                if "timestamp" in node_data:
                    node_data["timestamp"] = node_data["timestamp"].isoformat()
                graph_data["nodes"].append({
                    "id": node_id,
                    "data": node_data
                })
            
            # 导出边
            for source, target, key, edge_data in self.graph.edges(keys=True, data=True):
                graph_data["edges"].append({
                    "source": source,
                    "target": target,
                    "key": key,
                    "data": edge_data
                })
            
            # 保存到文件
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(graph_data, f, ensure_ascii=False, indent=2)
            
            print(f"[INFO] 因果图已导出到: {output_path}")
            
        except Exception as e:
            print(f"[ERROR] 导出因果图失败: {str(e)}")
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """获取图统计信息"""
        stats = {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "devices": len(self.device_events),
            "external_events": len([e for e in self.events.values() if e["is_external_event"]]),
            "causality_types": defaultdict(int),
            "avg_node_degree": 0,
            "max_path_length": 0
        }
        
        # 统计因果关系类型
        for _, _, edge_data in self.graph.edges(data=True):
            causality_type = edge_data.get("causality_type", "unknown")
            stats["causality_types"][causality_type] += 1
        
        # 计算平均节点度
        if stats["nodes"] > 0:
            total_degree = sum(dict(self.graph.degree()).values())
            stats["avg_node_degree"] = total_degree / stats["nodes"]
        
        # 转换defaultdict为普通dict
        stats["causality_types"] = dict(stats["causality_types"])
        
        return stats
    
    def export_graph_data(self) -> Dict[str, Any]:
        """导出图数据用于报告生成"""
        nodes_data = []
        edges_data = []
        
        # 导出节点数据
        for node_id, node_attrs in self.graph.nodes(data=True):
            node_data = {
                "id": node_id,
                "device": node_attrs.get("source_device", ""),
                "event_type": node_attrs.get("event_type", ""),
                "timestamp": node_attrs.get("timestamp", "").isoformat() if hasattr(node_attrs.get("timestamp", ""), "isoformat") else str(node_attrs.get("timestamp", "")),
                "is_external": node_attrs.get("is_external_event", False)
            }
            nodes_data.append(node_data)
        
        # 导出边数据
        for source, target, edge_attrs in self.graph.edges(data=True):
            edge_data = {
                "source": source,
                "target": target,
                "causality_type": edge_attrs.get("causality_type", ""),
                "strength": edge_attrs.get("strength", 0.0),
                "time_diff": edge_attrs.get("time_diff", 0.0)
            }
            edges_data.append(edge_data)
        
        return {
            "nodes": nodes_data,
            "edges": edges_data,
            "statistics": self.get_graph_statistics(),
            "metadata": {
                "total_nodes": len(nodes_data),
                "total_edges": len(edges_data),
                "devices": list(self.device_events.keys()),
                "export_time": datetime.now().isoformat()
            }
        }

# 测试函数
def test_causal_graph():
    """测试因果图构建"""
    print("=== 因果图构建测试 ===")
    
    # 创建测试事件
    test_events = [
        {
            "event_id": "evt_000001",
            "timestamp": datetime.now(),
            "source_device": "192.168.1.101",
            "event_type": "NETWORK_RECEIVE",
            "extracted_ips": {"external_ips": ["192.168.1.200"], "internal_ips": []},
            "is_external_event": True,
            "causal_attributes": {"process_id": 1234}
        },
        {
            "event_id": "evt_000002",
            "timestamp": datetime.now() + timedelta(seconds=5),
            "source_device": "192.168.1.101",
            "event_type": "PROCESS_LAUNCH",
            "extracted_ips": {"external_ips": [], "internal_ips": []},
            "is_external_event": False,
            "causal_attributes": {"process_id": 1235, "parent_process_id": 1234}
        },
        {
            "event_id": "evt_000003",
            "timestamp": datetime.now() + timedelta(seconds=10),
            "source_device": "192.168.1.106",
            "event_type": "NETWORK_RECEIVE",
            "extracted_ips": {"external_ips": ["192.168.1.200"], "internal_ips": []},
            "is_external_event": True,
            "causal_attributes": {"process_id": 2234}
        }
    ]
    
    # 构建因果图
    builder = CausalGraphBuilder()
    builder.add_events(test_events)
    builder.build_causal_relationships()
    
    # 获取统计信息
    stats = builder.get_graph_statistics()
    print(f"\n图统计信息:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # 获取攻击入口点
    entry_points = builder.get_attack_entry_points()
    print(f"\n攻击入口点: {entry_points}")
    
    # 获取跨设备路径
    if entry_points:
        cross_paths = builder.get_cross_device_paths(entry_points[0])
        print(f"跨设备路径数量: {len(cross_paths)}")
        for i, path in enumerate(cross_paths[:3]):  # 显示前3条路径
            score = builder.calculate_path_score(path)
            print(f"  路径 {i+1}: {' -> '.join(path)} (得分: {score:.2f})")

if __name__ == "__main__":
    test_causal_graph()