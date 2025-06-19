#!/usr/bin/env python3
"""
跨设备攻击溯源系统 - 主控制器

该模块是系统的核心控制器，负责协调各个模块的工作流程
"""

import os
import sys
import time
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# 导入系统模块
from sz_config import path_config, system_config
from sz_data import MultiFieldIPExtractor, EventStandardizer
from sz_graph import CausalGraphBuilder
from sz_detector import ExternalEntryDetector, AttackPathSearcher, ThreatScorer
from sz_analyzer import AttackIntentAnalyzer, ThreatAssessmentReporter
from sz_console import ConsoleOutputManager, ProgressTracker

class CrossDeviceAttackTracer:
    """跨设备攻击溯源系统主控制器"""
    
    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        """初始化系统"""
        self.console = ConsoleOutputManager()
        self.start_time = datetime.now()
        
        # 应用配置覆盖
        if config_override:
            self._apply_config_override(config_override)
        
        # 初始化各个组件
        self.ip_extractor = MultiFieldIPExtractor()
        self.event_standardizer = EventStandardizer()
        self.graph_builder = CausalGraphBuilder()
        self.entry_detector = ExternalEntryDetector()
        self.path_searcher = None  # 延迟初始化，需要causal_graph
        self.threat_scorer = ThreatScorer()
        self.intent_analyzer = AttackIntentAnalyzer()
        self.report_generator = ThreatAssessmentReporter()
        
        # 分析结果存储
        self.raw_events = []
        self.standardized_events = []
        self.causal_graph = None
        self.external_entries = []
        self.attack_paths = []
        self.threat_score = 0.0
        self.attack_intent = None
        self.threat_assessment = None
        
        self.console.print_header("跨设备攻击溯源系统初始化完成")
    
    def _apply_config_override(self, config_override: Dict[str, Any]):
        """应用配置覆盖"""
        for key, value in config_override.items():
            if hasattr(system_config, key):
                setattr(system_config, key, value)
                self.console.print_info(f"配置覆盖: {key} = {value}")
    
    def analyze(self, input_path: str, debug: bool = False) -> Dict[str, Any]:
        """执行完整的攻击溯源分析"""
        try:
            self.console.print_header("开始跨设备攻击溯源分析")
            
            # 创建进度跟踪器
            progress = ProgressTracker([
                "数据加载与预处理",
                "因果图构建", 
                "外部入口检测",
                "攻击路径搜索",
                "威胁评分",
                "攻击意图分析",
                "生成分析报告"
            ])
            
            # 1. 数据加载与预处理
            progress.start_step("数据加载与预处理")
            self._load_and_preprocess_data(input_path, debug)
            progress.complete_step()
            
            # 2. 因果图构建
            progress.start_step("因果图构建")
            self._build_causal_graph(debug)
            progress.complete_step()
            
            # 3. 外部入口检测
            progress.start_step("外部入口检测")
            self._detect_external_entries(debug)
            progress.complete_step()
            
            # 4. 攻击路径搜索
            progress.start_step("攻击路径搜索")
            self._search_attack_paths(debug)
            progress.complete_step()
            
            # 5. 威胁评分
            progress.start_step("威胁评分")
            self._calculate_threat_score(debug)
            progress.complete_step()
            
            # 6. 攻击意图分析
            progress.start_step("攻击意图分析")
            self._analyze_attack_intent(debug)
            progress.complete_step()
            
            # 7. 生成分析报告
            progress.start_step("生成分析报告")
            results = self._generate_reports(debug)
            progress.complete_step()
            
            self.console.print_success("攻击溯源分析完成")
            return results
            
        except Exception as e:
            self.console.print_error(f"分析过程中发生错误: {str(e)}")
            if debug:
                import traceback
                traceback.print_exc()
            raise
    
    def _load_and_preprocess_data(self, input_path: str, debug: bool = False):
        """加载和预处理数据"""
        self.console.print_info(f"从 {input_path} 加载数据...")
        
        # 加载原始事件数据
        self.raw_events = self._load_raw_events(input_path)
        self.console.print_info(f"加载了 {len(self.raw_events)} 个原始事件")
        
        if debug:
            self.console.print_debug(f"原始事件示例: {self.raw_events[:2] if self.raw_events else '无'}")
        
        # 标准化事件数据
        self.standardized_events = self.event_standardizer.standardize_events(self.raw_events)
        self.console.print_info(f"标准化了 {len(self.standardized_events)} 个事件")
        
        if debug:
            self.console.print_debug(f"标准化事件示例: {self.standardized_events[:2] if self.standardized_events else '无'}")
    
    def _load_raw_events(self, input_path: str) -> List[Dict[str, Any]]:
        """加载原始事件数据"""
        events = []
        
        if os.path.isfile(input_path):
            # 单个文件
            events.extend(self._load_events_from_file(input_path))
        elif os.path.isdir(input_path):
            # 目录中的所有JSON文件
            for filename in os.listdir(input_path):
                if filename.endswith('.json'):
                    file_path = os.path.join(input_path, filename)
                    events.extend(self._load_events_from_file(file_path))
        else:
            raise FileNotFoundError(f"输入路径不存在: {input_path}")
        
        return events
    
    def _load_events_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """从单个文件加载事件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 处理不同的JSON格式
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # 检查是否有events或data字段
                if 'events' in data:
                    return data['events']
                elif 'data' in data:
                    return data['data']
                else:
                    # 假设整个dict就是一个事件
                    return [data]
            else:
                self.console.print_warning(f"未知的JSON格式: {file_path}")
                return []
                
        except json.JSONDecodeError as e:
            self.console.print_error(f"JSON解析错误 {file_path}: {str(e)}")
            return []
        except Exception as e:
            self.console.print_error(f"文件读取错误 {file_path}: {str(e)}")
            return []
    
    def _build_causal_graph(self, debug: bool = False):
        """构建因果图"""
        self.console.print_info("构建因果图...")
        
        self.causal_graph = self.graph_builder.build_graph(
            self.standardized_events,
            debug=debug
        )
        
        node_count = self.causal_graph.number_of_nodes()
        edge_count = self.causal_graph.number_of_edges()
        self.console.print_info(f"因果图构建完成: {node_count} 个节点, {edge_count} 条边")
        
        if debug:
            self.console.print_debug(f"图节点示例: {list(self.causal_graph.nodes())[:5]}")
    
    def _detect_external_entries(self, debug: bool = False):
        """检测外部入口点"""
        self.console.print_info("检测外部入口点...")
        
        self.external_entries = self.entry_detector.detect_entries(
            self.standardized_events,
            self.causal_graph,
            debug=debug
        )
        
        self.console.print_info(f"检测到 {len(self.external_entries)} 个外部入口点")
        
        if debug and self.external_entries:
            self.console.print_debug(f"外部入口示例: {self.external_entries[:2]}")
    
    def _search_attack_paths(self, debug: bool = False):
        """搜索攻击路径"""
        self.console.print_info("搜索攻击路径...")
        
        # 初始化路径搜索器
        self.path_searcher = AttackPathSearcher(self.causal_graph)
        
        self.attack_paths = self.path_searcher.find_attack_paths(
            self.external_entries,
            self.standardized_events,
            debug=debug
        )
        
        self.console.print_info(f"发现 {len(self.attack_paths)} 条攻击路径")
        
        if debug and self.attack_paths:
            self.console.print_debug(f"攻击路径示例: {self.attack_paths[:2]}")
    
    def _calculate_threat_score(self, debug: bool = False):
        """计算威胁评分"""
        self.console.print_info("计算威胁评分...")
        
        self.threat_score = self.threat_scorer.calculate_score(
            self.attack_paths,
            self.external_entries,
            self.standardized_events,
            debug=debug
        )
        
        self.console.print_info(f"威胁评分: {self.threat_score:.2f}")
    
    def _analyze_attack_intent(self, debug: bool = False):
        """分析攻击意图"""
        self.console.print_info("分析攻击意图...")
        
        self.attack_intent = self.intent_analyzer.analyze_intent(
            self.attack_paths,
            self.standardized_events,
            debug=debug
        )
        
        if self.attack_intent:
            self.console.print_info(f"主要攻击意图: {self.attack_intent.get('primary_intent', '未知')}")
    
    def _generate_reports(self, debug: bool = False) -> Dict[str, Any]:
        """生成分析报告"""
        self.console.print_info("生成分析报告...")
        
        # 生成威胁评估报告
        self.threat_assessment = self.report_generator.generate_report(
            threat_score=self.threat_score,
            attack_paths=self.attack_paths,
            external_entries=self.external_entries,
            attack_intent=self.attack_intent,
            events=self.standardized_events,
            debug=debug
        )
        
        # 保存报告文件
        timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        
        # 保存威胁评估报告
        threat_report_path = path_config.get_output_file_path(
            f"threat_report_{timestamp}.json", "reports"
        )
        self._save_json_file(self.threat_assessment, threat_report_path)
        
        # 保存攻击链数据
        attack_chain_path = path_config.get_output_file_path(
            f"attack_chain_{timestamp}.json", "chains"
        )
        attack_chain_data = {
            "attack_paths": self.attack_paths,
            "external_entries": self.external_entries,
            "threat_score": self.threat_score
        }
        self._save_json_file(attack_chain_data, attack_chain_path)
        
        # 保存因果图数据
        if self.causal_graph:
            graph_path = path_config.get_output_file_path(
                f"causal_graph_{timestamp}.json", "graphs"
            )
            graph_data = {
                "nodes": list(self.causal_graph.nodes(data=True)),
                "edges": list(self.causal_graph.edges(data=True))
            }
            self._save_json_file(graph_data, graph_path)
        
        # 保存时间线数据
        timeline_path = path_config.get_output_file_path(
            f"timeline_{timestamp}.json"
        )
        timeline_data = {
            "events": self.standardized_events,
            "analysis_time": self.start_time.isoformat(),
            "processing_duration": (datetime.now() - self.start_time).total_seconds()
        }
        self._save_json_file(timeline_data, timeline_path)
        
        self.console.print_success("所有报告已生成并保存")
        
        return {
            "threat_assessment": self.threat_assessment,
            "attack_paths": self.attack_paths,
            "external_entries": self.external_entries,
            "threat_score": self.threat_score,
            "attack_intent": self.attack_intent,
            "causal_graph_stats": {
                "nodes": self.causal_graph.number_of_nodes() if self.causal_graph else 0,
                "edges": self.causal_graph.number_of_edges() if self.causal_graph else 0
            },
            "files_generated": {
                "threat_report": threat_report_path,
                "attack_chain": attack_chain_path,
                "causal_graph": graph_path if self.causal_graph else None,
                "timeline": timeline_path
            }
        }
    
    def _save_json_file(self, data: Any, file_path: str):
        """保存JSON文件"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            self.console.print_info(f"已保存: {file_path}")
        except Exception as e:
            self.console.print_error(f"保存文件失败 {file_path}: {str(e)}")
    
    def get_summary(self) -> Dict[str, Any]:
        """获取分析摘要"""
        return {
            "total_events": len(self.standardized_events),
            "external_entries": len(self.external_entries),
            "attack_paths": len(self.attack_paths),
            "threat_score": self.threat_score,
            "primary_intent": self.attack_intent.get('primary_intent') if self.attack_intent else None,
            "threat_level": self.threat_assessment.get('threat_level') if self.threat_assessment else None,
            "analysis_duration": (datetime.now() - self.start_time).total_seconds()
        }

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='跨设备攻击溯源系统')
    parser.add_argument('--input', '-i', type=str, help='输入数据路径（文件或目录）')
    parser.add_argument('--test', action='store_true', help='使用测试数据')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--config', type=str, help='配置文件路径')
    
    args = parser.parse_args()
    
    # 确定输入路径
    if args.test:
        input_path = path_config.test_data_dir
    elif args.input:
        input_path = args.input
    else:
        print("错误: 必须指定 --input 或 --test 参数")
        parser.print_help()
        sys.exit(1)
    
    # 加载配置文件
    config_override = {}
    if args.config:
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                config_override = json.load(f)
        except Exception as e:
            print(f"配置文件加载失败: {e}")
            sys.exit(1)
    
    try:
        # 创建系统实例
        tracer = CrossDeviceAttackTracer(config_override)
        
        # 执行分析
        results = tracer.analyze(input_path, debug=args.debug)
        
        # 打印摘要
        summary = tracer.get_summary()
        print("\n=== 分析摘要 ===")
        print(f"总事件数: {summary['total_events']}")
        print(f"外部入口点: {summary['external_entries']}")
        print(f"攻击路径: {summary['attack_paths']}")
        print(f"威胁评分: {summary['threat_score']:.2f}")
        print(f"主要意图: {summary['primary_intent'] or '未知'}")
        print(f"威胁等级: {summary['threat_level'] or '未知'}")
        print(f"分析耗时: {summary['analysis_duration']:.2f} 秒")
        
    except KeyboardInterrupt:
        print("\n用户中断分析")
        sys.exit(0)
    except Exception as e:
        print(f"分析失败: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
