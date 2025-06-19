#!/usr/bin/env python3
"""
跨设备攻击溯源系统 - 配置管理模块

该模块提供系统配置和路径配置管理功能
"""

import os
from pathlib import Path

class PathConfig:
    """路径配置类 - 管理系统的输入输出路径"""
    
    def __init__(self, base_dir=None):
        # 设置基础目录
        if base_dir is None:
            self.base_dir = Path.cwd()
        else:
            self.base_dir = Path(base_dir)
        
        # 默认输入路径
        self.DEFAULT_INPUT_PATH = "all_data/test_data/test.json"
        
        # 默认输出路径
        self.DEFAULT_OUTPUT_DIR = "output/"
        self.DEFAULT_CHAIN_DIR = "output/chains/"
        self.DEFAULT_GRAPH_DIR = "output/graphs/"
        self.DEFAULT_REPORT_DIR = "output/reports/"
        
        # 测试数据路径
        self.TEST_DATA_PATH = "all_data/json_data/"
        self.REFERENCE_CHAIN_PATH = "all_data/Chain/"
        
        # 添加缺失的属性
        self.input_dir = self.DEFAULT_INPUT_PATH
        self.output_dir = self.DEFAULT_OUTPUT_DIR
        self.chains_dir = self.DEFAULT_CHAIN_DIR
        self.graphs_dir = self.DEFAULT_GRAPH_DIR
        self.reports_dir = self.DEFAULT_REPORT_DIR
        self.test_data_dir = "all_data/test_data"
        
        # 可视化输出路径
        self.GRAPH_OUTPUT_PATH = "output/graphs/attack_graph.dot"
        self.CHAIN_VISUALIZATION_PATH = "output/chains/attack_chain_visual.txt"
        
        # 确保输出目录存在
        self._ensure_output_directories()
    
    def _ensure_output_directories(self):
        """确保所有输出目录存在"""
        output_dirs = [
            self.DEFAULT_OUTPUT_DIR,
            self.DEFAULT_CHAIN_DIR,
            self.DEFAULT_GRAPH_DIR,
            self.DEFAULT_REPORT_DIR
        ]
        
        for dir_path in output_dirs:
            full_path = self.base_dir / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
    
    def get_absolute_path(self, relative_path):
        """获取相对路径的绝对路径"""
        return str(self.base_dir / relative_path)
    
    def get_input_file_path(self, filename=None):
        """获取输入文件的完整路径"""
        if filename is None:
            return self.get_absolute_path(self.DEFAULT_INPUT_PATH)
        return self.get_absolute_path(filename)
    
    def get_output_file_path(self, filename, output_type="chains"):
        """获取输出文件的完整路径"""
        output_dirs = {
            "chains": self.DEFAULT_CHAIN_DIR,
            "graphs": self.DEFAULT_GRAPH_DIR,
            "reports": self.DEFAULT_REPORT_DIR
        }
        
        output_dir = output_dirs.get(output_type, self.DEFAULT_OUTPUT_DIR)
        return self.get_absolute_path(output_dir + filename)

class SystemConfig:
    """系统配置类 - 管理系统运行参数"""
    
    def __init__(self):
        # 因果图构建参数
        self.CAUSAL_TIME_WINDOW = 300  # 5分钟时间窗口
        self.CAUSAL_STRENGTH_THRESHOLD = 0.3  # 因果关系强度阈值
        
        # 攻击检测参数
        self.MAX_ATTACK_PATH_DEPTH = 15  # 最大攻击路径深度
        self.HIGH_RISK_SCORE_THRESHOLD = 80  # 高风险评分阈值
        self.SUSPICION_SCORE_THRESHOLD = 0.5  # 可疑度评分阈值
        
        # 性能参数
        self.MAX_PROCESSING_TIME = 30  # 最大处理时间（秒）
        self.MAX_MEMORY_USAGE = 1024  # 最大内存使用（MB）
        
        # 内部可信设备IP范围
        self.TRUSTED_IP_RANGES = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12"
        ]
        
        # 外部攻击者IP识别
        self.KNOWN_ATTACKER_IPS = [
            "192.168.1.200",  # 测试攻击者IP
        ]
        
        # 攻击检测规则
        self.ATTACK_INDICATORS = {
            "suspicious_commands": ["ssh", "scp", "wget", "curl", "nc", "ncat"],
            "suspicious_files": [".sh", ".py", ".exe", ".bat"],
            "suspicious_network_events": ["NETWORK_RECEIVE", "NETWORK_SEND"],
            "authentication_events": ["AUTH_SUCCESS", "AUTH_FAILURE"]
        }
        
        # 威胁评分权重
        self.THREAT_SCORE_WEIGHTS = {
            "external_entry": 0.3,
            "lateral_movement": 0.25,
            "privilege_escalation": 0.2,
            "data_exfiltration": 0.15,
            "persistence": 0.1
        }
        
        # 控制台输出配置
        self.CONSOLE_COLORS = {
            "header": "\033[95m",
            "info": "\033[94m",
            "success": "\033[92m",
            "warning": "\033[93m",
            "error": "\033[91m",
            "debug": "\033[90m",
            "reset": "\033[0m",
            "bold": "\033[1m"
        }
        
        # 日志配置
        self.LOG_LEVEL = "INFO"
        self.LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        self.LOG_FILE = "output/system.log"
        
        # 图形可视化配置
        self.GRAPH_LAYOUT = "spring"
        self.GRAPH_NODE_SIZE = 300
        self.GRAPH_FONT_SIZE = 8
        self.GRAPH_FIGURE_SIZE = (12, 8)
        
        # 报告生成配置
        self.REPORT_TEMPLATE = "default"
        self.INCLUDE_DETAILED_TIMELINE = True
        self.INCLUDE_GRAPH_VISUALIZATION = True
        
        # 数据处理配置
        self.EVENT_BATCH_SIZE = 1000
        self.MAX_EVENT_AGE_DAYS = 30
        self.ENABLE_EVENT_DEDUPLICATION = True
        
        # 攻击路径搜索配置
        self.PATH_SEARCH_ALGORITHM = "dfs"  # dfs, bfs, dijkstra
        self.MAX_PATHS_PER_ENTRY = 10
        self.PATH_SIMILARITY_THRESHOLD = 0.8
        
        # 机器学习模型配置（如果使用）
        self.ML_MODEL_PATH = "models/"
        self.ENABLE_ML_DETECTION = False
        self.ML_CONFIDENCE_THRESHOLD = 0.7
        
        # API配置（如果需要外部集成）
        self.API_TIMEOUT = 30
        self.API_RETRY_COUNT = 3
        self.ENABLE_EXTERNAL_THREAT_INTEL = False
        
        # 缓存配置
        self.ENABLE_CACHING = True
        self.CACHE_TTL = 3600  # 1小时
        self.CACHE_SIZE_LIMIT = 100  # MB
        
        # 并发处理配置
        self.MAX_WORKER_THREADS = 4
        self.ENABLE_PARALLEL_PROCESSING = True
        
        # 安全配置
        self.ENABLE_INPUT_VALIDATION = True
        self.MAX_INPUT_FILE_SIZE = 100  # MB
        self.ALLOWED_FILE_EXTENSIONS = [".json", ".log", ".txt"]
        
        # 调试配置
        self.DEBUG_MODE = False
        self.VERBOSE_LOGGING = False
        self.SAVE_INTERMEDIATE_RESULTS = False
        
        # 性能监控配置
        self.ENABLE_PERFORMANCE_MONITORING = True
        self.PERFORMANCE_LOG_INTERVAL = 60  # 秒
        
        # 告警配置
        self.ENABLE_ALERTS = True
        self.ALERT_THRESHOLD_HIGH = 80
        self.ALERT_THRESHOLD_CRITICAL = 95
        
        # 数据保留配置
        self.KEEP_RAW_DATA = True
        self.DATA_RETENTION_DAYS = 90
        self.AUTO_CLEANUP_OLD_RESULTS = True

# 创建全局配置实例
path_config = PathConfig()
system_config = SystemConfig()

# 配置验证函数
def validate_config():
    """验证配置的有效性"""
    errors = []
    
    # 验证路径配置
    if not os.path.exists(path_config.base_dir):
        errors.append(f"基础目录不存在: {path_config.base_dir}")
    
    # 验证系统配置
    if system_config.CAUSAL_TIME_WINDOW <= 0:
        errors.append("因果时间窗口必须大于0")
    
    if not (0 <= system_config.CAUSAL_STRENGTH_THRESHOLD <= 1):
        errors.append("因果关系强度阈值必须在0-1之间")
    
    if system_config.MAX_ATTACK_PATH_DEPTH <= 0:
        errors.append("最大攻击路径深度必须大于0")
    
    return errors

# 配置更新函数
def update_config(config_dict):
    """从字典更新配置"""
    for key, value in config_dict.items():
        if hasattr(system_config, key):
            setattr(system_config, key, value)
        elif hasattr(path_config, key):
            setattr(path_config, key, value)
        else:
            print(f"警告: 未知配置项 {key}")

# 配置导出函数
def export_config():
    """导出当前配置为字典"""
    config_dict = {}
    
    # 导出系统配置
    for attr in dir(system_config):
        if not attr.startswith('_'):
            config_dict[f"system.{attr}"] = getattr(system_config, attr)
    
    # 导出路径配置
    for attr in dir(path_config):
        if not attr.startswith('_') and not callable(getattr(path_config, attr)):
            config_dict[f"path.{attr}"] = getattr(path_config, attr)
    
    return config_dict

if __name__ == "__main__":
    # 配置测试
    print("配置验证结果:")
    errors = validate_config()
    if errors:
        for error in errors:
            print(f"错误: {error}")
    else:
        print("配置验证通过")
    
    print(f"\n基础目录: {path_config.base_dir}")
    print(f"输出目录: {path_config.DEFAULT_OUTPUT_DIR}")
    print(f"测试数据目录: {path_config.test_data_dir}")
    print(f"因果时间窗口: {system_config.CAUSAL_TIME_WINDOW}秒")
    print(f"最大攻击路径深度: {system_config.MAX_ATTACK_PATH_DEPTH}")
