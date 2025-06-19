# -*- coding: utf-8 -*-
"""
系统功能测试脚本
"""

import os
import sys
import json
from datetime import datetime

# 导入系统模块
from sz_config import path_config, system_config
from sz_data import MultiFieldIPExtractor, EventStandardizer
from sz_graph import CausalGraphBuilder
from sz_detector import ExternalEntryDetector, AttackPathSearcher
from sz_analyzer import AttackIntentAnalyzer
from sz_console import ConsoleOutputManager

def test_ip_extraction():
    """测试IP提取功能"""
    print("\n=== 测试IP提取功能 ===")
    
    extractor = MultiFieldIPExtractor()
    
    # 测试事件
    test_event = {
        "object": {
            "path": "//192.168.1.200/share/malware.exe"
        },
        "cmdLine": "net use \\\\192.168.1.200\\share /user:admin password123"
    }
    
    # 提取IP
    ip_info = extractor.extract_all_ips(test_event)
    ips = ip_info.get('external_ips', [])
    print(f"提取到的IP: {ips}")
    
    # 检查是否正确识别攻击者IP
    if "192.168.1.200" in ips:
        print("✅ 成功识别攻击者IP 192.168.1.200")
        return True
    else:
        print("❌ 未能识别攻击者IP 192.168.1.200")
        return False

def test_event_standardization():
    """测试事件标准化"""
    print("\n=== 测试事件标准化 ===")
    
    extractor = MultiFieldIPExtractor()
    standardizer = EventStandardizer()
    
    # 测试事件
    raw_event = {
        "timestamp": "2024-01-15T10:00:00Z",
        "type": "NETWORK_CONNECTION",
        "subject": {
            "host": "workstation-01",
            "cmdLine": "net use \\\\192.168.1.200\\share"
        },
        "object": {
            "path": "//192.168.1.200/share/malware.exe"
        },
        "description": "Network connection to external share"
    }
    
    # 标准化事件
    standardized = standardizer.standardize_event(raw_event)
    
    if standardized and standardized.get('extracted_ips', {}).get('external_ips'):
        print(f"✅ 事件标准化成功，外部IP: {standardized['extracted_ips']['external_ips']}")
        return True
    else:
        print("❌ 事件标准化失败")
        print(f"标准化结果: {standardized}")
        return False

def test_causal_graph():
    """测试因果图构建"""
    print("\n=== 测试因果图构建 ===")
    
    try:
        builder = CausalGraphBuilder()
        
        # 创建标准化测试事件
        from sz_data import EventStandardizer
        standardizer = EventStandardizer()
        
        raw_events = [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "type": "NETWORK_CONNECTION",
                "subject": {
                    "host": "workstation-01",
                    "cmdLine": "net use \\\\192.168.1.200\\share"
                },
                "object": {
                    "path": "//192.168.1.200/share/malware.exe"
                }
            },
            {
                "timestamp": "2024-01-15T10:01:00Z",
                "type": "FILE_CREATE",
                "subject": {
                    "host": "workstation-01"
                },
                "object": {
                    "path": "/tmp/malware.exe"
                }
            }
        ]
    
        # 标准化事件
        events = [standardizer.standardize_event(raw_event) for raw_event in raw_events]
        
        # 添加事件到图
        builder.add_events(events)
        
        # 构建因果关系
        builder.build_causal_relationships()
    
        # 检查图统计
        stats = builder.get_graph_statistics()
        
        if stats['nodes'] > 0:
            print(f"✅ 因果图构建成功，节点数: {stats['nodes']}, 边数: {stats['edges']}")
            return True
        else:
            print("❌ 因果图构建失败")
            return False
            
    except Exception as e:
        print(f"❌ 因果图构建 测试异常: {str(e)}")
        return False

def test_entry_detection():
    """测试入口点检测"""
    print("\n=== 测试入口点检测 ===")
    
    detector = ExternalEntryDetector()
    
    # 创建标准化测试事件
    raw_event = {
        "timestamp": "2024-01-15T10:00:00Z",
        "type": "NETWORK_CONNECTION",
        "subject": {
            "host": "workstation-01",
            "cmdLine": "net use \\\\192.168.1.200\\share"
        },
        "object": {
            "path": "//192.168.1.200/share/malware.exe"
        }
    }
    
    # 标准化事件
    from sz_data import EventStandardizer
    standardizer = EventStandardizer()
    events = [standardizer.standardize_event(raw_event)]
    
    # 检测入口点
    entry_points = detector.detect_entry_points(events)
    
    if entry_points:
        print(f"✅ 检测到 {len(entry_points)} 个入口点")
        for ep in entry_points:
            print(f"   - 设备: {ep['device']}, 置信度: {ep['confidence']:.2f}")
        return True
    else:
        print("❌ 未检测到入口点")
        return False

def test_load_sample_data():
    """测试加载示例数据"""
    print("\n=== 测试加载示例数据 ===")
    
    sample_file = os.path.join(path_config.test_data_dir, "sample_events.json")
    
    if not os.path.exists(sample_file):
        print(f"❌ 示例数据文件不存在: {sample_file}")
        return False
    
    try:
        with open(sample_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        events = data.get('events', [])
        print(f"✅ 成功加载 {len(events)} 个示例事件")
        
        # 检查是否包含攻击者IP
        attacker_ip_found = False
        for event in events:
            event_str = json.dumps(event)
            if "192.168.1.200" in event_str:
                attacker_ip_found = True
                break
        
        if attacker_ip_found:
            print("✅ 示例数据包含攻击者IP 192.168.1.200")
        else:
            print("⚠️  示例数据不包含攻击者IP 192.168.1.200")
        
        return True
        
    except Exception as e:
        print(f"❌ 加载示例数据失败: {e}")
        return False

def main():
    """主测试函数"""
    print("跨设备攻击溯源系统 - 功能测试")
    print("=" * 50)
    
    # 运行各项测试
    tests = [
        ("IP提取", test_ip_extraction),
        ("事件标准化", test_event_standardization),
        ("因果图构建", test_causal_graph),
        ("入口点检测", test_entry_detection),
        ("示例数据加载", test_load_sample_data)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {e}")
            results.append((test_name, False))
    
    # 输出测试结果摘要
    print("\n" + "=" * 50)
    print("测试结果摘要:")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"  {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n总计: {passed}/{total} 项测试通过")
    
    if passed == total:
        print("🎉 所有测试通过！系统功能正常")
        return 0
    else:
        print("⚠️  部分测试失败，请检查系统配置")
        return 1

if __name__ == "__main__":
    sys.exit(main())