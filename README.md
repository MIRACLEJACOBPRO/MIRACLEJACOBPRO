# 跨设备攻击溯源系统 (Cross-Device Attack Tracing System)

这是一个用于检测和分析跨设备网络攻击的高级溯源系统。

## 功能特性

- 跨设备攻击检测
- 因果图构建
- 攻击链分析
- 威胁评估报告
- 时间线分析

## 系统架构

- `sz_main.py` - 主程序入口
- `sz_analyzer.py` - 攻击分析器
- `sz_detector.py` - 攻击检测器
- `sz_graph.py` - 因果图构建
- `sz_data.py` - 数据处理
- `sz_config.py` - 系统配置
- `sz_console.py` - 控制台输出

## 使用方法

```bash
python sz_main.py --test  # 使用测试数据
python sz_main.py --input <data_path>  # 使用自定义数据
```

## 输出结果

系统会生成以下分析报告：
- 攻击链报告 (attack_chain_*.json)
- 威胁评估报告 (threat_report_*.json)
- 因果图数据 (causal_graph_*.json)
- 时间线分析 (timeline_*.json)
