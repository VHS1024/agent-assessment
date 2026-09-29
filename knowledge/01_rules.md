# 漏洞复测规则

规则编号：VR-HTTP-001
适用范围：仅适用于同一 URL、同一参数、同一认证状态下的对照响应
前处理：删除动态字段后再计算长度
计算方法：比较 baseline_length 和 observed_length 的差值
判定结果：
  - 差异比例 >= 0.15：输出 POSITIVE
  - 差异比例 <= 0.03：输出 NEGATIVE
  - 其他情况：输出 INCONCLUSIVE
证据要求：保存样本摘要、计算结果和原始证据文件路径
