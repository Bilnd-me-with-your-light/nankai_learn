# 恶意代码批量检测报告

- 检测对象：90 个真实恶意代码样本
- 数据来源：VirusTotal API v3；国家计算机病毒协同分析平台开放接口
- 样本数：106
- 生成时间：2026-09-30 03:15:30
- 说明：该目录实际含 106 个文件，均已检测

## 一、检测结果概览

| 指标 | 数量 | 占比 |
| --- | --- | --- |
| 样本总数 | 106 | 100.0% |
| VirusTotal 已收录 | 106 | 100.0% |
| VirusTotal 未收录 | 0 | 0.0% |
| 至少一家引擎报毒 | 105 | 99.1% |
| 平均检出率（报毒引擎占比） | 62.5% | — |

## 二、检出率分布

| 检出的引擎数 | 样本数 | 占比 |
| --- | --- | --- |
| 0（无引擎报毒） | 1 | 0.9% |
| 1–5 家 | 0 | 0.0% |
| 6–20 家 | 0 | 0.0% |
| 21 家及以上 | 105 | 99.1% |

## 三、主要恶意家族（Top 10）

| 家族 | 样本数 |
| --- | --- |
| trojan.cerber/zerber | 1 |
| trojan.encoder/expelcod | 1 |
| trojan.gandcrab/chapak | 1 |
| trojan.xorist/razr | 1 |

> VirusTotal 只为 106 个样本中的 4 个给出了聚合家族标签，其余样本没有家族标注——这是平台侧的数据限制，不是漏查；未标注样本的检出命名可查 summary.csv。

## 四、文件类型分布（Top 10）

| 文件类型 | 样本数 |
| --- | --- |
| ZIP | 106 |

## 五、检出率最高的样本（Top 10）

| # | SHA256 | 文件名 | 检出比 | 家族 | 协同平台检出 |
| --- | --- | --- | --- | --- | --- |
| 1 | `d4a2a8ff4c30e42c6e0df15ab0e4ab4ca9aef10ecc06a84e8845fcfe5ae66483` | 锁机.zip | 57/75 | - | - |
| 2 | `696a971f31a94211807e35560fcd34bde565e13404aac4c16dee3a5840123e06` | Ransom.crowti 勒索.zip | 56/74 | - | - |
| 3 | `037171c0bfd60eb438eab7f1bf51ac77dffcc137963f1120ad041dd6a55d50b9` | memz_____.zip | 55/75 | - | - |
| 4 | `ad886c73ae4ff4e6ab2ea50be01e90cf12d93cef9014a61a0a5c01dc0399905c` | Ransom_HPCERBER.SMONT2 勒索.zip | 55/75 | - | - |
| 5 | `54f7edcb849c72c7c8ea43b91250e5d70867cf217bd011b93055afa120d15a6f` | Ransom.Mole 勒索.zip | 54/75 | - | - |
| 6 | `5df11d20ab7bd6f2535067e5b7a21cb6fc4b7c7bf0cb1cfc6b451367ccae5da7` | Ransom.Petya (DLL)勒索.zip | 54/75 | - | - |
| 7 | `7580532be2f1215f83574f14d14a939988a54516f9617c7b2f1cc6bcde1fea72` | Sage.Ransom 勒索.zip | 54/75 | - | 10/17 |
| 8 | `f636b1a16aab9ae14cfdde5b0963e36d3d1fbce1d70262e833402d7fa722f67c` | Petya 勒索.zip | 54/75 | - | - |
| 9 | `fa491f5ff14e079bcc8f01667e1b42133a46e47efb8dd472fe1f2b47917ad5a2` | wcry2.0 勒索.zip | 54/75 | - | - |
| 10 | `26c186803930e1ff4ac8ee741a53ad77bc6d7bae92aa225ca4b4c502699de648` | Ransom.Cerber 2 勒索.zip | 53/75 | - | - |

> 「协同平台检出」列中的「-」表示国家计算机病毒协同分析平台没有收录该样本；本批 106 个样本中该平台有检出数据的是 4 个。

## 六、VirusTotal 未收录的样本

（全部样本均已在 VirusTotal 收录）

> 每个样本的完整字段（哈希、大小、类型、检出比、家族、提交时间等）见同目录的 `summary.csv`。