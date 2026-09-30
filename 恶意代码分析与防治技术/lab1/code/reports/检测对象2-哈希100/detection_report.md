# 恶意代码批量检测报告

- 检测对象：100 条 SHA256 哈希值
- 数据来源：VirusTotal API v3；国家计算机病毒协同分析平台开放接口
- 样本数：100
- 生成时间：2026-09-30 03:09:25

## 一、检测结果概览

| 指标 | 数量 | 占比 |
| --- | --- | --- |
| 样本总数 | 100 | 100.0% |
| VirusTotal 已收录 | 99 | 99.0% |
| VirusTotal 未收录 | 1 | 1.0% |
| 至少一家引擎报毒 | 99 | 99.0% |
| 平均检出率（报毒引擎占比） | 75.9% | — |

## 二、检出率分布

| 检出的引擎数 | 样本数 | 占比 |
| --- | --- | --- |
| 0（无引擎报毒） | 0 | 0.0% |
| 1–5 家 | 0 | 0.0% |
| 6–20 家 | 1 | 1.0% |
| 21 家及以上 | 98 | 98.0% |
| 平台未收录（无检出数据） | 1 | 1.0% |

## 三、主要恶意家族（Top 10）

| 家族 | 样本数 |
| --- | --- |
| trojan.upatre/jqby | 2 |
| ransomware.gandcrab/encoder | 1 |
| ransomware.gandcrab/gandcrypt | 1 |
| ransomware.lockbit/blackmatter | 1 |
| trojan.convagent/injuke | 1 |
| trojan.cryptolocker/upatre | 1 |
| trojan.dpeq/presenoker | 1 |
| trojan.emotetu/hes7fooi | 1 |
| trojan.guloader/nsis | 1 |
| trojan.msil/taskun | 1 |

> VirusTotal 只为 100 个样本中的 15 个给出了聚合家族标签，其余样本没有家族标注——这是平台侧的数据限制，不是漏查；未标注样本的检出命名可查 summary.csv。

## 四、文件类型分布（Top 10）

| 文件类型 | 样本数 |
| --- | --- |
| Win32 EXE | 99 |

## 五、检出率最高的样本（Top 10）

| # | SHA256 | 文件名 | 检出比 | 家族 | 协同平台检出 |
| --- | --- | --- | --- | --- | --- |
| 1 | `e4340671519e67e8bf5f79c24b9ddeb2393e79f6f9467d89167eb81dbb4c0056` | misid.exe | 68/76 | - | 14/14 |
| 2 | `e4c4038f4aafd810ad506d2dcc1ce5bd4de17dac221a895c4aaefde150f3fb4e` | lossy.exe | 67/75 | trojan.upatre/jqby | 14/14 |
| 3 | `e4e024d389669e5d1ded99f025d7d87675eb4e6cbb49e9a59775d47425748f42` | - | 67/76 | - | 13/14 |
| 4 | `e4e7cc527184a1724559b6c2887514d7e45ef0c990b861b4667799553c199ea8` | {12A061A6-DB1D-4433-B7D9-66ABC23E26DF}.exe | 66/76 | - | 14/14 |
| 5 | `e4f49129ec71efbff45599bfe2d1c8d50bed72e218a82a9e7c962413dd5e9813` | WinWord.exe | 66/76 | - | 13/14 |
| 6 | `e50d2e5f050a76a9e063e6361b29d83c55960291668f2178fb7ea45e89ff1539` | - | 66/75 | trojan.upatre/jqby | 14/14 |
| 7 | `e594e1a1f984b5b3982571d5519c39ba132eb63a4fdd3cbdcc60f7c4775fb2e3` | asih.exe | 66/75 | - | 14/14 |
| 8 | `e407076bd7576e05d6d9b4a37fca380d9b8561c308f9eb1f1ed9c42861234a48` | Multimedia.exe | 65/76 | - | 14/14 |
| 9 | `e44e5833e97e572af6bef5e53cee0cd328a6a14767ea64c4ff1c88b1f47e479e` | WinWord.exe | 65/75 | - | 13/14 |
| 10 | `e48f56198e301531ce5bff14c3abdfab0059d61b0bc47d9da5a3618342364fb7` | WinWord.exe | 65/75 | - | 13/14 |

> 「协同平台检出」列中的「-」表示国家计算机病毒协同分析平台没有收录该样本；本批 100 个样本中该平台有检出数据的是 93 个。

## 六、VirusTotal 未收录的样本

共 1 个样本未收录，其中：

`e53b1a1d8bcdcedd187302b4e9c5b063ce579cd2be4b181f0e7005eae6e8be18`

> 每个样本的完整字段（哈希、大小、类型、检出比、家族、提交时间等）见同目录的 `summary.csv`。