# 恶意代码样本报告批量查询

对一批恶意代码样本，用 VirusTotal 的 API 批量检测并生成检测报告。

- **VirusTotal**（官方 API v3，`x-apikey` 头鉴权）——作业要求的检测平台
- **国家计算机病毒协同分析平台**（开放接口，`apikey` 放在请求体里）——可选，用于结果对比

支持两种输入：老师给的 **SHA256 哈希清单**，或者直接指向**样本文件目录**（程序自己算哈希）。

## 目录结构

```
batch-reports/
├── query_reports.py     全部功能都在这一个文件里：算哈希、查平台、下载报告、出检测报告
├── hashes-90.txt        检测对象1：虚拟机里取自 90 个样本的 SHA256 清单（实际 106 条）
├── hashes-100.txt       检测对象2：老师分配的 100 条 SHA256 哈希值
├── config.example.json  配置模板，复制成 config.json 填 key
├── config.json          本机实际的 key 配置
└── reports/             检测成果，每个检测对象一个子目录
    └── 检测对象N-xxx/
        ├── vt/<sha256>.json            VirusTotal 完整 JSON 报告
        ├── cverc/<sha256>.<接口>.json   协同平台报告，每个接口一个文件
        ├── summary.csv                  关键字段汇总表
        ├── detection_report.md          检测报告
        └── report_meta.json             报告用过的 label / note，重出报告时自动复用
```

## 快速开始

**1. 准备哈希清单**

清单一行一个 SHA256，行尾可以用逗号或空格加备注，`#` 开头是注释，空行和重复行会自动忽略。

注意 `--hashes` 的默认值是 `hashes.txt`，而本目录里的两份清单不叫这个名字，所以要显式指定：

```bash
python query_reports.py --hashes hashes-90.txt     # 检测对象1
python query_reports.py --hashes hashes-100.txt    # 检测对象2
```

**2. 填 API key**

把 `config.example.json` 复制成 `config.json`，填两个 key：

```json
{
  "vt_api_key": "你的VirusTotal key",
  "cverc_api_key": "你的协同分析平台apikey"
}
```

**3. 运行**

```bash
# 只查 VirusTotal
python query_reports.py --hashes hashes-90.txt --only vt --out "reports\检测对象1-样本90"

# 两个平台都查，报告里会多一列协同平台检出做对比
python query_reports.py --hashes hashes-90.txt --out "reports\检测对象1-样本90"
```

跑完在输出目录里拿到 `detection_report.md`（检测报告）、`summary.csv`（明细）、以及两个平台的原始 JSON 报告。

**两个检测对象要用不同的 `--out` 目录**，否则结果会混进同一份汇总表和报告里。

## 直接从样本文件出发（不用先准备哈希清单）

指向一个样本目录，程序自己算 SHA256 再查询：

```bash
python query_reports.py --samples D:\samples
```

会递归目录里所有文件、按内容去重（改名副本自动合并）。

### 只出清单、不联网（--list-only）

`--samples` 是就地查询，不留下清单文件。如果只要一份独立的哈希清单（比如要在断网的虚拟机里算完再带出来查），加 `--list-only`：

```bash
python query_reports.py --samples D:\samples --list-only --with-name
```

算哈希是纯读取文件内容、**不会执行任何文件**。输出默认写到 `hashes.txt`，可以用 `--hashes 别的文件名` 改。

### 平台里没有的样本，可以选择上传（--upload）

如果样本在两个平台的库里都还没有，加 `--upload` 会把样本文件本身提交给平台去分析：

```bash
python query_reports.py --samples D:\samples --upload
```

上传用的是两个平台各自的提交接口（VT 的 `POST /files`，协同平台的 `/scan/file`）。提交成功后平台要排队分析几分钟到几十分钟，**稍后重跑一次同样的命令**就能取到完整报告（已有报告会跳过，不会重复上传）。

## 在虚拟机里取哈希

**只是查已有报告的话，不需要把程序搬进虚拟机。** 哈希值本身不是恶意代码，在虚拟机里算出清单、把清单带出来在宿主机查，是更安全也更省事的做法——虚拟机可以完全断网。

1. **把 `query_reports.py` 拷进虚拟机**。不需要 `config.json`，不需要 key，也不联网。

2. **在虚拟机里解压样本压缩包**到一个目录，比如 `D:\samples`。解压密码见压缩包文件名。解压完**不要双击**里面任何可执行文件。

3. **算哈希**：

   ```bash
   python query_reports.py --samples D:\samples --list-only --with-name
   ```

4. **把清单带出虚拟机**
   
5. **回宿主机上跑报告**（宿主机要能联网）：

   ```bash
   python query_reports.py --hashes hashes.txt --out "reports\检测对象1-样本90"
   ```

## 常用参数

| 参数 | 说明 |
| --- | --- |
| `--hashes 文件` | 指定哈希清单（默认 `hashes.txt`，本目录里是 `hashes-90.txt` / `hashes-100.txt`） |
| `--samples 目录` | 直接吃样本目录：程序自己算 SHA256 再查询 |
| `--list-only` | 只算 SHA256 生成清单、不联网（配合 `--samples`） |
| `--with-name` | 生成清单时每行附上文件相对路径，便于对照 |
| `--upload` | 平台未收录时把样本文件上传给平台分析（默认关闭，需配合 `--samples`） |
| `--hash <sha256>` | 只查一个哈希，用来验证 key 是否可用 |
| `--only vt` / `--only cverc` | 只查其中一个平台 |
| `--out 目录` | 报告输出目录（默认 `reports\`） |
| `--limit 5` | 只查前 5 条，先小批量试跑 |
| `--vt-interval 16` | VT 两次请求的最小间隔秒数，免费 key 别调小于 16 |
| `--cverc-endpoints basic,engines` | 协同平台要取哪几个接口，见下表 |
| `--force` | 已有报告也重新下载 |
| `--summary-only` | **不联网**，只根据已下载的报告重算 `summary.csv` 和 `detection_report.md` |
| `--label 名称` | 检测报告里"检测对象"的名称，默认取 `--out` 的目录名 |
| `--note 文字` | 往报告开头加一行"说明"，可重复用多次 |
| `--report-detail` | 把全部样本明细表也写进检测报告（默认不写，保持篇幅精简） |

协同平台的接口可选值（可用性以本机 apikey 实测为准）：

| 名称 | 接口路径 | 内容 | 本机 apikey |
| --- | --- | --- | --- |
| `basic` | `/v1/file/report` | 文件名、格式、大小、家族名、可信度 | ✅ 可用过 |
| `engines` | `/v1/file/multiscan/report` | 多引擎检出结果 | ✅ 可用过 |
| `static` | `/v1/file/staticinfo/report` | PE 头、节表、导入表、模糊哈希 | ⚠️ 权限未开通 |
| `dynamic` | `/v1/file/dynamics/report` | 动态行为报告 | ⚠️ 权限未开通 |
| `full` | `/v1/file/full/report` | 平台自己的"文件完整检测报告" | ⚠️ 权限未开通 |

`static`/`dynamic`/`full` 平台返回"当前账户未开通此api权限"（响应码 -1），普通用户账号拿不到。程序会**自动识别并跳过**这类接口，不会反复重试浪费时间，跑完会提示是哪个接口没取到。需要 PE 头和导入表的话，直接从 VT 的 JSON 报告里取——`reports/.../vt/<sha256>.json` 里本来就有。

## 检测报告

跑完会在输出目录里生成 `detection_report.md`，考虑到"篇幅不宜过长"，默认只出概览性的短表，**一页以内**：

| 节 | 内容 |
| --- | --- |
| 检测对象 / 说明 | 标题下方标注这批样本是哪一类；`--label` 指定名称，`--note` 追加说明 |
| 一、检测结果概览 | 样本总数、已收录/未收录数、至少一家引擎报毒的数量、平均检出率 |
| 二、检出率分布 | 按检出的引擎数分档（0 家 / 1–5 家 / 6–20 家 / 21 家及以上） |
| 三、主要恶意家族 | 按 VT 聚合标签统计 Top 10；表下会注明有多少样本被标注 |
| 四、文件类型分布 | PE / 脚本 / 压缩包等类型统计 |
| 五、检出率最高的样本 | Top 10，含文件名、检出比、家族；有协同数据时会多一列 |
| 六、未收录的样本 | 数量加少量哈希，其余指向 `summary.csv` |

每个样本的完整字段（大小、MD5/SHA1、SSDeep/TLSH、提交时间等）都在同目录的 `summary.csv` 里，不必塞进报告。确实需要把明细表也写进报告时加 `--report-detail`，会多出"七、全部样本明细"一节。

报告是纯文本 Markdown，可以直接交、贴进实验报告，或者用 `pandoc` 转成 Word/PDF。

`--label` 和 `--note` 会记进输出目录的 `report_meta.json`，所以以后重出报告不用再传一遍：

```bash
# 不联网重出报告，标签和说明自动带上
python query_reports.py --summary-only --out "reports\检测对象1-样本90"
```

## 关于两个平台的 API

**VirusTotal**：官方文档的 v3 接口 `GET https://www.virustotal.com/api/v3/files/{hash}`，鉴权靠请求头 `x-apikey`。报告是完整原始 JSON，字段和网页上看到的一致。官方文档写明公开 API 限制是**每分钟 4 次、每天 500 次**，且不得用于商业产品、不得注册多账号绕过限制。程序查 100 条哈希约 27 分钟，远在每天 500 次以内。

**协同分析平台**：没有对外发布的接口文档，程序里的路径和参数是从平台自己的接口文档页（`https://virus.cverc.org.cn/#/api/info`，响应码表在同站的 `#/api/code_info`）的前端代码里取出来的，已实测可达：

- 路径形如 `https://virus.cverc.org.cn/api/v1/file/report`，参数 `{"apikey": "...", "hash": "..."}`；`full` 接口的参数名是 `hashes`（列表）。
- **样本不在平台库里时，平台返回的是 `code: 0` 加一个空的 `data`**，并不是错误码。所以程序判断"是否收录"看的是 `data` 里有没有内容，不会误报成"已收录"。
- 官方响应码：`0` 成功、`2` 未检索到数据、`3` 任务进行中、`4` 文件等待扫描、`5` 文件扫描超时、`-1` 权限受限或外部服务不可用、`-2` 请求无效、`-3` 参数错误、`-4` 超限、`-5` 系统错误。
- 无效密钥返回 `{"code": -1, "msg": "API密钥无效，请检查后重试"}`，程序立刻停下提示，不会空转重试。
- 不管成功失败，接口的原始响应都会存进 `reports/.../cverc/`，可以直接打开看平台到底回了什么。
- 平台的两个报告接口都是**按单个样本**出报告的，没有"给一批哈希返回一份报告"的批量接口——批量这件事只能由程序来做。

## 常见问题

**协同平台报"远程主机强迫关闭了一个现有的连接"（ConnectionResetError）**

先检查是不是开了**代理或 VPN**。实测开着 VPN 时，Python 的请求会被平台侧重置连接，关掉后同样的代码立刻正常。这和代码无关（`curl` 可能不受影响，所以别用 curl 能不能通来判断）。

**`summary.csv` 里某些列是空的**

对应的接口没取到数据。常见的是 `cverc_pack`/`cverc_compiler` 为空，因为它们来自需要额外权限的 `static` 接口。

**VirusTotal 报 429**

免费 key 每分钟只能 4 次。程序默认 16 秒一次，如果同时还在用网页版或其它工具查，容易撞上限流；等一分钟重跑即可，已下载的报告会跳过。

## 限速与断点续传

VirusTotal 免费账号限制**每分钟 4 次、每天 500 次**，所以程序默认每次请求间隔 16 秒，100 个哈希约 27 分钟。触发 429 时会读 `Retry-After` 自动等待重试（指数退避，最多 5 次）。有付费 key 的话用 `--vt-interval` 调小间隔。

程序是**断点续传**的：已存在报告文件的哈希会直接跳过，所以中途 `Ctrl+C`、断网或超时都不用怕，重新运行会接着没查完的继续。中断时程序仍会把已有的报告整理成汇总表和检测报告再退出。

## 输出说明

`detection_report.md` 是给检测报告；`summary.csv` 用 Excel 打开，是每个样本的完整明细：

- VT：是否收录、检出比、家族标签、类别、威胁名称、文件名、类型、大小、MD5/SHA1、SSDeep/TLSH 模糊哈希、首次提交时间、最近分析时间、提交次数、标签
- 协同平台：是否收录、检出比、恶意家族名、格式、文件名、大小、可信度、加壳信息、编译器

某个样本在某个平台未收录时，对应列会写「未收录」，不影响其他行。

## 注意

- 程序只查询哈希、**不下载样本文件本身**，所有报告都是 JSON 文本，在联网机器上分析没有风险。只有显式加 `--upload` 时才会把样本发给平台。
- 需要 Python 3（算哈希只用标准库；联网查询需要 `requests`：`pip install requests`）。
- `config.json` 里是你的 API 凭据，别把它连同报告一起外传。
