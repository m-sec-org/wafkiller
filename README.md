# WAF Killer
`WAF Killer` 是一个使用 Go 编写的桌面工具，主要用于采集疑似存在 WAF 的站点、做 WAF 指纹识别、管理规则，并对规则验证结果进行聚类和统计展示。

> 说明：为避免主仓库体积过大，README 配套截图与演示素材托管在独立的 `readme-assets` 分支，不随 `main` 一起分发。

## 使用说明
第一次启动时，默认没有WAF池数据，需要自动化灌入数据便于测试。需要先配置fofa key，然后点击一键执行，这里可以将 ✖️ 后面的数字改大一些，推荐使用8-10，这样可以连续多轮从Fofa 拉去数据灌入WAF池，一键执行会自动生成采样关键词（每轮随机产生），然后自动识别站点是否存在WAF，自动对WAF拦截页面生成浏览器快照并进行聚类。聚类后我们可以手工根据经验为WAF产品厂商添加标签，便于后续测试的时候快速找出针对某厂商WAF的通用绕过规则。
![Main](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/Main.gif?raw=1)

扫描后，可根据经验对新增的聚类分组打标签，标记WAF类型，这些标记会固化到规则便于下次直接匹配。可根据经验编写绕过规则，也可以用内置AI模型直接生成规则，目前支持GPT-Codex和智谱-GLM两种模型。以最近热度较高的Java幽灵比特绕过为例：
![110529_766](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/28a843953e4955bd650b89bb91c4f12a.jpg?raw=1)

生成的规则如下：
![110500_448](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/110500_448.jpg?raw=1)

通过规则验证，测试规则bypass成功率：
![110620_011](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/110620_011.jpg?raw=1)
还可以通过规则对比，观察两条规则绕过的差异：
![](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/17781233482441.jpg?raw=1)

![](https://github.com/m-sec-org/wafkiller/blob/readme-assets/assets/17781233697412.jpg?raw=1)


## 主要能力

- 通过 FOFA 批量采集站点
- 对响应进行疑似 WAF 识别与聚类
- 支持 `waf.yaml` 指纹规则识别
- 支持基于原始 HTTP 报文的规则库加载与验证
- 支持绕过统计、规则对比、详情查看
- 支持运行数据导入、导出
- 支持 OpenAI / 智谱 智能体接入
- 支持上行代理、下行代理与证书配置

## 目录说明

核心目录如下：

- [main.go](main.go)：程序入口
- [internal/ui](internal/ui)：桌面界面与主要交互逻辑
- [internal/tester](internal/tester)：规则验证与请求执行
- [internal/detector](internal/detector)：站点探测与相似度判断
- [internal/plugin](internal/plugin)：规则加载与元信息解析
- [internal/store](internal/store)：本地数据存储
- [plugins](plugins)：高级规则目录
- [waf.yaml](waf.yaml)：WAF 识别规则
- [config.json](config.json)：本地运行配置
- [config.release.json](config.release.json)：发布配置模板

## 运行环境

- Go `1.25+`
- 默认使用仓库自带 `vendor/` 依赖
- macOS 本地运行可直接 `make run`
- Windows 交叉编译需要 `mingw-w64`

## 快速开始

### 1. 准备配置

程序默认读取项目根目录的 `config.json`。

如果只是本地体验界面，可以先直接运行；如果要用 FOFA、智能体或代理，再补充相关配置。

### 2. 启动程序

```bash
make run
```

或直接执行：

```bash
GOCACHE=$(pwd)/.gocache GOMODCACHE=$(pwd)/.gomodcache go run -mod=vendor .
```

### 3. 常用构建

```bash
make build
```

该命令会编译当前仓库所有 Go 包，适合日常检查改动是否可编译。

## Windows 64 位发布

仓库已经提供了 Windows 发布脚本：

- [scripts/build_windows_release.sh](scripts/build_windows_release.sh)

脚本行为：

- 生成 `release/windows-amd64/`
- 复制脱敏后的 `config.json`
- 保留 `waf.yaml`
- 保留 `plugins/`
- 编译 `wafbps.exe`

执行方式：

```bash
scripts/build_windows_release.sh
```

当前发布产物默认放在：

- [release/windows-amd64](release/windows-amd64)
- [release/wafbps-windows-amd64.zip](release/wafbps-windows-amd64.zip)

说明：

- 发布包不会复用你本地正在使用的 `config.json`
- FOFA、OpenAI、智谱的密钥会被清空
- 发布配置默认关闭智能体

## 配置文件说明

默认配置文件是 `config.json`，常用字段如下。

### FOFA

- `fofa.email`：FOFA 邮箱
- `fofa.api_key`：FOFA Key
- `fofa.query`：默认查询语句
- `fofa.size`：每轮采集数量

### 应用

- `app.database_path`：本地数据库路径
- `app.window_title`：窗口标题

### 探测与验证

- `tester.timeout_seconds`：请求超时
- `tester.concurrency`：并发数
- `tester.snapshot_concurrency`：快照并发数
- `tester.verify_tls`：是否校验证书
- `tester.default_scheme`：默认协议

### 规则目录

- `plugin.dir`：规则目录，默认 `plugins`

### 智能体

- `llm_provider`：当前默认智能体供应商
- `openai.enabled` / `zhipu.enabled`：是否启用
- `openai.api_key` / `zhipu.api_key`：各自密钥
- `openai.proxy_url` / `zhipu.proxy_url`：各自独立代理

### 变量

- `variables.USER_AGENT`：默认浏览器 UA
- `variables.PAYLOAD`：默认示例变量

## 规则文件格式

规则文件支持：

- `.http`
- `.req`
- `.txt`

推荐写成原始 HTTP 报文格式，例如：

```http
# @name: 示例规则
# @color: green
# @validate: baseline_similarity
# @threshold: 0.90
# @tags: demo,post
# @intent: replace
# @intent.replace_from: " "
# @intent.replace_to: "%20"
POST / HTTP/1.1
Host: {{TARGET_HOST_HEADER}}
User-Agent: {{USER_AGENT}}
Content-Type: application/x-www-form-urlencoded

id=1
```

## 规则元信息

目前支持的常用元信息：

- `# @name:`：规则名称
- `# @tags:`：标签，逗号分隔
- `# @color:`：规则颜色
- `# @scheme:`：默认协议
- `# @validate:`：验证模式
- `# @threshold:`：相似度阈值
- `# @note:`：备注
- `# @intent:`：规则意图
- `# @intent.xxx:`：意图参数
- `# @preflight_mode:`：预探测方式
- `# @preflight_prune:`：预探测是否自动裁剪无效 URL

说明：

- 旧版 `@waf` 过滤机制已经移除，规则不会再按目标 WAF 类型做精确筛选
- `template.http` 是内置模板规则，会自动保留

## `@color` 可选颜色

- `cyan`
- `blue`
- `green`
- `amber`
- `orange`
- `gold`
- `pink`
- `purple`
- `violet`
- `lavender`
- `red`
- `rose`
- `teal`
- `yellow`
- `white`
- `ice`

## 预探测控制

规则可通过元信息控制系统内置预探测：

```http
# @preflight_mode: skip
# @preflight_prune: false
```

含义：

- `preflight_mode: skip`
  - 跳过系统内置预探测
- `preflight_prune: false`
  - 即使预探测发现异常，也不自动删除该 URL

如果不写，程序按默认内置逻辑执行。

## 可用占位符

规则模板中可使用的占位符包括：

- `{{TARGET_URL}}`
- `{{TARGET_HOST}}`
- `{{TARGET_HOST_HEADER}}`
- `{{TARGET_DOMAIN}}`
- `{{TARGET_IP}}`
- `{{TARGET_PORT}}`
- `{{TARGET_TITLE}}`
- `{{TARGET_WAF}}`
- `{{TARGET_ORIGIN}}`
- `{{PLUGIN_NAME}}`
- `{{TIMESTAMP}}`
- `{{RAND}}`

以及 `config.json` 中 `variables` 定义的自定义变量，例如：

- `{{USER_AGENT}}`
- `{{PAYLOAD}}`

建议：

- `Host` 头优先使用 `{{TARGET_HOST_HEADER}}`
- `User-Agent` 建议显式写成 `{{USER_AGENT}}`

## 数据文件

运行过程中常见数据文件：

- [data/wafkiller.db.json](data/wafkiller.db.json)：主数据文件
- [data/wafkiller.db.json.startup.json](data/wafkiller.db.json.startup.json)：启动快照
- [data/rule_validation_diagnostics.log](data/rule_validation_diagnostics.log)：关键诊断日志

说明：

- 初始化不会删除内置模板规则
- 手工标记的聚类规则会持久化保存
- 导入导出会包含程序运行数据、规则库和相关配置

## 导入与导出

程序支持将当前运行数据导出为单文件包，并支持再次导入恢复。

导出内容通常包含：

- `config.json`
- `waf.yaml`
- 本地数据库
- 启动快照
- 规则目录
- 关键诊断日志

这部分逻辑位于：

- [internal/exporter/workspace_bundle.go](internal/exporter/workspace_bundle.go)

## 智能体说明

当前支持：

- OpenAI Responses API
- 智谱 API

特点：

- 两个供应商可切换
- 可分别配置独立代理
- 配置入口已与 FOFA 分开
- 对话窗口支持自动换行

如果要发布给他人使用，建议：

- 使用 [config.release.json](config.release.json)
- 不要直接分发你本机的 `config.json`

## 开发建议

日常开发建议优先使用：

```bash
make build
```

如果需要重新整理依赖：

```bash
make tidy
make vendor
```

如果遇到国内网络拉取依赖慢，可设置：

```bash
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
```

## 说明

本项目适合在授权环境中用于规则验证、识别分析、产品测试和内部研究。发布或共享版本时，建议始终使用脱敏配置，并对本地数据与密钥做单独管理。
