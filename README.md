# endpoint-discovery：网页端点发现与内容枚举引擎

输入一个目标地址与一组候选路径，引擎并发探测并输出可复现的发现结果。
本地回环服务即可模拟目标，不依赖外部网络。

## 构建与运行

```bash
go build -o ed .
./ed -config config.json
```

命令行参数：

| 参数 | 说明 |
| --- | --- |
| `-config` | JSON 配置文件路径 |
| `-target` | 目标 URL（覆盖配置中的 targets，可多次指定） |
| `-wordlist` | 候选词表文件路径（每行一个路径，`#` 开头为注释） |
| `-checkpoint` | 断点续扫文件路径 |
| `-output` | 结果 JSON 文件路径 |
| `-rate` | 全局请求速率（请求/秒，0 表示不限速） |
| `-concurrency` | 单目标并发度 |
| `-retries` | 限流/连接失败的最大重试次数 |

未提供配置文件时使用内置默认值；命令行参数优先级高于配置文件。

## 配置文件

```json
{
  "targets": ["http://127.0.0.1:8080"],
  "wordlist": "words.txt",
  "scope": {
    "allowed_hosts": ["example.com", "*.example.com"],
    "allowed_ports": [80, 443],
    "allowed_schemes": ["http", "https"],
    "path_prefixes": ["/app"]
  },
  "excludes": {
    "hosts": ["admin.example.com"],
    "path_prefixes": ["/logout"]
  },
  "rate_limit": 20,
  "per_target_concurrency": 4,
  "max_retries": 3,
  "retry_backoff_ms": 200,
  "request_timeout_ms": 15000,
  "max_redirects": 10,
  "checkpoint": "checkpoint.json",
  "output": "results.json",
  "headers": { "X-Custom": "value" },
  "auth": { "type": "basic", "username": "user", "password": "pass" }
}
```

### 范围规则（scope）

所有 URL 在判定前都会被规范化：

- 协议名小写，仅允许 `http` / `https`；
- 主机名小写、去除末尾点号、剥离默认端口（80/443）；
- 路径解析 `.` / `..` 段，空路径补 `/`；
- 查询串与片段（fragment）不参与判定与去重。

判定规则：

- `allowed_hosts`：允许探测的主机，支持精确主机（`example.com`）与
  通配主机（`*.example.com`，匹配子域及根域）。留空时默认仅允许目标主机。
- `allowed_ports`：允许的端口。留空时默认仅允许目标端口。
- `allowed_schemes`：允许的协议。留空时默认仅允许目标协议。
- `path_prefixes`：允许的路径前缀，按规范化后的小写路径匹配。留空表示不限制。
- `excludes.hosts` / `excludes.path_prefixes`：排除规则，优先级高于允许规则。

**超出范围或未授权的主机在发出任何请求之前即被拒绝**，结果中以
`rejected` 分级记录，且不会产生任何网络请求。重定向链的每一跳都会经过
范围检查；跳转到范围外时判定为 `redirect_out_of_scope`，且不对跳转目标
发请求。

### 去重标识

每个待探测路径按规范化标识去重，以下差异不会产生重复请求：

- 大小写（`/Admin` 与 `/admin`）；
- 结尾斜杠（`/admin` 与 `/admin/`）；
- 查询串与片段（`/admin?x=1` 与 `/admin#frag`）。

实际请求使用首次出现的规范形式。

## 判定语义（grade）

| 分级 | 含义 |
| --- | --- |
| `available` | 2xx 响应，且与软 404 基线不等价 |
| `soft404` | 与软 404 基线等价的响应（内容不存在但返回 200 等） |
| `not_found` | 404 响应，且与基线不等价 |
| `redirect` | 重定向链，最终响应为 2xx（链中记录每一跳） |
| `redirect_out_of_scope` | 重定向跳转到了范围外的主机 |
| `auth_required` | 401/403 响应（凭据缺失或失效） |
| `error` | 传输失败或 5xx，且重试耗尽 |
| `rejected` | 范围拒绝，未发出请求 |

### 软 404 检测

扫描开始前，引擎会向目标主机请求一个随机的不存在路径，建立软 404 指纹
（状态码 + 响应体哈希 + 长度 + 头尾各 256 字节片段）。后续响应与基线指纹
匹配时归并为 `soft404`。基线本身请求失败时不启用软 404 判定。

### 重定向链

3xx 响应由引擎手动跟随（不使用 HTTP 客户端的自动跟随），每一跳都记录
URL 与状态码并做范围检查。链中所有跳转 URL 都会作为新路径入队探测，
因此重定向目标不会被遗漏。

### 凭据与自定义请求头

- `headers` 中的键值会附加到每个请求；
- `auth.type` 支持 `basic`（用户名/密码）与 `bearer`（token）；
- 敏感值**不会**出现在日志或结果中；
- 401/403 响应被判定为 `auth_required`，不会被误判为目标不可用。

## 限速与重试参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `rate_limit` | 20 | 全局令牌桶速率（请求/秒），所有目标共享 |
| `per_target_concurrency` | 4 | 单目标在飞请求上限 |
| `max_retries` | 3 | 429/503 与连接失败的最大重试次数 |
| `retry_backoff_ms` | 200 | 退避基数，实际退避为 `base * 2^(attempt-1)` 加抖动 |
| `request_timeout_ms` | 15000 | 单次请求超时 |
| `max_redirects` | 10 | 最大重定向跳数 |

重试仅针对 429/503 与传输错误，遵循指数退避并尊重 `Retry-After` 头
（上限 60 秒）。**重试不会放大流量**：总尝试次数有上界
`任务数 * (1 + max_retries)`，且每次重试都消耗全局令牌。

## 断点续扫

检查点文件（默认 `checkpoint.json`）在每个任务完成后原子写入：

- 已确认完成的路径标记为 `done`，恢复后不再重复请求；
- 未确认完成的路径（重试耗尽的错误）**不会**标记为完成，保留为 `pending`，
  下次运行时自动重试；
- 中断（SIGINT/SIGTERM）后重启，从已提交进度继续，不重复、不遗漏。

## 输出稳定性

- 结果按规范化标识排序，写入 `output` 指定的 JSON 文件；
- 同一目标与输入在不同并发度、不同完成顺序下，发现集合、分级与排序完全一致；
- JSON 字段顺序固定，可直接字节级对比。

## 测试

```bash
go test ./... -race
```

集成测试使用本地回环服务器模拟：正常响应、限流（429 + Retry-After）、
软 404、乱序响应（随机延迟）、重定向链、范围拒绝、去重、鉴权与断点续扫。
