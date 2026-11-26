# Linux 崩溃栈还原服务

值班员提交崩溃栈各帧的 **ELF Build ID** 与**扣除装载偏移后的地址**，服务凭报告号返回
函数名与源码行；CI 可整批补传带 Build ID 与 DWARF 调试信息的 x86-64 ELF。

## 设计要点

| 需求 | 实现 |
| --- | --- |
| Build ID 从文件读取 | pyelftools 解析 `SHT_NOTE` 中的 `NT_GNU_BUILD_ID`，不信任文件名 |
| 整批退回 | 先做纯内存校验（非 ELF / 非 x86-64 / 缺 Build ID / 缺 `.debug_info`），再核对同批与已发布内容；任一不合格返回 422，无任何落盘或数据库变更 |
| 同号内容冲突 | Build ID → sha256 唯一映射，哈希不同即退回，已发布内容不可变 |
| 相同文件重传成功 | 幂等：计入 `redundant`，版本号不前进；同批内重复文件按去重处理 |
| 查询期间可发布 | 全局符号版本号每次有效发布 +1；查询在开始时取一次版本快照，只解析 `version <= 快照版本` 的 ELF |
| 未解析帧保留原地址 | 帧原样持久化，响应中带 `status=unresolved` 与原因；补传后用同一报告号再查即可 |
| 解析积压时只登记 | `POST /reports?register_only=true` 只写入报告与全部原始帧即返回 201 与报告号，不做同步或后台解析，也不占解析名额 |
| 登记失败不留半份 | 报告头与全部帧在同一 SQLite 事务内写入，任一失败整体回滚并返回 503 |
| 解析并发可配置 | `SYMBOL_RESOLVE_LIMIT`（默认 4）限制解析名额，默认上报的同步解析与按号查栈共用；只登记不经过名额 |
| 重启后可查 | 报告/帧、Build ID 映射、版本号全部存 SQLite（WAL）；ELF 按 sha256 内容寻址落盘；启动时核对并清理悬挂映射 |
| 查栈与发布并行 | 发布仅持短写锁，查询走只读快照；ELF 解析结果按 Build ID 惰性缓存且不可变，可跨线程共享 |
| Docker Compose | 单服务 + 命名卷 `symbol-data:/data`，`/docs` 提供 Swagger 演示 |

### 目录结构

```
app/
  config.py        运行期配置（SYMBOL_DATA_DIR）
  elftools_ext.py  ELF 校验 + DWARF 符号化（函数/源码行，兼容 DWARF v4/v5、PIC）
  storage.py       SQLite 持久化、原子批量发布、版本快照、重启恢复
  main.py          FastAPI 路由与模型
scripts/
  build_fixtures.sh  构造固定 Build ID 的测试 ELF
  ci_upload.py       CI 批量上传客户端
tests/             pytest 自测（含真实 uvicorn 并发交错测试）
```

## 启动

```bash
docker compose up --build
# 文档与演示： http://localhost:8000/docs
# 健康检查：    http://localhost:8000/health
# 解析并发上限（默认 4，默认上报与查栈共用）：
SYMBOL_RESOLVE_LIMIT=4 docker compose up --build
```

本地无 Docker 时：

```bash
pip install -r requirements.txt
SYMBOL_DATA_DIR=./data SYMBOL_RESOLVE_LIMIT=4 uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/reports` | 提交崩溃帧（`build_id` 可空、`address` 支持 0x 十六进制或十进制），返回报告号与同步解析结果 |
| POST | `/reports?register_only=true` | 只登记：写入报告与全部原始帧后立即返回 201 与报告号，不做任何解析 |
| GET  | `/reports/{id}` | 凭报告号查询；每次查询绑定开始时的符号版本快照，与默认上报共用解析并发上限 |
| GET  | `/reports/{id}/raw` | 查看原始帧（地址原样保留） |
| POST | `/symbols/batch` | multipart 整批上传 ELF；整批不合格返回 422 及逐文件原因 |
| GET  | `/symbols` | 当前符号版本与已发布 Build ID 列表 |
| GET  | `/health` | 健康检查（含解析名额 `resolve_limit`/`resolve_active`/`resolve_waiting`） |

未解析原因：`frame_missing_build_id` / `build_id_not_published_at_snapshot` /
`address_not_found_in_elf` / `invalid_address`。

### 解析积压时只登记

符号解析忙不过来（多帧、冷缓存、大 ELF）时，崩溃采集端可以先只登记拿回执，
把解析留给之后的值班查询：

```bash
curl -X POST 'localhost:8000/reports?register_only=true' \
  -H 'Content-Type: application/json' \
  -d '{"frames":[{"build_id":"aaaa…aaaa","address":"0x401140"}]}'
# 201 {"report_id":1,"created_at":"…","frame_count":1}

curl localhost:8000/reports/1   # 值班员凭原入口按号查栈；重启后同样可查
```

- 回执只包含报告号、登记时间与帧数，不含解析结果；
- 全部原始帧与报告头在同一事务里落库，写入失败返回 503 且不留半份报告；
- 只登记不占用 `SYMBOL_RESOLVE_LIMIT` 名额：即使解析满额、查栈在排队，也能立即提交并回执。

### 示例

```bash
# 1) 值班员提交
curl -X POST localhost:8000/reports -H 'Content-Type: application/json' \
  -d '{"frames":[{"build_id":"aaaa…aaaa","address":"0x401140"}]}'

# 2) CI 整批补传
python scripts/ci_upload.py http://localhost:8000 ./build-artifacts/

# 3) 用原报告号再查
curl localhost:8000/reports/1
```

## 自测

```bash
bash scripts/build_fixtures.sh tests/fixtures/built   # 构造测试 ELF（需要 gcc）
pip install -r requirements-dev.txt
pytest -q
```

固件包含：固定 Build ID 的可执行文件与共享库、DWARF v4/v5 各一份、同 Build ID 冲突文件、
无 Build ID 文件、strip 调试信息文件、非 ELF 文件。

## 余项 / 已知边界

- 本机未安装 Docker，Compose 文件仅做 YAML 静态校验；容器路径已在同等 uvicorn 进程下端到端验证。
- 只登记上报不触发任何后台解析：报告要等值班员按号查询、或再次提交时才会解析。
- 解析并发上限是进程内名额（单实例有效）；多实例部署时每个实例各自计数。
- 仅接受 `EM_X86_64`；其它架构在入库校验阶段明确退回。
- 符号化依赖 DWARF（`.debug_info`/`.debug_line`）；无调试信息的 ELF 不允许入库。
- 未做上传鉴权与文件大小配额，按内网服务假设；如需暴露公网应在网关层补齐。
- 当前为单实例 + 本地卷部署；多实例横向扩展需把数据层换成共享存储/数据库。
