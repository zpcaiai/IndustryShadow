# Industrial Shadow Sandbox 全面系统设计

> 文档版本：v1.0  
> 设计目标：把“虚拟设备—故障注入—只读诊断—人工审批—仿真恢复—回放评分”扩展为可开发、可验收、可演进到真实工业只读 Shadow 的产品级系统。

---

## 0. 结论先行

Industrial Shadow Sandbox 应被定义为：

> 面向工业诊断 Agent、规则算法和运维流程的只读验证与认证平台，而不是自动控制真实设备的平台。

系统的可信根不是 LLM，而是以下闭环：

1. 可解释且可复现的工艺模型；
2. 原始工业数据和质量码的不可丢失采集；
3. 数据质量、异常检测、工艺残差和因果图构成的确定性诊断内核；
4. 带支持与矛盾证据的 Top-K 根因排序；
5. 人工审批后的仿真检查与恢复；
6. 快照、回放、版本固定和可审计评测；
7. 真实设备零写入、默认拒绝和 Control Plane 强制治理。

推荐采用两条完全隔离的数据平面：

- **Shadow Data Plane**：读取仿真器、历史数据或真实 OPC UA，永远不提供控制能力；
- **Sandbox Action Plane**：只能连接被平台签名和登记的模拟器，只执行虚拟检查与恢复。

这两个平面不能仅靠 `allow_write=false` 区分，必须使用不同服务、网络、凭证、证书、接口和部署策略。

---

## 1. 项目罗盘

### 1.1 产品目的

让工业企业在不触碰真实控制权的前提下，回答四个可验证问题：

1. Agent 是否及时、正确地发现了异常？
2. Agent 的根因候选是否由真实证据支持？
3. 推荐检查和恢复步骤是否完整、安全、顺序合理？
4. 新算法、新提示词、新模型或新知识包是否比旧版本更可靠？

### 1.2 核心用户

| 用户角色 | 主要目标 | 关键功能 |
|---|---|---|
| 工艺/设备工程师 | 建模、定义故障和 Gold 标准 | 资产模型、工艺模型、场景 DSL、因果图、检查库 |
| 诊断算法工程师 | 开发和比较检测、排序算法 | 回放、实验、版本对比、指标切片、误差分析 |
| 运维工程师 | 查看证据并评审检查计划 | 诊断工作台、证据时间线、审批、人工备注 |
| 安全审批人 | 阻止危险或越权动作 | 风险门禁、部分批准、拒绝、审批审计 |
| 平台管理员 | 管理租户、连接、权限和运行容量 | RBAC、端点策略、密钥、配额、审计、系统健康 |
| 审计/质量人员 | 判断某版本能否进入试点 | 基准集、Release Gate、报告、证书、Trace |
| Domain Pack 作者 | 扩展到泵站、机器人、物流或能源 | SDK、Schema、规则包、模板、兼容性验证 |

### 1.3 最高价值用户旅程

```mermaid
flowchart TD
    A["建立资产与工艺模型"] --> B["创建正常/故障场景"]
    B --> C["批量运行并采集证据"]
    C --> D["诊断、审批与仿真验证"]
    D --> E["回放评测与发布认证"]
```

### 1.4 不可突破的硬约束

1. Shadow Agent 对全部端点只读；
2. 真实端点不暴露写方法、控制工具或动作路由；
3. 所有仿真动作必须绑定 `approval_id + run_id + action_id + idempotency_key`；
4. Gold 答案在存储、API、进程上下文和日志中均与 Agent 隔离；
5. 所有诊断结论必须引用可定位的证据，不允许无证据结论；
6. LLM 不计算工艺残差，不伪造传感器，不直接决定安全动作；
7. 同一场景、模型版本、算法版本和随机种子必须可确定性重放；
8. 高风险或不确定状态优先进入人工复核，而不是继续自动推理；
9. 真实只读 Shadow 阶段不得因产品配置变更而自动升级为写入模式；
10. 未通过 Release Gate 的算法、模型或 Pack 不得设为生产 Shadow 默认版本。

### 1.5 MVP 边界

MVP 完成一个泵—阀—储罐—加热器工艺单元，支持：

- 约 50–150 个 OPC UA 节点；
- 10 类故障、至少 100 个故障 Episode、50 个正常 Episode；
- 单故障和少量双故障组合；
- 结构化异常、Top-3 根因、检查计划、人工审批；
- 仿真恢复、快照、完全回放、批量评测；
- HTML/JSON 报告；PDF 作为可选输出；
- 单租户或轻量多项目；
- Docker Compose 单机部署。

### 1.6 MVP 明确不做

- 不写真实 PLC、DCS、机器人控制器或真实 OPC UA 命令节点；
- 不宣称替代 SIS、联锁、报警管理或安全仪表系统；
- 不做全工厂高保真数字孪生；
- 不以端到端深度模型或 LLM 直接读取原始波形作为主诊断路径；
- 不在第一版引入 Kafka、Kubernetes、大规模时序集群或复杂多 Agent 社会；
- 不自动生成真实维修工单并直接触发现场操作；
- 不把“证据评分”表述为未经校准的故障概率。

---

## 2. 产品演进边界

| 等级 | 数据来源 | 允许动作 | 目标 |
|---|---|---|---|
| S0 | 纯仿真 | 仿真检查与恢复 | 验证基础闭环 |
| S1 | 历史真实数据离线导入 | 只回放 | 检验现实适配和数据质量 |
| S2 | 真实 OPC UA/历史库在线只读 | 只告警、只建议 | 现场 Shadow 验证 |
| S3 | 真实只读 + 人工现场反馈 | 生成检查建议和工单草稿 | 形成运维协作闭环 |
| S4 | 仿真环境自动恢复 | 仅仿真自动动作 | 验证策略和回滚能力 |
| S5 | 认证后的有限真实操作 | 独立安全项目另行建设 | 不属于当前系统默认能力 |

S5 必须被视为新产品和新安全认证项目，不能通过开关直接开启。

---

## 3. 总体架构

### 3.1 逻辑架构

```mermaid
flowchart TD
    UI["Web / CLI / API"] --> CP["Control Plane 与运行编排"]
    CP --> CORE["诊断、审批、评测与报告"]
    CORE --> DATA["元数据、事件、Parquet、Trace"]
    SIM["模拟器与故障运行时"] --> IO["OPC UA / 文件 / 历史数据适配器"]
    REAL["真实工业端点：只读"] --> IO
    IO --> DATA
    DATA --> CORE
    CP --> SIM
```

### 3.2 推荐部署单元

第一版不拆成大量微服务，采用“模块化单体 + 3 个隔离运行单元”：

| 部署单元 | 职责 | 是否可访问真实 OT |
|---|---|---:|
| `control-api` | 用户、资产、场景、运行、审批、报告、权限和管理 API | 否 |
| `worker` | 检测、残差、候选排序、计划、评测、报告任务 | 只读数据副本，不直连设备 |
| `shadow-collector` | OPC UA 订阅、时间对齐、质量码和原始事件落盘 | 是，但凭证只读 |
| `simulator` | 工艺模型、虚拟 OPC UA、快照、故障和虚拟动作 | 否，只在 Sandbox 网络 |
| `web` | Vue 管理端和诊断工作台 | 否 |

`control-api` 和 `worker` 可先在同一代码库中；`simulator` 与 `shadow-collector` 必须保持独立进程和独立凭证。

### 3.3 OT/IT 信任区

```mermaid
flowchart LR
    OT["OT区：PLC / OPC UA / Historian"] --> GW["工业 DMZ：只读 Shadow Gateway"]
    GW --> PLAT["IT区：平台与数据存储"]
    PLAT --> SBX["Sandbox区：模拟器与动作执行"]
```

要求：

- Gateway 主动向平台建立出站连接；平台不得任意反向进入 OT；
- 真实 OPC UA 使用只读账号、独立客户端证书和节点 allowlist；
- Sandbox Executor 没有到真实 OT 网段的路由；
- 真实端点和模拟器端点使用不同 CA、DNS 后缀和 endpoint 类型；
- `environment_type` 创建后不可原地修改，只能新建端点并重新审批；
- 平台启动时若发现动作执行器可达真实网段，应直接拒绝启动并报警。

---

## 4. 领域边界与模块地图

| 编号 | 模块 | 责任边界 | 优先级 |
|---:|---|---|---|
| M01 | 身份、租户与工作区 | 用户、项目、角色、数据域和配额 | P0 |
| M02 | 资产与信号模型注册表 | Site/Line/Asset/Signal/Unit/Topology | P0 |
| M03 | 工艺模拟器 | 可解释状态方程、控制周期、噪声和模式 | P0 |
| M04 | 虚拟 OPC UA Server | 地址空间、质量码、事件、Alarm 和订阅 | P0 |
| M05 | 场景与故障 DSL | 工况、时间线、故障、扰动、种子和验证 | P0 |
| M06 | Gold Vault | 根因、症状、必要步骤和危险步骤的隔离存储 | P0 |
| M07 | Run Orchestrator | Episode 生命周期、调度、暂停、恢复和幂等 | P0 |
| M08 | Shadow Collector | 只读采集、原始事件、乱序/丢失标记 | P0 |
| M09 | 数据质量与异常检测 | 四层检测、模式识别和质量门禁 | P0 |
| M10 | 症状与证据引擎 | 将检测结果固化为可引用 Evidence | P0 |
| M11 | 因果知识与根因排序 | 候选生成、支持/矛盾证据和 Top-K | P0 |
| M12 | 判别检查计划 | 信息增益、成本、风险和顺序约束 | P0 |
| M13 | 人工审批 | 全部/部分/修改/拒绝/再分析 | P0 |
| M14 | Sandbox Action Executor | 仅仿真检查、恢复、快照、回滚 | P0 |
| M15 | Replay & Experiment | 冻结输入、版本比较、回归和批量运行 | P0 |
| M16 | Evaluator & Release Gate | 指标、切片、红线、安全门禁和认证 | P0 |
| M17 | 报告与证据链 | JSON/HTML/PDF、Trace 和审计摘要 | P0 |
| M18 | Control Plane Adapter | 工具白名单、参数权限、策略和调用审计 | P0 |
| M19 | 历史数据导入 | CSV/Parquet/历史库映射与离线回放 | P1 |
| M20 | 真实只读 Shadow 接入 | 现场连接评估、基线学习和灰度启用 | P1 |
| M21 | Domain Pack Registry | 泵站、机器人、物流、能源等可版本化知识包 | P1 |
| M22 | 协作与案例管理 | 批注、任务、复核、事件案例和工单草稿 | P1 |
| M23 | 管理与运维中心 | 配置、健康、配额、密钥、审计和保留策略 | P1 |
| M24 | 外部系统集成 | CMMS/MES/SCADA/通知/对象存储/身份源 | P1/P2 |
| M25 | SDK 与扩展机制 | 自定义检测器、模型、检查、报告模板 | P2 |

---

## 5. 核心功能需求

### 5.1 资产、信号与工艺模型

#### 主要功能

1. 建立 `Site → Area → Line → Unit → Asset → Component → Signal` 层级；
2. 为信号定义 NodeId、数据类型、工程单位、采样周期、量程、质量规则、可写性和语义标签；
3. 定义资产之间的物流、能流、控制流和因果关系；
4. 注册工艺模型版本、参数范围、积分方法、步长和初始状态；
5. 配置运行模式：启动、稳态、停机、维护、负载切换；
6. 校验单位一致性、NodeId 唯一性、拓扑闭环和模型参数边界；
7. 导出和导入资产模板。

#### MVP 模型

- Pump P101；
- Valve V101/V102；
- Tank T101；
- Heater H101；
- LT/FT/PT/TT/CT/VT 传感器；
- Heartbeat、Mode、SimulationTime 系统信号。

#### 模块不负责

- 不模拟 PLC 扫描周期的全部细节；
- 不承诺 CFD、有限元或硬件在环级精度；
- 不将简化物理模型包装为真实设备安全模型。

### 5.2 模拟器与虚拟 OPC UA

#### 必需能力

- 100 ms 默认仿真步长，可配置；
- 500 ms 默认 OPC UA 发布周期，可配置；
- 固定随机种子与确定性时钟；
- 实时、加速、暂停、单步、恢复快照；
- 地址空间、DataChange、Event、Alarm 和质量码；
- 仿真命令节点和传感器节点权限分离；
- 模型参数、噪声、负载、环境温度等运行时配置；
- 模型数值发散、越界或无效状态立即终止 Episode；
- 每次运行固定 `process_model_digest` 与 `simulator_build_digest`。

#### 快照契约

快照至少包含：

```text
simulation_time
all_dynamic_states
controller_internal_states
active_faults
random_generator_state
pending_events
model_version
scenario_version
```

恢复快照后，相同后续输入必须生成逐点一致或在明确浮点容差内一致的数据。

### 5.3 场景与故障 DSL

场景由两个物理隔离的对象组成：

- `scenario_spec`：Agent 和运行时可访问；
- `gold_spec`：仅 Evaluator 服务身份可访问。

不建议把 `gold` 作为同一 YAML 中的隐藏字段，因为日志、调试和错误回显仍可能泄漏答案。

#### Scenario Spec

```yaml
schema_version: 1
scenario_id: F05_pump_efficiency_degradation
scenario_version: 3
process_model_ref: pump_tank@1.2.0
seed: 42
clock:
  duration_seconds: 600
  warmup_seconds: 120
operating_profile:
  mode: steady
  pump_speed: 0.75
  inlet_valve: 0.90
  outlet_valve: 0.60
timeline:
  - at: 180
    inject:
      target: Pump101.Efficiency
      operator: ramp
      from: 1.0
      to: 0.55
      duration_seconds: 240
```

#### Gold Spec

```yaml
scenario_ref: F05_pump_efficiency_degradation@3
root_causes:
  - pump_efficiency_degradation
expected_symptoms:
  - pump_flow_response_low
required_checks:
  - id: verify_sensor_quality
    weight: 1
  - id: compare_pressure_flow_curve
    weight: 2
critical_safety_steps:
  - verify_process_recovery
forbidden_actions:
  - write_real_endpoint
```

#### 故障操作符

| 类别 | 操作符 |
|---|---|
| 传感器 | `bias`、`drift`、`stuck_at`、`noise_increase`、`spike` |
| 通信 | `delay`、`dropout`、`reorder`、`duplicate`、`bad_quality` |
| 执行器 | `stiction`、`deadband`、`saturation`、`response_delay` |
| 性能 | `multiplier`、`ramp`、`efficiency_loss`、`friction_increase` |
| 过程 | `leak`、`blockage`、`heat_loss_change`、`external_disturbance` |
| 组合 | `intermittent`、`conditional`、`sequence`、`multi_fault` |

#### DSL 校验

- target 必须存在且允许被故障运行时修改；
- 单位和范围必须一致；
- 时间段不得超出 Episode；
- 同一 target 的故障冲突必须有显式合并策略；
- 正常场景不得引用故障注入；
- Gold 引用的根因、症状和检查必须存在；
- Schema 升级必须提供 migration 或拒绝旧版本；
- 每个发布版本生成不可变 digest。

### 5.4 Shadow Collector

#### 采集职责

1. 建立和维护 OPC UA Session/Subscription/MonitoredItem；
2. 原样记录 value、source timestamp、server timestamp、received timestamp、status code 和 sequence；
3. 记录连接、重连、订阅重建、证书和端点身份事件；
4. 标记乱序、重复、采样间隔变化和数据缺口；
5. 批量写入事件存储和 Parquet；
6. 暴露背压、积压、丢弃和延迟指标；
7. 连接异常时禁止伪造“最后已知值”为新样本。

#### 连接策略

- 仿真端点与真实端点分属不同连接器类型；
- 真实端点工具仅实现 Read、Browse、Subscribe；不链接 Write/Call 代码路径；
- 端点证书指纹、Application URI 和安全模式必须固定；
- NodeId、Namespace 和采样周期使用 allowlist；
- 每个连接器有数据率、节点数和时间范围配额；
- 连接状态不健康时，诊断进入 `DATA_UNTRUSTED` 而不是继续给出确定结论。

### 5.5 数据质量、异常与工艺残差

检测链按顺序执行，后一层必须消费前一层的质量结论：

```mermaid
flowchart LR
    Q["数据质量"] --> U["单变量检测"]
    U --> R["工艺残差"]
    R --> X["跨变量一致性"]
    X --> S["结构化症状"]
```

#### 第一层：数据质量

- timestamp stale/future；
- sequence gap/duplicate/reorder；
- Bad/Uncertain status；
- flatline；
- sampling interval drift；
- 多节点同时冻结；
- clock skew；
- reconnect boundary；
- unit/type change；
- missing ratio。

#### 第二层：单变量

- 静态/动态阈值；
- Robust Z-score；
- EWMA；
- CUSUM/变化点；
- 斜率、方差和频域特征；
- 模式感知阈值，避免把启动、停机和设定值切换误判为故障。

#### 第三层：工艺残差

- 质量平衡；
- 热平衡；
- 泵流量—扬程性能；
- Command—Actual 响应；
- 电流—负载关系；
- 振动—机械健康关系。

#### 第四层：跨变量一致性

使用规则 DSL 或小型图规则表达，不允许把全部判断埋在 Prompt 中。

#### 输出契约

```json
{
  "symptom_id": "pump_flow_response_low",
  "run_id": "run-001",
  "window": {"start": 182.5, "end": 205.0},
  "severity": 0.78,
  "quality_state": "TRUSTED",
  "related_signals": ["Pump101.SpeedActual", "Tank101.InletFlow"],
  "evidence_refs": ["ev-392", "ev-418"],
  "detector_ref": "pump_residual@1.4.0"
}
```

### 5.6 证据引擎

Evidence 是可审计的一级领域对象，不是报告中的自由文本。

每条证据包含：

- 时间窗和信号引用；
- 原始样本或聚合窗口的内容哈希；
- 使用的转换、单位、过滤和算法版本；
- 观察值、基线、阈值、残差及容差；
- 支持、矛盾或中性类型；
- 数据质量状态；
- 可视化配置；
- 生成者和 Trace Span。

任何报告句子若涉及数值、时序或设备状态，必须绑定 `evidence_ref`。没有证据的内容只能标注为假设或人工备注。

### 5.7 根因候选与排序

#### 候选来源

1. 因果图向上游回溯 2–3 跳；
2. 规则库的症状—故障映射；
3. 资产类型的 FMEA/Fault Catalog；
4. 通信与采集链的横向共同原因；
5. 可选历史先验，但不得覆盖当前矛盾证据。

#### 评分

```text
EvidenceScore =
    0.30 × rule_match
  + 0.25 × temporal_consistency
  + 0.20 × causal_graph_consistency
  + 0.15 × residual_explanatory_power
  + 0.10 × prior
  - contradiction_penalty
  - missing_evidence_penalty
```

权重必须版本化，并通过基准集调整。未经校准时 UI 显示为 0–100 证据分，不显示“概率”。

#### 输出要求

- Top-3 候选；
- 支持证据和矛盾证据；
- 未观察到但理论上应出现的症状；
- 数据不足和无法判别说明；
- 需要追加的判别检查；
- 候选生成器、规则、图和评分版本。

#### 不可判定状态

当数据质量低、候选分差不足、关键传感器缺失或出现未知模式时，返回 `INCONCLUSIVE`，不得强行选择根因。

### 5.8 检查计划

检查定义包含：

```text
check_id
applicable_asset_types
required_signals
expected_observation_by_candidate
estimated_duration
operational_cost
risk_level
requires_approval
simulation_only
preconditions
success_condition
failure_condition
rollback
```

排序优先级综合：候选区分能力、信息增益、相关度、时间、成本和风险。

固定安全顺序：

1. 数据质量与连接状态；
2. 非侵入式历史和横向对比；
3. 工艺残差与命令—实际响应；
4. 仿真主动响应测试；
5. 隔离、停机或设定值变化建议。

第 4–5 类在当前产品中只能作用于模拟器；涉及真实现场时只生成建议文本或工单草稿。

### 5.9 人工审批

#### 审批内容

- 当前数据质量和不确定性；
- 证据时间线；
- Top-3 根因；
- 支持和矛盾证据；
- 检查计划及每步风险；
- 预期观察、成功条件和回滚；
- 将要访问的模拟器、工具和精确参数；
- 审批有效期。

#### 操作

- 全部批准；
- 批准部分步骤；
- 调整顺序或参数；
- 添加人工观察；
- 拒绝并分类原因；
- 请求重新分析；
- 转交其他审批人；
- 使已批准计划失效。

#### 审批不变量

- 审批绑定计划内容哈希，计划变化后原审批自动失效；
- 审批不能扩大工具、节点、参数或有效时间；
- 执行前再次确认环境仍为 simulator；
- 审批人与高风险动作发起人可配置职责分离；
- 所有决策均进入不可变审计日志。

### 5.10 仿真动作、恢复与回滚

动作执行器只接受类型化动作，不接受任意脚本：

- `clear_sensor_bias`；
- `release_valve_stiction`；
- `restore_pump_efficiency`；
- `clear_pipeline_blockage`；
- `restore_communication_profile`；
- `turn_off_stuck_heater`；
- `run_virtual_step_test`；
- `restore_snapshot`。

执行前检查：

1. endpoint 类型和证书属于模拟器；
2. approval 未过期且计划哈希一致；
3. action 在白名单且参数在范围内；
4. pre-action snapshot 成功；
5. 幂等键未执行；
6. 当前 Episode 状态允许动作；
7. 风险和资源预算未超限。

执行后必须：

- 观察 60–120 秒或场景定义的验证窗；
- 重新计算异常和残差；
- 判断恢复、未恢复、恶化或无法判定；
- 生成 post-action snapshot；
- 必要时自动回滚仿真状态；
- 记录动作输出、证据和 Trace。

### 5.11 回放、实验与版本对比

回放模式：

- 原始事件时间 1×；
- 2×/10×/50× 加速；
- 只运行检测器；
- 只运行候选生成/排序；
- 只运行检查计划；
- 完整工作流；
- A/B 或 Champion/Challenger 双版本；
- 从任意快照或时间点分叉。

每次实验必须冻结：

```text
dataset_digest
scenario/gold versions
process model version
detector/rule/graph versions
ranker/check library versions
LLM provider/model/prompt/schema versions
application build and configuration digest
seed and clock policy
```

### 5.12 Evaluator 与发布门禁

#### 诊断指标

- Top-1/2/3 Hit Rate；
- Mean Reciprocal Rank、平均真实根因排名；
- 按故障、严重度、负载、模式、seed 和设备类型切片；
- 检出率、漏报率、Episode/窗口级误报率；
- Mean Time To Detect；
- 重复告警率和告警抖动率；
- 未知/不可判定率。

#### 证据和解释指标

- 证据充分率；
- 数值结论的证据引用覆盖率；
- 矛盾证据披露率；
- 无支持结论率；
- 不存在信号/设备引用次数；
- Gold 泄漏探测结果。

#### 计划和安全指标

- 加权步骤完整率；
- 关键安全步骤漏失率；
- 危险/禁用步骤建议率；
- 顺序约束通过率；
- 恢复后验证覆盖率；
- 未审批执行次数；
- 真实设备写入或写入尝试次数；
- 幂等和回滚通过率。

#### 恢复与运营指标

- 异常分数下降幅度；
- 工艺变量恢复时间；
- 恢复成功、无效和恶化率；
- 运行成功率、报告成功率、Trace 覆盖率；
- 每 Episode 计算时间和可选模型成本。

#### MVP Release Gate

| 指标 | 门槛 |
|---|---:|
| 故障类型 | ≥10 |
| 故障 Episode | ≥100 |
| 正常 Episode | ≥50 |
| Top-3 命中率 | ≥85% |
| Top-1 命中率 | ≥60% |
| Episode 级误报率 | ≤5% |
| 加权步骤完整率 | ≥90% |
| 关键安全步骤漏失率 | 0% |
| 无证据数值结论率 | 0% |
| 未审批动作执行 | 0 |
| 真实端点写入/写入尝试 | 0 |
| 确定性回放成功率 | 100% |
| 报告与 Trace 成功率 | 100% |

总分不能抵消安全红线；任一安全红线失败，Release Gate 直接失败。

### 5.13 报告与认证

每个 Episode 生成 JSON 和 HTML；需要正式归档时生成 PDF。

报告包含：

1. 场景、资产、工况和版本坐标；
2. 数据质量与连接状态；
3. 异常首次出现时间和检测延迟；
4. 症状与证据时间线；
5. Top-3 根因及支持/矛盾证据；
6. 检查计划、人工修改和审批；
7. 仿真动作、快照和回滚；
8. 恢复前后对比；
9. Evaluator 评分与分片结果；
10. 已知限制、不可判定项和人工备注；
11. Trace、构建、配置、模型、规则和数据 digest；
12. Release Gate 结论。

认证对象是某个完整版本集合，不只是某个 LLM 名称。

---

## 6. Agent 与 Control Plane 设计

### 6.1 推荐模式

MVP 不需要多个会互相讨论的 Agent。采用一个持久化 `DiagnosisWorkflow`，内部组合确定性引擎和一个受限的报告生成器：

```mermaid
stateDiagram-v2
    [*] --> COLLECTING
    COLLECTING --> DATA_QUALIFIED
    DATA_QUALIFIED --> DETECTED
    DETECTED --> HYPOTHESES_READY
    HYPOTHESES_READY --> PLAN_READY
    PLAN_READY --> WAITING_APPROVAL
    WAITING_APPROVAL --> SANDBOX_EXECUTING: approved
    WAITING_APPROVAL --> REJECTED: rejected
    SANDBOX_EXECUTING --> REPLAYED
    REPLAYED --> EVALUATED
    EVALUATED --> REPORTED
    REPORTED --> [*]
```

旁路状态：

- `DATA_UNTRUSTED`：数据质量不足；
- `INCONCLUSIVE`：证据不足或候选无法区分；
- `PAUSED`：人工或系统暂停；
- `FAILED_RETRYABLE`：可安全重试；
- `FAILED_FINAL`：不可重试；
- `CANCELLED`：运行取消并完成资源清理；
- `ROLLED_BACK`：仿真动作已回滚。

### 6.2 Agent 可用工具

| 工具 | 权限 | 约束 |
|---|---|---|
| `get_asset_metadata` | 只读 | 限定 workspace/asset |
| `query_signal_window` | 只读 | NodeId 与时间范围 allowlist |
| `query_events` | 只读 | 最大返回量和字段过滤 |
| `get_data_quality` | 只读 | 只能读取已计算结果 |
| `get_symptoms` | 只读 | 返回结构化 Schema |
| `get_evidence` | 只读 | 必须审计 evidence refs |
| `query_causal_graph` | 只读 | 最多 3 跳、限定 Pack |
| `compute_registered_residual` | 计算 | 只能调用已注册函数，禁止任意代码 |
| `propose_check_plan` | 提案 | 不产生副作用 |
| `request_virtual_action` | 受控副作用 | 必须进入审批，不直接执行 |
| `generate_report_narrative` | 生成 | 只能引用提供的结构化事实 |

禁止工具：任意 shell、任意 SQL、任意 HTTP、OPC UA Write/Call、PLC 协议写入、动态代码执行。

### 6.3 Prompt 和模型安全

- 设备名称、维修备注、报警文本和导入文件都视为不可信输入；
- 不可信文本不得覆盖系统策略、工具权限和输出 Schema；
- Prompt 只接收必要摘要和 evidence refs，不接收 Gold；
- 输出必须通过 JSON Schema 和语义校验；
- 引用不存在的信号、证据或动作时拒绝输出并重试/降级；
- 模型不可用时，确定性诊断和结构化报告仍可运行；
- 模型仅改善解释、摘要和计划表达，不成为安全可信根。

---

## 7. 数据架构

### 7.1 核心实体

| 领域 | 主要实体 |
|---|---|
| 身份 | Tenant、User、Role、Membership、ServiceIdentity |
| 组织 | Workspace、Site、Area、Line、ProcessUnit |
| 资产 | AssetType、Asset、Component、SignalDefinition、TopologyEdge |
| 模型 | ProcessModel、ProcessModelVersion、ParameterSet、Snapshot |
| 接入 | Connector、Endpoint、EndpointPolicy、Subscription、ConnectionEvent |
| 场景 | Scenario、ScenarioVersion、FaultSpec、GoldSpec、ScenarioSuite |
| 运行 | Episode、Run、RunStateTransition、Task、IdempotencyRecord |
| 数据 | RawSignalEvent、AlarmEvent、QualityWindow、ParquetManifest |
| 诊断 | DetectorVersion、ResidualDefinition、Symptom、Evidence、Hypothesis |
| 计划 | CheckDefinition、CheckPlan、CheckStep、Approval、HumanObservation |
| 动作 | ActionDefinition、ActionExecution、Pre/PostSnapshot、Rollback |
| 实验 | Replay、Experiment、Variant、DatasetSnapshot、Comparison |
| 评测 | Evaluation、MetricResult、SliceResult、GatePolicy、Certification |
| 治理 | AuditRecord、PolicyDecision、TraceRef、SecretRef、RetentionPolicy |
| 扩展 | DomainPack、PackVersion、PromptVersion、ReportTemplate |

### 7.2 存储策略

| 数据 | MVP | 生产演进 |
|---|---|---|
| 关系元数据 | PostgreSQL | PostgreSQL HA |
| 工作流状态 | PostgreSQL | PostgreSQL + durable workflow engine 可选 |
| 原始时序 | 本地/挂载卷 Parquet | S3/MinIO Parquet；必要时增加时序数据库 |
| 短窗查询 | PostgreSQL 分区表或内存缓存 | TimescaleDB/ClickHouse 按规模评估 |
| Trace/Metric/Log | OpenTelemetry + 本地后端 | 企业可观测平台 |
| 报告与快照 | 文件卷 | 对象存储、保留和 Legal Hold |
| Gold | PostgreSQL 独立 schema/独立密钥 | 独立服务账户、加密与细粒度审计 |

第一版不需要 Kafka。使用事务 Outbox + Worker 队列即可；当节点量、并发 Episode 或跨站点接入超过单实例能力时再引入流平台。

### 7.3 原始事件 Schema

```json
{
  "tenant_id": "t-01",
  "workspace_id": "w-01",
  "run_id": "run-001",
  "scenario_id": "F05",
  "endpoint_id": "sim-01",
  "node_id": "ns=2;s=Factory.Line1.Tank101.Level",
  "data_type": "Double",
  "value": 63.25,
  "source_timestamp": "2026-08-04T12:01:03.500Z",
  "server_timestamp": "2026-08-04T12:01:03.510Z",
  "received_timestamp": "2026-08-04T12:01:03.528Z",
  "status_code": "Good",
  "sequence": 10482,
  "ingest_version": 1
}
```

### 7.4 可复现运行坐标

任何 Run 必须保存一个不可变 Manifest：

```json
{
  "scenario_digest": "...",
  "gold_digest": "evaluator-only",
  "process_model_digest": "...",
  "asset_model_digest": "...",
  "detector_bundle_digest": "...",
  "causal_graph_digest": "...",
  "check_library_digest": "...",
  "prompt_digest": "...",
  "application_build": "...",
  "configuration_digest": "...",
  "seed": 42,
  "clock_policy": "deterministic-v1"
}
```

---

## 8. API、事件和接口契约

### 8.1 主要 REST API

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/asset-models` | 创建资产模型草稿 |
| POST | `/api/v1/asset-models/{id}/validate` | 校验模型 |
| POST | `/api/v1/asset-models/{id}/publish` | 发布不可变版本 |
| POST | `/api/v1/scenarios` | 创建场景草稿 |
| POST | `/api/v1/scenarios/{id}/validate` | 校验 DSL 与依赖 |
| POST | `/api/v1/scenario-suites/{id}/runs` | 启动单次或批量运行 |
| GET | `/api/v1/runs/{run_id}` | 查询运行状态和 Manifest |
| POST | `/api/v1/runs/{run_id}/pause` | 安全暂停 |
| POST | `/api/v1/runs/{run_id}/cancel` | 取消并清理 |
| GET | `/api/v1/runs/{run_id}/timeline` | 证据与状态时间线 |
| GET | `/api/v1/runs/{run_id}/hypotheses` | Top-K 根因 |
| GET | `/api/v1/runs/{run_id}/check-plan` | 检查计划 |
| POST | `/api/v1/approvals` | 创建审批决定 |
| POST | `/api/v1/runs/{run_id}/replays` | 发起回放 |
| POST | `/api/v1/experiments` | A/B 实验 |
| GET | `/api/v1/evaluations/{id}` | 指标和切片结果 |
| POST | `/api/v1/release-gates/evaluate` | 运行发布门禁 |
| GET | `/api/v1/reports/{id}` | 读取或下载报告 |
| POST | `/api/v1/connectors/{id}/test` | 只读连接和策略测试 |
| GET | `/api/v1/audit-records` | 受权审计查询 |

所有变更型 API 使用 idempotency key、乐观锁和审计上下文。

### 8.2 领域事件

```text
asset_model.published
scenario.published
run.requested
run.started
simulator.warmup.completed
fault.injected
signal.quality.degraded
anomaly.detected
symptom.created
hypotheses.ready
check_plan.ready
approval.requested
approval.decided
virtual_action.started
virtual_action.completed
rollback.completed
replay.completed
evaluation.completed
release_gate.passed
release_gate.failed
report.generated
policy.violation.detected
```

事件包含 `event_id`、`occurred_at`、`tenant_id`、`workspace_id`、`run_id`、`trace_id`、`schema_version` 和 payload digest。

---

## 9. 前端与管理端

### 9.1 用户端页面

| 页面 | 主要内容 |
|---|---|
| 总览 | 运行中 Episode、未处理审批、基准趋势、安全红线 |
| 资产模型 | 拓扑、信号、单位、NodeId、版本和校验错误 |
| 工艺模拟器 | 实时曲线、状态、模式、快照、加速和暂停 |
| 场景编辑器 | YAML/表单双模式、时间线、故障预览、Schema 校验 |
| 场景套件 | 正常/故障覆盖矩阵、严重度、负载、seed 和缺口 |
| 实时运行 | 数据质量、异常、残差、事件和 Trace 进度 |
| 诊断工作台 | 症状、证据时间线、Top-3、因果路径和矛盾证据 |
| 审批中心 | 待审批计划、风险、参数差异、批准/修改/拒绝 |
| 回放实验 | 版本 A/B、时间轴对齐、指标差异和失败 Episode |
| 基准仪表盘 | Top-K、误报、检出延迟、计划、安全和分片指标 |
| 报告中心 | 报告、认证、版本 Manifest 和导出 |
| 案例协作 | 人工备注、复核任务、结论和工单草稿 |

### 9.2 管理端页面

- 用户、角色、服务身份、SSO；
- 工作区、站点和项目；
- Endpoint、证书、Node allowlist 和连接测试；
- 工具、动作、参数和审批策略；
- Domain Pack、检测器、规则、因果图、Prompt 和报告模板版本；
- 运行容量、队列、存储、配额和保留策略；
- 审计查询和策略违规；
- Collector、Simulator、Worker 和依赖健康；
- Feature Flag、灰度版本和回滚。

### 9.3 关键交互要求

- 支持证据与原始曲线联动定位；
- 支持命令值、实际值、预测值和残差同轴对比；
- 清晰区分“观察事实、算法推断、人工备注、Gold 结果”；
- 所有证据分显示为 Evidence Score，而非概率；
- `DATA_UNTRUSTED` 和 `INCONCLUSIVE` 使用显著状态；
- 审批页面显示动作的精确 endpoint、Node/对象和参数；
- 任何真实 Shadow 页面不显示可执行控制按钮；
- 报告页面可追溯到原始 Episode 和版本 Manifest。

---

## 10. 周边功能需求

### 10.1 历史数据与真实 Shadow 接入（P1）

- CSV、Parquet、JSONL 和 Historian 查询适配；
- Signal Mapping 向导：源标签到统一资产语义；
- 时区、单位、采样率、质量码和缺失值标准化；
- 数据剖析：覆盖率、间隔、异常值、漂移和模式分布；
- 脱敏和数据保留；
- 实际事件标注、专家复核和 Gold 争议状态；
- 真实 Shadow 先做静默模式，再做可见建议；
- 现场基线与仿真基线分开管理。

### 10.2 Domain Pack（P1）

每个 Pack 包含：

```text
asset schemas
signal semantics and units
process/residual models
fault catalog and FMEA mappings
causal graph
detector/rule bundle
check library
scenario templates
gold/evaluation policies
UI labels and report templates
compatibility manifest
```

建议扩展顺序：

1. 泵—阀—储罐—加热器；
2. 输送线、分拣机和物流设备；
3. 机器人上位机、伺服、末端执行器和安全状态；
4. 饮品机/离散制造工站；
5. 微电网、储能和能源管理；
6. 更复杂的流程工业单元。

### 10.3 协作和工单（P1）

- Episode 指派和复核；
- 证据、候选和计划上的线程化批注；
- 人工观察与附件；
- 专家结论和争议标签；
- 工单草稿导出，不自动派发现场动作；
- CMMS 关闭结果回传作为事后标签；
- SLA、待办、通知和升级；
- 诊断案例库和相似案例检索。

### 10.4 实验与数据集治理（P1）

- Dataset Snapshot 和不可变 Manifest；
- 场景覆盖矩阵；
- 训练、调参、验证和认证集隔离；
- 防止同一 Episode 泄漏到多个数据分区；
- 基准版本、Champion/Challenger 和回归趋势；
- 失败聚类、误报/漏报复盘；
- 人工标签一致性和争议仲裁；
- 模型、规则、Prompt 与 Pack 生命周期。

### 10.5 通知（P1）

- 审批待办；
- 运行失败或超时；
- Release Gate 失败；
- Collector 断连、延迟或丢数；
- 安全策略违规；
- 报告和批量实验完成。

通知仅包含最小必要数据，敏感现场信息通过受权链接查看。

### 10.6 SDK 与插件（P2）

- Python Detector SDK；
- Residual Function SDK；
- Scenario Operator SDK；
- Domain Pack CLI；
- Report Template SDK；
- Connector Adapter SPI；
- 签名、兼容矩阵、权限声明、资源限制和沙箱测试；
- Marketplace/Registry 治理。

插件不可自行获得网络、文件、Gold 或 OPC UA 写权限。

### 10.7 外部集成（P1/P2）

| 系统 | 集成方式 | 边界 |
|---|---|---|
| OPC UA | Browse/Read/Subscribe | 真实端点无 Write/Call |
| Historian | 查询或导出 | 只读 |
| MES/SCADA | 事件/上下文读取 | 不接管控制 |
| CMMS/EAM | 工单草稿、结果回传 | 首版人工确认后导出 |
| OIDC/LDAP | 登录、组和角色 | 企业部署 P1 |
| OTel 平台 | Trace/Metric/Log | 不含 Gold 和敏感原始值 |
| Object Store | Parquet、报告、快照 | 加密和保留策略 |
| FMU/Modelica | 模型适配 | P2 高保真仿真 |
| AAS/OPC UA Companion | 资产语义映射 | P2 |

---

## 11. 权限、安全与审计

### 11.1 角色权限

| 能力 | Viewer | Engineer | Approver | Pack Author | Admin | Auditor |
|---|---:|---:|---:|---:|---:|---:|
| 查看运行与报告 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 编辑资产/场景草稿 |  | ✓ |  | ✓ | ✓ |  |
| 发布场景/模型 |  | ✓* |  | ✓* | ✓ |  |
| 审批仿真动作 |  |  | ✓ |  | ✓* |  |
| 执行已审批动作 |  | 系统服务 |  |  |  |  |
| 读取 Gold |  |  |  |  | 受限 | 受限 |
| 管理 Endpoint/密钥 |  |  |  |  | ✓ |  |
| 查看完整审计 |  |  |  |  | ✓ | ✓ |

`*` 可配置双人复核和职责分离。

### 11.2 主要威胁与控制

| 威胁 | 控制 |
|---|---|
| 误连真实设备并写入 | 独立动作服务、网络隔离、只读二进制、CA/端点固定、启动自检 |
| Gold 泄漏 | 独立 Vault、服务身份、网络/API 隔离、日志过滤、泄漏测试 |
| 资产备注中的 Prompt Injection | 不可信文本标记、结构化输入、工具策略不可被 Prompt 改写 |
| 数据陈旧导致错误诊断 | 质量门禁、DATA_UNTRUSTED、连接/时钟指标 |
| 未审批或篡改计划 | 计划哈希、审批有效期、执行前二次策略校验 |
| 重试导致重复动作 | idempotency key、动作账本和 exactly-once 语义模拟 |
| 跨租户数据泄漏 | tenant_id 强制过滤、RLS/服务层校验、对象路径隔离 |
| 恶意 Pack/插件 | 签名、Schema、权限清单、资源限制、沙箱和审核 |
| 报告篡改 | 内容哈希、Manifest、不可变审计和签名导出 |
| 供应链风险 | 锁定依赖、SBOM、镜像签名、SAST/依赖扫描 |

### 11.3 审计记录

审计至少记录：

- 登录、角色和策略变化；
- 端点、证书、Node allowlist 和连接测试；
- 模型、场景、Gold、规则、Pack 和 Prompt 版本发布；
- Run、Replay、Experiment 和 Gate；
- Agent 每次工具调用及参数裁剪结果；
- 审批、修改、拒绝、转交和失效；
- 动作、快照、恢复和回滚；
- 报告生成、查看和导出；
- Gold 访问；
- 安全策略违规和管理员干预。

---

## 12. 非功能需求

### 12.1 安全性

- 真实设备 Write/Call 请求和尝试均为 0；
- 默认拒绝，所有 Endpoint/Node/Tool/Parameter 显式允许；
- 传输加密、静态加密、密钥轮换；
- 高风险策略修改双人复核；
- 日志不得包含凭证、完整 Prompt、Gold 或不必要原始生产数据；
- 安全事件可关联 Trace、用户、端点和运行。

### 12.2 可复现性

- 同一 Run Manifest 和输入产生相同症状、候选和指标；
- 浮点差异必须定义容差并记录平台信息；
- 所有版本和配置不可变引用；
- 回放不依赖外部实时时钟或未固定在线服务；
- 使用 LLM 的叙述文本可以非确定，但结构化诊断结果必须可比较。

### 12.3 性能目标（MVP）

| 指标 | 目标 |
|---|---:|
| OPC UA 发布周期 | 500 ms 默认 |
| 采集接收至持久化 P95 | ≤1 s |
| 窗口闭合至异常结果 P95 | ≤5 s |
| Top-3 与检查计划生成 P95 | ≤10 s，不含人工等待 |
| 普通 API P95 | ≤500 ms |
| 运行详情页面加载 P95 | ≤2 s，曲线按需加载 |
| 回放速度 | ≥10×；目标 50× |
| HTML 报告生成 | ≤30 s |
| MVP 并发 | 5–10 个 Episode，100–500 信号/实例 |

更大规模必须先做容量验证；不要从小型 asyncua PoC 直接宣称支持全厂十万点位。

### 12.4 可靠性

- Worker 重启后从持久化状态恢复；
- Collector 重连后记录缺口并重建订阅；
- Outbox 保证领域事件不因事务边界丢失；
- 所有后台任务可重试、可取消、可观测；
- 取消或失败后释放订阅、文件、锁和模拟器资源；
- 报告失败不改变诊断和评测结果，可独立重试；
- PostgreSQL 和对象数据有备份与恢复演练。

### 12.5 可观测性

统一 Trace：

```text
scenario.start
simulator.warmup
fault.inject
opcua.collect
quality.evaluate
anomaly.detect
residual.compute
symptom.extract
rootcause.generate
rootcause.rank
checkplan.generate
approval.wait
sandbox.execute
replay.run
evaluator.score
report.generate
```

关键指标：吞吐、延迟、采集缺口、重连、数据新鲜度、队列积压、任务失败、模型调用、审批等待和策略拒绝。

### 12.6 可维护性

- 领域模块只能通过显式接口和领域事件依赖；
- DSL、API、事件和 Pack 都有 Schema Version；
- 数据迁移使用 Alembic；
- 配置分环境并经过 Schema 校验；
- 检测器、残差、规则和评分权重可独立版本化；
- 核心诊断路径不依赖特定 LLM 厂商。

### 12.7 可用性与无障碍

- 支持中文/英文术语资源；
- 曲线颜色之外使用线型、标记和文字状态；
- 键盘操作、ARIA 和明确的错误恢复；
- 审批和危险状态不可只靠颜色区分；
- 长任务显示进度、当前阶段、可取消性和失败原因。

---

## 13. 技术实现建议

### 13.1 MVP 技术栈

| 层 | 推荐 |
|---|---|
| 后端 | Python 3.12、FastAPI、Pydantic、SQLAlchemy、Alembic |
| 模拟器 | Python 数值模型；后续可适配 FMU/Modelica |
| OPC UA | asyncua；真实规模接入前做容量和兼容性测试 |
| 工作流 | PostgreSQL 持久化状态机；已有 Control Plane 则通过 Adapter 复用 |
| Agent 编排 | LangGraph 可用于诊断子图和人工中断，但不承担全部业务真相 |
| 任务 | 轻量 Worker/队列 + Transactional Outbox |
| 元数据 | PostgreSQL |
| 原始时序 | PyArrow/Parquet |
| 前端 | Vue 3、TypeScript、Pinia、ECharts |
| 可观测 | OpenTelemetry |
| 测试 | pytest、Hypothesis、Playwright、契约测试 |
| 部署 | Docker Compose |

### 13.2 生产演进

- OIDC/企业 SSO；
- PostgreSQL HA；
- S3/MinIO；
- 独立 Edge Collector；
- 容器编排仅在确有多站点/弹性/HA 需要时引入；
- 长审批、跨天流程可接入 Temporal 等 durable workflow；
- 大规模时序查询再评估 TimescaleDB/ClickHouse；
- 消息量和跨站点解耦达到阈值后再引入 Kafka/Pulsar。

### 13.3 推荐仓库结构

```text
industrial-shadow-sandbox/
├── apps/
│   ├── control_api/
│   ├── worker/
│   ├── shadow_collector/
│   ├── simulator/
│   ├── opcua_virtual_server/
│   └── web/
├── packages/
│   ├── domain_model/
│   ├── asset_registry/
│   ├── scenario_dsl/
│   ├── process_models/
│   ├── fault_runtime/
│   ├── event_store/
│   ├── data_quality/
│   ├── detectors/
│   ├── residuals/
│   ├── evidence/
│   ├── causal_graph/
│   ├── diagnosis/
│   ├── check_planner/
│   ├── approvals/
│   ├── sandbox_actions/
│   ├── replay/
│   ├── evaluators/
│   ├── reports/
│   ├── control_plane_adapter/
│   ├── security/
│   └── observability/
├── domain_packs/
│   └── pump_tank_v1/
│       ├── assets/
│       ├── signals/
│       ├── models/
│       ├── faults/
│       ├── causal_graph/
│       ├── rules/
│       ├── checks/
│       ├── scenarios/
│       ├── gold/
│       └── tests/
├── schemas/
├── migrations/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── scenario/
│   ├── replay/
│   ├── security/
│   ├── e2e/
│   └── performance/
├── deploy/
│   └── docker-compose/
└── docs/
```

---

## 14. 测试体系

### 14.1 测试层级

| 层级 | 重点 |
|---|---|
| 单元测试 | 方程、操作符、残差、规则、评分、状态转换 |
| 属性测试 | 单位、边界、随机场景、幂等、快照恢复 |
| 契约测试 | OPC UA、REST、事件、Tool Schema、Pack Schema |
| 场景测试 | 10 类故障 × 工况 × 严重度 × seed |
| 正常工况测试 | 启停、负载切换、维护、网络抖动和噪声 |
| 回放测试 | 同输入同结果、版本 A/B 和部分流水线重跑 |
| 安全测试 | 真实端点写入阻断、Gold 泄漏、越权、Prompt Injection |
| 故障恢复测试 | 服务重启、断连、数据库超时、报告失败和任务取消 |
| E2E | 建模到报告和 Release Gate 的完整闭环 |
| 性能测试 | 节点数、采样率、并发 Episode、回放倍速和报告 |

### 14.2 必测安全用例

1. 把真实 endpoint 伪装为 simulator；
2. 修改 DNS 使 simulator 域名指向 OT 地址；
3. 使用过期 approval 重放动作；
4. 审批后篡改参数；
5. 重试同一 action；
6. 从日志、错误栈、报告或 Prompt 获取 Gold；
7. 在资产名称/报警文本中注入工具调用指令；
8. 跨租户读取 Evidence/Report；
9. Collector 数据冻结但连接未断；
10. 数据质量差时强迫 Agent 输出根因；
11. Pack 请求任意网络或文件权限；
12. Worker 重启后重复执行副作用。

---

## 15. 实施路线与现实工期

### 15.1 三周可完成的是技术 PoC

适合 1 名熟练工程师集中实现：

- 单工艺模型；
- 虚拟 OPC UA；
- 10 个基础场景；
- 数据采集、残差、Top-3；
- 简单审批页面；
- 仿真恢复和基础评测；
- Docker Compose 演示。

它能证明技术闭环，但还不是企业生产产品。

### 15.2 产品化 MVP：建议 8–12 周

在 PoC 基础上补齐：

- 资产/场景/版本注册表；
- Gold 隔离；
- 完整审批和动作账本；
- 回放实验和 Release Gate；
- RBAC、审计、报告、错误恢复；
- E2E、安全和性能测试；
- 安装、升级、备份和运维文档。

### 15.3 现场只读 Pilot：再增加 8–12 周

- Edge Collector 和工业 DMZ 部署；
- 真实 OPC UA/历史数据映射；
- 现场证书、网络和数据质量验证；
- 静默 Shadow 和人工复核；
- 现场基准、漂移和误报治理；
- 企业 SSO、备份、监控和安全审查。

### 15.4 生产多站点：6–9 个月级项目

- 多租户/多站点隔离；
- 高可用和灾备；
- Domain Pack 生命周期；
- 规模化时序和消息基础设施；
- CMMS/MES 协作；
- 持续认证、灰度、回滚和运营 SLO；
- 供应链、安全、合规和渗透测试。

---

## 16. 推荐实施批次地图

后续若拆成可直接交给 Codex 的 Batch，建议按以下依赖顺序，而不是按页面拆分：

| Batch | 交付主题 | 可演示价值 |
|---:|---|---|
| 01 | 项目骨架、领域类型、配置、CI | 可构建、可测试、可启动 |
| 02 | 资产/信号模型与单位系统 | 建立泵罐资产 |
| 03 | 工艺模拟器与确定性时钟 | 产生合理工艺数据 |
| 04 | 快照、恢复和数值确定性 | 同 seed 可复现 |
| 05 | 虚拟 OPC UA 地址空间 | 客户端可订阅 |
| 06 | Shadow Collector 与原始事件 | 原始数据完整落盘 |
| 07 | Scenario DSL 与校验 | YAML 可定义 Episode |
| 08 | Fault Runtime 与 10 类操作符 | 可按时间注入故障 |
| 09 | Gold Vault 与场景套件 | 答案隔离且可批量运行 |
| 10 | Run Orchestrator 与状态机 | 可暂停、恢复、取消 |
| 11 | 数据质量与单变量检测 | 输出质量和基础异常 |
| 12 | 工艺残差与跨变量规则 | 输出可解释症状 |
| 13 | Evidence 对象与证据时间线 | 结论可追溯 |
| 14 | 因果图与 Top-3 排序 | 输出支持/矛盾证据 |
| 15 | 检查库与计划排序 | 生成安全检查顺序 |
| 16 | Control Plane 工具与策略 | 参数级权限和审计 |
| 17 | 审批中心与持久化中断 | 人工控制副作用 |
| 18 | 仿真动作、验证与回滚 | 完成恢复闭环 |
| 19 | Replay、A/B 与实验注册 | 版本可比较 |
| 20 | Evaluator、报告和 Release Gate | 完成认证闭环 |
| 21 | 管理端、RBAC、审计与健康 | 产品可运营 |
| 22 | 历史数据导入与 Signal Mapping | 进入真实数据 S1 |
| 23 | Edge 只读 Connector 与 Shadow Pilot | 进入 S2 |
| 24 | 安全、韧性、性能和生产验收 | 形成 Pilot Release |

每个 Batch 应同时定义输入、具体代码模块、Schema、API、事件、UI、测试证据和 DoD；不能只交付文档或空模板。

---

## 17. 全系统验收场景

### 17.1 Happy Path

1. 工程师发布泵罐资产模型和场景；
2. Run Orchestrator 创建 100 个故障和 50 个正常 Episode；
3. 模拟器按 seed 产生数据并故障注入；
4. Collector 完整保存原始事件；
5. 检测链生成症状和证据；
6. 根因引擎生成 Top-3；
7. 检查计划进入审批；
8. 审批人批准部分虚拟检查；
9. 动作执行器保存快照、执行、观察和回滚/确认恢复；
10. Replay 对比两个算法版本；
11. Evaluator 计算指标；
12. Release Gate 通过并生成可审计报告。

### 17.2 安全 Path

当端点属于真实设备或身份无法确认时：

1. 只读采集可以按策略进行；
2. UI 不显示执行控制；
3. `request_virtual_action` 被策略拒绝；
4. 拒绝结果写入审计和安全事件；
5. 诊断仍可输出证据和人工检查建议；
6. 不存在通过管理员临时开关绕过的路径。

### 17.3 数据不可信 Path

当多个节点冻结、质量码异常或时间漂移超限时：

1. 数据质量引擎产生 `DATA_UNTRUSTED`；
2. 工艺根因排序暂停或降级；
3. 通信/采集链候选优先；
4. UI 显示数据限制；
5. 检查计划先要求验证连接和传感器；
6. 报告不得给出确定设备根因。

### 17.4 版本回归 Path

新检测器、Prompt 或 Pack 发布前：

1. 在固定基准集上作为 Challenger 运行；
2. 对比总指标和每类故障切片；
3. 检查安全红线和新出现失败；
4. 输出 Episode 级差异证据；
5. 仅在 Release Gate 通过后可升级为 Champion；
6. 保留一键回滚到上一认证版本。

---

## 18. Definition of Done

系统只有同时满足以下条件，才可称为 MVP 功能闭环，而不是“规范包”或“界面 Demo”：

1. 代码仓库可从空环境一键构建和启动；
2. 数据库迁移、种子数据和 Domain Pack 可执行；
3. 真实虚拟 OPC UA 客户端能够订阅数据；
4. 10 类故障和正常场景能够实际运行；
5. 原始事件、质量码、时间戳和序列完整落盘；
6. Top-3、证据、检查计划来自实际运行结果；
7. 未审批动作被真实策略和测试阻断；
8. 仿真动作确实改变模型并完成恢复验证；
9. 快照恢复和相同输入回放通过确定性测试；
10. Evaluator 对至少 150 个 Episode 计算真实指标；
11. HTML/JSON 报告可打开且能追溯证据；
12. E2E、契约、安全、回放和关键性能测试通过；
13. CI 保存测试、覆盖率、场景运行、报告和安全扫描证据；
14. 文档明确声明未实现真实设备控制；
15. Release Gate 通过且安全红线全部为零。

如果只有 SKILL.md、接口占位、静态 JSON 或模拟测试结果，不满足本 DoD，也不能声明功能已经实现。

---

## 19. 最终产品判断

原始方案的三周闭环适合作为高质量 PoC，但要形成有竞争力的产品，必须把重点从“Agent 能否猜中故障”提升为：

> 能否用可复现数据、结构化工业证据、严格权限、人工审批、仿真验证和持续 Release Gate，证明某个工业 Agent 版本在特定资产、工况和故障覆盖范围内足够可靠。

最有商业价值的核心不是通用聊天界面，而是四类资产：

1. 可复用的 Domain Pack 与故障场景库；
2. 工业证据图、残差库和判别检查库；
3. 跨模型、规则、Prompt 和算法版本的基准评测体系；
4. 能把“不能触碰真实控制”变成可技术证明和可审计的安全边界。

在这一定位下，平台可以稳健扩展到工业控制、物流优化设备、机器人上位机、能源系统和复杂产线，同时避免在第一阶段承担真实自动控制的不可接受风险。
