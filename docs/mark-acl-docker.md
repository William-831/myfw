# 标记+地址组联动白名单拦截设计

## 1. 背景与现象

宿主机 Docker 跑容器,端口映射 `-p 8080:80`。目标:**仅白名单 IP 可访问宿主机 8080,其余拒绝**。

现象:下发 MARK 规则后,非白名单 IP 仍能访问,拦截失效。

## 2. 根因:光打标不拦截

```
iptables -t mangle -A PREROUTING -p tcp --dport 8080 -j MARK --set-mark 15
```

这条命令**只给流量盖戳,不丢包**。要拦截**必须**在 filter 链补 `match_mark 15 -j DROP`。

## 3. 方案:标记+地址组联动(一键式)

用户只填 4 项:**流量方向 + 标记 + 端口 + 源地址组**。平台自动编译 3 条规则,落 MYFW 内置链,与 Docker/K8s 共存。

### 3.1 流量方向决定过滤链落点

| 方向 | 场景 | 打标 | 过滤 |
|---|---|---|---|
| 容器转发(FORWARD) | Docker `-p` 端口映射 | mangle PREROUTING | filter FORWARD |
| 主机入站(INPUT) | 主机本地服务(无 Docker) | mangle PREROUTING | filter INPUT |

打标都在 mangle PREROUTING(DNAT 前,dport 仍是宿主端口);过滤按方向落 FORWARD 或 INPUT。

### 3.2 自动编译的 3 条规则(以容器转发为例)

```
mangle/MYFW-MARKMANGLE:   -p tcp --dport <端口> -j MARK --set-mark <标记>          # 打标:只匹配端口,所有流量打标
filter/MYFW-MARKACL-FWD:  -m set --match-set <源地址组> src -m mark --mark <标记> -j ACCEPT  # 白名单放行(优先级 P)
filter/MYFW-MARKACL-FWD:  -m mark --mark <标记> -j DROP                            # 兜底丢弃(优先级 P+1)
```

主机入站方向则过滤链为 `MYFW-MARKACL-IN`(挂 `MYFW-INPUT`)。

### 3.3 设计要点(端口标识 + 源IP管控 分离)

- **打标规则只匹配目的端口**:清空 source/source_group,所有到该端口的流量都打标(端口标识)。
- **白名单规则用源地址组控制放行**:源在白名单地址组 + 有标记 -> ACCEPT(源IP管控)。
- **兜底丢弃**:有标记但非白名单 -> DROP。
- 不带标记的其它流量穿过过滤链不匹配,不受影响。

内置链 `MYFW-MARKMANGLE`(挂 `MYFW-MANGLE`)、`MYFW-MARKACL-FWD`(挂 `MYFW-FORWARD`)、`MYFW-MARKACL-IN`(挂 `MYFW-INPUT`)由编译器按需下发,driver 自动创建+挂载。实例 `group_id=0`(不归属用户组)。

## 4. 流量匹配验证

| 来源 | 打标 | 过滤链匹配 | 结果 |
|---|---|---|---|
| 白名单 IP | mark=N | 命中白名单+标 ACCEPT | **放行** |
| 非白名单 IP | mark=N | 跳过 ACCEPT,命中标 DROP | **拒绝** |
| 其它流量 | 无标 | 穿过不匹配 | 不受影响 |
| 容器回包 | 无标(反向) | 首条 ESTABLISHED | 放行 |

## 5. 改动点

- **模型**:`NodePolicyInstance` + `PolicyTemplate` 加 `Direction` 字段(FORWARD/INPUT)。
- **编译器 `compileInstance`**:`MARK + source_group + 端口` -> 自动 3 规则;打标落 `MARKMANGLE`,过滤按 `Direction` 落 `MARKACL-FWD`/`MARKACL-IN`;打标清空 source_group(只按端口)。
- **编译器 `CompileForNode`**:`group_id=0` 实例允许编译;按需追加 3 条内置 `CustomChainDef`。
- **校验 `ValidateFields`**:`MARK + 白名单` 需端口;方向须 FORWARD/INPUT(空默认 FORWARD)。
- **实例 CRUD**:`body` 加 `direction`;MARK 白名单 `group_id` 可空。
- **UI**:MARK 场景显示「流量方向 + 源地址组 + 协议/端口 + 标记值」,隐藏所属组/放行组/源地址/目的地址/匹配标记。

## 6. 验证清单

- [x] 单测:`ValidateFields` 白名单四态(FORWARD/INPUT/无端口/方向非法)+ 纯打标。
- [x] 单测:编译器 FORWARD -> `MARKACL-FWD`、INPUT -> `MARKACL-IN`,打标落 `MARKMANGLE`,内置链按需下发。
- [x] `go test ./internal/controller/{policy,compiler,server}/` 通过。
- [ ] 手测:容器转发填源地址组 + 端口 8080 + 标记,非白名单访问 8080 拒绝,白名单可访问。
- [ ] 手测:主机入站填端口 22 + 标记,非白名单 SSH 拒绝。
- [ ] 手测:`iptables-save` 确认规则在 `MYFW-MARKMANGLE`(mangle)与 `MYFW-MARKACL-FWD`/`MYFW-MARKACL-IN`(filter)。
