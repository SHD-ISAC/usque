# 按需启动的自适应系统 TUN（Linux / Team）

`usque up`、`usque down`、`usque status` 和 `usque check` 已集成进 Usque。
不需要 Python 启停脚本，不安装开机服务，不重新注册设备，不修改原始配置或公钥 pin。
旧的 `socks`、`scout`、`nativetun` 命令继续可用。

## 使用

适用已启用 systemd-resolved、`/etc/resolv.conf` 仅使用其本地 stub 解析器的系统。
复用已有的 systemd、iproute2、resolvectl 和 sudo；健康检查直接使用 Go 网络接口，无需 curl。
二进制安装在 root 所有且不可由普通用户写入的目录，通常为 `/usr/local/bin/usque`。

如果原来的手动 TUN 仍在运行，先执行原来的 `usque-down`。安装新二进制后：

```fish
usque up --plan
and usque up
usque status
usque check
usque down
```

`up` 默认读取调用者的 `~/.config/usque/config.json`，需要时通过 sudo 提权。
`--plan` 只进行本地只读预检，不探测入口、不改变路由、不显示凭据。
原配置必须为 0600 或更严格的普通文件，属于调用者或 root。

明确指定原配置：

```fish
usque -c "$HOME/.config/usque/config.json" up
```

外层入口策略与可调参数：

```fish
usque up --family prefer6
usque up --family 6
usque up --family 4 --ports 500,4500,443
usque up --probe-timeout 8s --family-budget 32s
```

每次更改启动参数前先 `usque down`。`--family 6` 是严格只使用 IPv6 入口；
默认 `prefer6` 才会在 IPv6 不可用时回退 IPv4。所有模式的隧道内流量仍同时支持 IPv4 和 IPv6。

## 自动适应

- 默认优先探测原配置中的入口，并补充 Cloudflare Zero Trust MASQUE 公共入口候选。
  候选仅限于 Cloudflare 官方公布的共享 MASQUE 入口范围，参见文末官方防火墙文档。
  这些入口由不同组织共享，具体 Team 身份通过设备注册和认证信息区分。
  不向个人 WARP 地址段、第三方中转或注册 API 发送注册凭据。
- 默认 QUIC 端口顺序为 `500,4500,443,1701,4443,8443,8095`。端口保存在会话参数与缓存中，
  不写入原始注册配置。自动模式不切换 HTTP/2，也不接受 `--insecure`。
- IPv6 必须先具备物理网络路由和可用的公网源地址。只有默认路由、链路本地地址或
  隧道内 IPv6 可用，都不足以被当成可用的 IPv6 入口。
- 每次最多并行探测两个候选；每个完整的原公钥 CONNECT-IP + 隧道内 HTTPS 检查默认 6 秒。
  IPv6 每轮默认先试 24 秒，失败后给 IPv4 同等预算；一旦有候选通过便停止该轮。
  超出预算的候选在后续轮次轮换，不在一次启动时穷举整个地址段。
- 在相同物理网络和注册配置下，优先复测上次成功的同地址族组合。即使缓存为 IPv4，
  `prefer6` 也仍先检查 IPv6。缓存仅包含入口、时间、网络与配置的摘要，不含密钥、token 或公钥原文。
- 启动 native TUN 后，先通过接口绑定的 UDP DNS 和普通证书校验的 HTTPS 验证隧道内双栈，
  然后才接管系统互联网流量与 DNS。
- 每 30 秒检查一次隧道内 UDP DNS 和双栈 HTTPS；连续三轮失败后重新选择组合。
  当前组合失败后冷却两分钟，避免反复选中它。物理路由、网关或源地址变化时重新选择。
- 使用 IPv4 时，每 5 分钟重新检查 IPv6；只有 IPv6 完整验证通过后才进行切换。
  可通过 `--health-interval` 和 `--ipv6-retry` 调整间隔。
- 初次启动有总时限；无法验证可用隧道时失败退出并清理，不留下无限等待的启动任务。

这是以连通性和 IPv6 优先为目标的故障恢复，不是带宽测速。不会仅凭 ping 或 TLS 握手成功选中入口。
切换涉及重建 MASQUE 会话，已有 TCP/UDP 会话可能中断，需要应用自行重连。

## 系统管理与清理

`up` 创建临时 `usque-native.service`，`Restart=no`，没有 enable、定时启动或开机启动。
运行时有两个来自同一个二进制的进程：会话管理进程和 native TUN 进程。
管理进程监督网络与健康状态，native TUN 进程转发数据包。传输层卡住时可以结束整个子进程再切换。

使用 `usque0`、专用路由表 51871、规则优先级 18050–18054、protocol 199。
启用 CN 绕过时额外使用表 51872，规则优先级范围扩展到 18055。
两个地址族的 Team 入口范围都绕过 TUN，查询当前物理 main 表；物理路由消失时阻止其落回 TUN。
局域网及 main 表已有的更具体路由继续优先。原 main 表及默认路由不修改。

默认只在 `usque0` 上设置 Cloudflare 公共 DNS 和 `~.`；查询经过 TUN，
可正常返回 AAAA。更具体的局域网域名路由继续保留。
不修改 resolv.conf、NetworkManager 配置、UFW、sysctl、文件 capabilities 或自定义 hooks。
发现其他 Usque、原脚本会话、自定义策略规则，或活动的 Xray/warp-svc 时拒绝接管。
运行期间检测到这些 VPN 服务启动，会结束本会话并清理。

每项路由或 DNS 变更先写入私有撤销记录，再执行；停止和启动失败均逆序撤销。
systemd 的 ExecStopPost 在异常退出后再次清理，`usque down` 可重试未完成的清理。
只撤销本次记录的项目，不清空全局规则或路由。

运行记录：`/run/usque-native/session.json`，成功停止后删除。
上次成功入口缓存：`/run/usque-native/last-endpoint.json`，在同次开机内保留，重启后消失。
目录 0700，文件 0600，均不保存凭据。

本方案没有永久断网保护。自动切换期间会撤销旧会话的系统路由与 DNS，重新选择后再接管；
这段时间物理网络可能直接承载应用流量。`down` 和退出清理后也恢复物理网络。

## 可选的 CN IP / 域名绕过

```fish
usque up --bypass-cn --plan
and usque up --bypass-cn
```

`--bypass-cn` 单独使用表示 `both`，即 CN IP 或 CN 域名满足任一条件便走物理网络。
也可以用 `--bypass-cn=ip`、`--bypass-cn=domain` 或 `--bypass-cn=off`；默认 `off`。
这是每次启动的参数，不写入原始注册配置；下次启动需要再次带上。
IPv6 优先和自动入口回退仍然生效。外层入口地址族与内层分流地址族独立。

复用已安装 Xray 的 `geoip.dat` / `geosite.dat` 中的 `cn` 分类；不需要启动 Xray，
不内置、不下载或更新数据库，不增加 Go 模块依赖。只启用 IP 模式不需要 geosite，反之亦然。
自动查找 `XRAY_LOCATION_ASSET`、`/usr/local/share/xray`、`/usr/share/xray`、
`/var/lib/xray`、`/etc/xray`、`/usr/local/etc/xray`，以及调用者的
`~/.config/xray`、`~/.local/share/xray`。也可以明确指定已有文件：

```fish
usque up --bypass-cn \
    --geoip-file /usr/local/share/xray/geoip.dat \
    --geosite-file /usr/local/share/xray/geosite.dat
```

CN IP 前缀在专用表 51872 中指向当前物理接口、网关和物理源地址；不修改 main 表，
不使用 nftables、NAT 或防火墙标记。LAN 与已有更具体的 main 路由继续优先。
如果物理网络没有某个地址族可用的路由，该地址族仍走 TUN，避免直连黑洞。
网关或源地址变化后随会话重新加载这些路由。停止只清理本会话的专用表和规则。

域名模式使用集成的 DNS 转发器，监听 `usque0` 自身的 IPv4 地址、UDP/TCP 1053，
仅接受本机来源。只调整该接口的 resolved DNS，保留全局解析器配置。
CN 域名默认通过物理网络查询阿里公共 DNS；
其他域名通过 TUN 查询 Cloudflare 公共 DNS，不回退到物理 DNS。
可用 `--cn-dns` 指定 1–4 个公共 DNS 的 IP 和可选端口。
国内查询使用普通 UDP/TCP DNS；网络中已有的 DNS 劫持仍可能影响国内答案。

仅学习匹配域名及其 CNAME 链的 A/AAAA 答案，在发送答案前先安装物理路由。
路由按 DNS TTL 保留，最长 10 分钟；TTL 为零时提供短暂的即时路由。
已建立的 TCP/UDP 连接通过只读内核 socket / 可用的 conntrack 状态延长路由，
不记录或持久化连接、查询域名。最多保留 8192 个动态地址。

这是基于 DNS 的域名分流，没有 Xray 的流量嗅探或 FakeDNS。
应用自带 DoH/DoQ、已有应用 DNS 缓存或 HTTPS 记录中的 IP 提示可能跳过域名学习，
但仍接受 CN IP 规则判断。同一 IP 承载多个域名时，学习期间其他域名也可能直连。
因此域名规则不能视为逐连接的严格隔离；原有 TLS 校验和 Cloudflare 公钥 pin 不变。

## 验证与日志

```fish
usque check --duration 5m --interval 10s
usque status
sudo journalctl -u usque-native.service -n 100 --no-pager
```

`check` 的 DNS 与 HTTPS socket 均绑定 `usque0`，不采用环境代理，不允许直连回退。
UDP DNS 分别通过隧道内 IPv4、IPv6 传输；HTTPS 校验正常证书链、主机名、返回地址族及 `warp=on/plus`。
检查不显示完整出口地址。该命令验证 UDP DNS，不等价于测试所有 UDP 应用或 STUN。

测试覆盖地址族优先级、端口回退、超时取消、故障冷却、缓存隔离、配置只读、私有状态、
写前撤销记录、幂等清理、DNS/trace 校验与竞态检查。CI 另在独立 Linux 网络命名空间中验证
双栈默认路由、两个入口范围的物理绕行、IPv6 物理路由消失时防循环及退出恢复。
CN 分流另覆盖真实内核的双栈物理源地址选择、动态域名路由到期、接口绑定的本地 DNS、
UDP/TCP DNS 转发、CNAME / TTL 校验、数据库匹配和旧脚本内容校验。
这些测试不使用真实 Team 凭据，也不替代用户网络上的首次新版本实测。

## 迁移旧脚本

原 `usque-up`/`usque-down` 仍属于 Python 脚本，新功能的命令是带空格的 `usque up`/`usque down`。
新版本实测正常后：

```fish
usque cleanup-legacy --plan
and usque cleanup-legacy
```

仅删除已核对内容的 1.0.1 Python 脚本 `/usr/local/bin/usque-session`，
以及明确指向它的 `usque-up`、`usque-down` 符号链接。若旧会话仍有运行或撤销记录，
先调用已验证的旧脚本正常停止并恢复；恢复失败便不删除文件。
遇到被修改的旧脚本、非预期的文件或持久化旧服务，拒绝删除以供人工检查。
不会删除新的 Usque 二进制、原始配置、公钥、Xray 数据库或 Downloads。

确认无需保留下载副本后，可以单独删除旧工具的这些明确路径：

```fish
rm -f -- "$HOME/Downloads/usque-session.py" \
    "$HOME/Downloads/usque-verify.py" \
    "$HOME/Downloads/usque-manual-kit/usque-session.py" \
    "$HOME/Downloads/usque-manual-kit/usque-verify.py"
```

常规的 DNS / HTTPS 隧道验证可使用 `usque check`；旧验证脚本中的 SOCKS STUN 检查未集成。
Python 本身不属于本次清理范围。
不需要删除或重新生成 `~/.config/usque/config.json`。

参考：

- https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/
- https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html
- https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
- https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html
