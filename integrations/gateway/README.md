# DVLAA 统一入口网关（5080）

全部环境只通过 `127.0.0.1:5080` 暴露，按 Host 头（虚拟主机）路由，不再向宿主机发布其他端口。

## 路由表

| Host | 后端 | 说明 |
|---|---|---|
| `localhost` / `127.0.0.1` / `dvlaa.localhost` | dvlaa-console:5000 | DVLAA 控制台（登录墙） |
| `awdp02/06/08.localhost` | dvlaa-dify-nginx-1:80 | 真实 Dify 1.9.2 |
| `awdp03/09.localhost` | dvlaa-upstream-ragflow-1:9380 | 真实 RAGFlow（停止时回退 native 模拟目标） |
| `awdp04.localhost` | dvlaa-upstream-langflow-1:7860 | 真实 Langflow（同上回退） |
| `awdp05.localhost` | dvlaa-upstream-flowise-1:3005 | 真实 Flowise（同上回退） |
| `awdp07.localhost` | dvlaa-upstream-open-webui-1:8080 | 真实 Open WebUI（同上回退） |
| `awdp10.localhost` | dvlaa-upstream-n8n-1:5678 | 真实 n8n（同上回退） |
| `awdp01.localhost` | dvlaa-awdp-native:5900 | 本地案例模拟目标 |

`*.localhost` 在 macOS / Linux 上默认解析到 127.0.0.1；如浏览器不解析，把对应域名写入 /etc/hosts。

## 双轨制

- **默认模拟链路**：题目页 `/awdp-web/<id>/` 在真实环境停止时回退到 fixture / native 模拟目标（漏洞链路完整复刻，秒开零负担）。
- **真实复现环境**：题目页「启动真实复现环境」按钮调用 `/api/awdp/<id>/realenv/start`，控制台经 docker.sock 拉起对应容器组；就绪探测通过后题目自动切换到真实环境；`/api/awdp/<id>/realenv/stop` 停止后回退模拟链路。
- 网关对上游 502/503/504 自动回退 native 模拟目标（`nginx.conf` 中的 `error_page` + `map $host $native_challenge_root`），学员不会看到裸 502。

## 运维

- 修改 `nginx.conf` 后：`docker exec dvlaa-gateway nginx -t && docker exec dvlaa-gateway nginx -s reload`
- 网关用 Docker DNS（`resolver 127.0.0.11`）+ 变量 proxy_pass，目标容器未启动不影响网关自身启动。
- `proxy_redirect` 只改写容器名/回环形式的内部绝对地址，指向 `awdpNN.localhost` 的跨主机重定向原样保留。
