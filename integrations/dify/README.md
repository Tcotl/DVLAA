# DVLAA real Dify integration

此目录部署的是 **Dify 官方容器**，不是 DVLAA 的对话 Fixture。选手可以在
Dify 原生 Web 控制台创建 Chatflow/Workflow、上传知识库、配置工具，并通过
Dify 的 `/v1` API 进行真实模型交互。DVLAA 的 AWDP 题目可以把这里的地址作为
独立目标服务使用。

## 版本锁定

| 项目 | 值 |
| --- | --- |
| Dify release | `1.9.2` |
| upstream commit | `ec871819e46de82f2f9ee33a71a61d96a58bdb37` |
| official source | <https://github.com/langgenius/dify/tree/1.9.2/docker> |
| default URL | <http://127.0.0.1:5800> |
| active vector profile | Weaviate |

`docker-compose.yaml` 是上游生成的官方文件，API、Web、Sandbox 和插件镜像
均使用 `1.9.2` 系列；`VERSION` 中记录 Compose 文件的 SHA-256。Dify API、
Web、Sandbox 和插件镜像已提供 `linux/arm64` manifest，Docker 会按主机架构
选择镜像，不需要在 Compose 中写死 `platform`。

## 启动

要求 Docker 24+、Docker Compose v2 和至少 8 GB 可用内存（首次拉取镜像需要
网络）。在项目根目录执行：

```bash
cd integrations/dify
./bootstrap.sh
```

脚本会：

1. 从 `.env.example` 创建权限为 `0600` 的本地 `.env`；
2. 为 Dify、PostgreSQL、Redis、Sandbox 和插件服务生成随机密钥；
3. 创建官方 Compose 使用的持久化目录，并从上游 Sandbox 示例生成匹配密钥的本地 `config.yaml`；
4. 校验 Compose 配置、拉取固定版本镜像并启动服务；
5. 轮询 Dify 原生 `/console/api/ping`，成功后输出控制台地址；
6. 当 `DIFY_AUTO_PROVISION=true`（示例默认值）时，通过 Dify Console API
   幂等创建本地管理员和 AWDP02 Chat 应用。

常用命令：

```bash
./bootstrap.sh config       # 只生成配置并打印解析结果
./bootstrap.sh pull         # 拉取镜像
./bootstrap.sh down         # 停止服务，保留 volumes 中的数据
./healthcheck.sh             # 单独检查原生 API
```

示例配置的本地管理员为 `admin@dvlaa.local` / `DVLAA2026+`，只用于本机训练，
对外提供服务前应在 `.env` 中替换密码。Dify 的 API Key、应用 Token 和工作区
数据由 Dify 自己保存，不写入 DVLAA 代码。若关闭 `DIFY_AUTO_PROVISION`，首次
访问 <http://127.0.0.1:5800>，按 Dify 的初始化页面创建管理员即可。

也可以让官方 API 完成首次管理员初始化（凭据只通过环境变量传入）：

```bash
DIFY_ADMIN_EMAIL=admin@example.test \
DIFY_ADMIN_NAME='DVLAA Administrator' \
DIFY_ADMIN_PASSWORD='CHANGE_ME' \
./init-admin.sh
```

如果在 `.env` 中启用了 Dify 的 `INIT_PASSWORD`，同时设置
`DIFY_INIT_PASSWORD`。脚本只调用 `/console/api/init` 和 `/console/api/setup`，
不会创建伪造用户或写入凭据文件；已经完成初始化时会直接退出。

## 真实模型配置

Dify 将模型提供商凭据保存在工作区数据库中，官方 Compose 不会把模型密钥
自动注入容器。默认方式是在原生 Console 中配置：

1. 在 `.env` 中填写 `DVLAA_MODEL_PROVIDER`、`DVLAA_MODEL_API_BASE`、
   `DVLAA_MODEL_NAME`，并把 API Key 留在本地环境变量或密钥管理器中；
2. 登录 Dify，进入 **Settings -> Model Provider**，选择 OpenAI-compatible
   （或对应的 SiliconFlow 插件），填写同一 Base URL、API Key 和模型名；
3. 创建一个 Chatflow/Workflow，发布后使用应用 API Key 调用 `/v1/chat-messages`
   或 `/v1/workflows/run`。这条链路经过真实 Dify API、队列、Sandbox、向量库
   和模型服务，不经过 DVLAA 固定回复。

首次初始化和模型提供商配置仍遵循 Dify 官方工作区流程。完成配置后运行：

```bash
./bootstrap.sh provision --require-model
```

该命令会复用已有管理员、应用和模型凭据，不会重复创建；只有检测到可用的真实
LLM 后才会写入 AWDP02 的模型提示词。AWDP 适配器只读取运行环境中生成的公开
应用 URL/ID 元数据，不读取管理密码、模型密钥或 Flag。

SiliconFlow 示例（只展示变量名，不把真实密钥提交到仓库）：

```dotenv
DVLAA_MODEL_PROVIDER=OpenAI-API-compatible
DVLAA_MODEL_API_BASE=https://api.siliconflow.cn/v1
DVLAA_MODEL_API_KEY=TOKEN
DVLAA_MODEL_NAME=Qwen/Qwen3-8B
OPENAI_API_BASE=https://api.siliconflow.cn/v1
```

需要全自动配置时，先在 Dify 原生控制台的 **Settings -> Model Provider** 中
安装官方 `OpenAI-API-compatible` 插件（版本 `0.0.62` 或更新版本），再在本地
`.env` 使用插件 slug 和密钥（不会提交到 Git）：

```dotenv
DIFY_MODEL_PROVIDER=langgenius/openai_api_compatible/openai_api_compatible
DIFY_MODEL_API_BASE=https://api.siliconflow.cn/v1
DIFY_MODEL_API_KEY=TOKEN
DVLAA_MODEL_NAME=Qwen/Qwen3-8B
```

`provision.py` 会按 provider 的原生凭据接口创建或更新模型，并启用该模型；
不同 provider 的字段不一致时，改用 `DIFY_MODEL_CREDENTIALS_JSON` JSON 对象。
插件安装完成后，运行 `./bootstrap.sh provision --require-model`；如果目标网关
不支持模型校验或模型名不在插件的可发现列表中，命令会保留失败状态，不会把
AWDP02 标记为已就绪。

## 与 AWDP 的连接

DVLAA 本身仍监听 `5080`；本集成使用独立的 Compose project 名称
`dvlaa-dify` 和端口 `5800`，因此可以同时运行。AWDP 目标适配器应使用：

```text
Web base: http://127.0.0.1:5800
Console API: http://127.0.0.1:5800/console/api
Application API: http://127.0.0.1:5800/v1
```

当 DVLAA 由 `./install.sh` 运行在 Docker 中时，DVLAA 容器不能用自身的
`127.0.0.1` 访问 Dify。为 DVLAA 的环境文件加入以下变量后重建容器：

```dotenv
DVLAA_DIFY_MODE=native
DVLAA_DIFY_URL=http://host.docker.internal:5800
```

`install.sh` 会为 Linux Docker 和 Docker Desktop 添加
`host.docker.internal:host-gateway` 映射。Dify 的浏览器地址仍然是
`http://127.0.0.1:5800`；前一项仅供 DVLAA 后端健康探测使用。

不要把 Dify 的管理 API Key、应用 API Key 或模型提供商 Token 写入题库、前端
模板或 Git；每次训练应为目标工作区生成独立的应用和数据集。

## 数据与重置

数据位于本目录的 `volumes/`，默认 `down` 不删除数据。需要重置本地目标时，
先停止服务，再把 `volumes/` 改名为备份目录后重新运行 `./bootstrap.sh`；不要
在共享服务器上直接删除其他训练会话的数据。

## 公开来源

- [Dify Docker deployment](https://docs.dify.ai/getting-started/install-self-hosted/docker-compose)
- [Dify repository](https://github.com/langgenius/dify)
- [Dify 1.9.2 Docker files](https://github.com/langgenius/dify/tree/1.9.2/docker)
