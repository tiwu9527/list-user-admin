# OpenList 用户管理

## 项目定位

独立运行的 OpenList 用户管理后台，用于创建和管理普通 WebDAV 用户。

- 项目名称：**OpenList 用户管理**
- 项目目录：`/vol1/@apphome/trim.openclaw/data/workspace/openlist-user-admin`
- 服务地址：`http://192.168.1.9:19100/`
- Cloudflare 公网地址：`https://a.tiwunb.xyz/`
- 主程序：`app.py`
- 数据库：`data.db`
- 日志：`app.log`
- PID 文件：`app.pid`

## 运行状态与依赖

这是一个独立的 Python Web 服务，不依赖 OpenClaw 对话进程运行。它与 OpenClaw 位于同一台宿主机，但使用独立进程监听 `0.0.0.0:19100`。

服务依赖：

1. 宿主机正常运行；
2. 本地 Python 进程正常运行；
3. 需要同步 OpenList 的操作要求 OpenList API 可用；
4. 公网访问要求 Cloudflare Tunnel 正常运行。

当前 Cloudflare Tunnel 使用现有 Tunnel `by-tiwunb`，配置文件位于：

`/vol1/@apphome/trim.openclaw/data/home/.cloudflared/config.yml`

其中 `a.tiwunb.xyz` 转发到 `http://127.0.0.1:19100`。

## 功能

- 独立后台账号密码登录；
- 登录失败只显示错误提示，不展示后台内容；
- 修改后台密码后清除会话并强制重新登录；
- 用户名即时检查；
- 用户名只允许小写英文字母和数字；
- 禁止使用包含管理员相关词语或管理员账号的用户名；
- 创建普通 OpenList 用户：`role=0`、`permission=256`；
- 用户绑定 `base_path`；
- 周卡、年卡、自定义到期时间；
- 用户列表按用户名查询；
- 所有用户支持续费一年或两年；
- 停用、恢复、删除用户并同步 OpenList；
- 每 60 秒检查到期用户并自动停用；
- 新增用户后显示固定网易爆米花 WebDAV 配置文本；
- 配置文本支持复制和继续新增；
- 设置页面隐藏 OpenList 管理员密码，使用 `***` 展示；
- 页面支持移动端适配和 Cloudflare HTTPS 访问。

## 重要接口约定

OpenList 用户管理 API：

- 登录：`POST /api/auth/login`
- 用户列表：`GET /api/admin/user/list?page=1&per_page=1000`
- 创建用户：`POST /api/admin/user/create`
- 更新用户：`POST /api/admin/user/update`
- 删除用户：`POST /api/admin/user/delete?id=<id>`

## 数据与安全说明

- `data.db` 包含后台设置及 OpenList 连接信息，不应复制到公开仓库或发送到聊天；
- 不要将 OpenList 密码、Token 写入日志；
- 对外访问优先使用 `https://a.tiwunb.xyz/`；
- Cloudflare WAF 建议对 `a.tiwunb.xyz` 使用 Managed Challenge；
- 不建议直接将 `19100` 做公网端口映射；
- 修改代码后至少执行 `python3 -m py_compile app.py`，再重启服务并检查 `/health`。

## 版本与在线更新准备

- 版本号采用语义化版本 `MAJOR.MINOR.PATCH`，例如 `0.1.0`；修复问题递增 PATCH，增加兼容功能递增 MINOR，不兼容变更递增 MAJOR。
- 当前版本记录在 `VERSION` 文件。发布时更新该文件并创建同名 Git tag（如 `v0.1.0`），便于确认版本和回滚。
- `.gitignore` 排除数据库、运行日志、PID、备份和 `.env` 等运行数据/敏感信息；这些文件不得推送到仓库。
- `update.sh` 是服务器侧更新脚本草案：先备份代码和 SQLite 数据库，再从配置的 Git 分支 fast-forward 更新、语法检查、重启并检查 `/health`；失败时恢复旧代码。它只在手动运行时更新，不会自动执行。
- 服务器部署时应将运行数据放在代码目录之外，并在检查脚本中的目录、服务启动/停止方法、健康检查 URL 后再启用。当前项目尚未配置 Git remote，亦未在本机运行此更新脚本。

## 后续修改约定

修改本项目时：

1. 保持项目名称为“OpenList 用户管理”；
2. 先检查 `app.py` 当前实现，不要覆盖已有功能；
3. 涉及 OpenList API 时确认 HTTP 方法、路径及响应格式；
4. 涉及登录、密码、删除等操作时优先考虑安全性和会话状态；
5. 修改后执行语法检查、健康检查，并确认服务仍监听 `19100`；
6. 不删除 `data.db`，不重新创建已有用户；
7. 不记录密码或 Token。
