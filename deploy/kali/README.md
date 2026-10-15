# Kali 执行环境

VMware NAT 地址通常会变化。Windows 控制端可以在 Kali 开机并拿到 DHCP 地址后运行自动发现脚本：

~~~powershell
powershell -ExecutionPolicy Bypass -File .\deploy\kali\discover_vmware.ps1 -VmxPath "<VMX_PATH>" -User kali -KeyPath "<SSH_KEY_PATH>"
~~~

如果提示没有租约，请先启动 Kali，在 Kali 内确认 SSH 服务：

~~~bash
sudo systemctl enable --now ssh
ip -4 addr
~~~

脚本只读取 VMX、VMware DHCP 租约并检查 TCP/22，不会启动虚拟机，也不会运行扫描器。

首次连接建议使用公钥，不把 Kali 密码写入 VulnFusion：

~~~powershell
ssh-keygen -t ed25519 -f <SSH_KEY_PATH>
~~~

把生成的公钥内容追加到 Kali 的 ~/.ssh/authorized_keys，然后测试：

~~~powershell
ssh -i <SSH_KEY_PATH> kali@<KALI_IP> "printf ssh-ok"
~~~

SSH 测试成功并确认主机指纹后，把连接配置保存到项目根目录 `.env`，通过 `powershell -ExecutionPolicy Bypass -File .\start.ps1` 启动。项目使用严格主机密钥校验；重新安装虚拟机后，需要重新核实指纹。

VulnFusion 的 Windows/API 控制端不安装或运行扫描器。所有 `nmap`、`httpx`、`ffuf`、`nuclei`、`sqlmap` 等命令都由控制端通过 SSH 发送到 Kali，并且只有在人工批准任务后才会执行。

把 `bootstrap.sh` 放到 Kali 的 `~/vulnfusion/bootstrap.sh`，使用普通 Kali 用户运行 `bash ~/vulnfusion/bootstrap.sh`，不要在整条命令前加 sudo。脚本只为缺失的系统软件包请求 sudo，Semgrep 使用 pipx 隔离安装；默认创建 `~/vulnfusion/workspaces`。控制端会为远程命令添加用户的 `.local/bin` 和 `go/bin` 到 PATH。控制端配置：

```env
VULNFUSION_KALI_HOST=192.0.2.10
VULNFUSION_KALI_USER=kali
VULNFUSION_KALI_PORT=22
VULNFUSION_KALI_KEY=<SSH_KEY_PATH>
VULNFUSION_KALI_REMOTE_ROOT=/home/kali/vulnfusion/workspaces
VULNFUSION_KALI_HTTPX=httpx-toolkit
```

脚本只提供环境准备，不会被 VulnFusion 自动调用。请先确认目标属于授权范围，再把 `execute_remote=true` 且 `dry_run=false` 的运行请求交给人工审批。

控制台“检查连接和工具”会执行 SSH 身份验证、工具路径检查、HTTPX 版本检查和工作目录检查。缺少工具时会显示具体名称；该检查不会向测试目标发包。接口是 `POST /api/kali/check`，`GET /api/kali/status` 仅返回配置。
