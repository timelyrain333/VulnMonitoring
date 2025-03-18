简介：
    一个简单的 python 命令行工具，用于监控 Openwall 安全邮件列表，支持将新的漏洞帖子通知到 Slack 或者 DingTalk。该工具支持关键词过滤，确保只接收相关的安全通知。
    
要求：
    python3.9或更高的版本
    
运行参数：
    运行脚本时，可以通过命令行参数指定：
    --keywords：用逗号分隔的关键词列表，用于过滤消息。
    
    --slack-webhook：Slack 通知的 Webhook URL。
    
    --dingtalk-webhook：DingTalk 通知的 Webhook URL。
    
    --interval：轮询间隔，单位为分钟，默认 60 分钟。

示例：
    python3 VulnMonitoring.py --keywords "CVE,exploit" --slack-webhook "https://hooks.slack.com/services/xxx" --interval 30

