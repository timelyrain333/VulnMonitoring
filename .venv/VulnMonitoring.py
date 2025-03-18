# coding=utf-8

import argparse
import os
import time
import requests
from lxml import html
from datetime import datetime

BASE_URL = "https://www.openwall.com/lists/oss-security/"

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Monitor OSS-Security mailing list for vulnerabilities.")
    parser.add_argument("--keywords", default="", help="Comma-separated list of keywords to filter messages")
    parser.add_argument("--slack-webhook", default="", help="Slack Webhook URL for notifications")
    parser.add_argument("--dingtalk-webhook", default="", help="DingTalk Webhook URL for notifications")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in minutes")
    return parser.parse_args()

def send_init_message(interval, slack_webhook, dingtalk_webhook):
    """发送初始化消息"""
    log_message = f"vuln-notifier initialized successfully. Polling every {interval} minutes."
    today = datetime.utcnow()
    current_url = f"{BASE_URL}{today.year}/{today.month:02d}/{today.day:02d}/"
    send(log_message, current_url, slack_webhook, dingtalk_webhook)

def send(title, url, slack_webhook, dingtalk_webhook):
    """发送通知到 Slack 和/或 DingTalk"""
    if slack_webhook:
        message = f"{title} ({url})"
        send_to_slack(slack_webhook, message)
    if dingtalk_webhook:
        message = f"{title} {url}"
        escaped_message = escape_message(message)
        send_to_dingtalk(dingtalk_webhook, escaped_message)

def send_to_slack(webhook_url, message):
    """发送消息到 Slack"""
    payload = {"text": message}
    requests.post(webhook_url, json=payload)

def send_to_dingtalk(webhook_url, message):
    """发送消息到 DingTalk"""
    payload = {"msgtype": "text", "text": {"content": message}}
    requests.post(webhook_url, json=payload)

def escape_message(message):
    """转义消息中的双引号"""
    return message.replace('"', '\\"')

def fetch_content(url):
    """获取网页内容"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Failed to fetch URL: {e}")
        return None

def parse_items(content):
    """解析 HTML 内容，提取列表项"""
    try:
        tree = html.fromstring(content)
        list_items = tree.findall(".//ul/li/a")
        items = []
        for item in list_items:
            href = item.get("href")
            title = item.text_content().strip()
            items.append([href, title])
        return items
    except Exception as e:
        print(f"Failed to parse HTML: {e}")
        return None

def fetch(url):
    """获取并解析 URL 的内容"""
    content = fetch_content(url)
    if not content:
        return None
    items = parse_items(content)
    if not items:
        return None
    return items

def load_visited_vuln():
    """加载已访问的漏洞标题"""
    visited_vuln = set()
    file_name = generate_file_name()
    try:
        with open(file_name, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
            i = 0
            while i < len(lines):
                if lines[i]:
                    title = lines[i]
                    i += 1
                    # 跳过 URL 行
                    if i < len(lines) and lines[i]:
                        i += 1
                    # 跳过任何空行
                    while i < len(lines) and not lines[i]:
                        i += 1
                    visited_vuln.add(title)
                else:
                    i += 1
    except FileNotFoundError:
        pass
    return visited_vuln

def generate_file_name():
    """基于当前日期生成文件名"""
    today = datetime.utcnow()
    return f"vuln-{today.year}-{today.month:02d}-{today.day:02d}.txt"

def append_to_file(file_name, title, url):
    """将新漏洞追加到文件中"""
    try:
        with open(file_name, "a", encoding="utf-8") as f:
            f.write(f"{title}\n{url}\n\n")
    except Exception as e:
        print(f"Failed to append to file: {e}")

def log_with_time(message):
    """带时间戳的日志输出"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def monitor(keywords, slack_webhook, dingtalk_webhook):
    """监控 OSS-Security 邮件列表，查找新漏洞"""
    today = datetime.utcnow()
    url = f"{BASE_URL}{today.year}/{today.month:02d}/{today.day:02d}/"

    try:
        items = fetch(url)
    except Exception as e:
        print(f"Failed to fetch and parse content: {e}")
        return

    if not items:
        log_with_time("No items found for the current time.")
        return

    visited_vuln = load_visited_vuln()
    file_name = generate_file_name()

    for href, title in items:
        title = title.replace("\n", " ")  # 清理标题中的换行符
        detail_url = f"{url}{href}"

        if title.startswith("Re:"):
            continue

        if title in visited_vuln:
            continue

        log_with_time(f"New message found: {title} {detail_url}")

        if not keywords:
            send(title, detail_url, slack_webhook, dingtalk_webhook)
            append_to_file(file_name, title, detail_url)
        else:
            for keyword in keywords:
                if keyword.strip().lower() in title.lower():
                    send(title, detail_url, slack_webhook, dingtalk_webhook)
                    append_to_file(file_name, title, detail_url)
                    break

        visited_vuln.add(title)

def main():
    """主函数"""
    args = parse_arguments()
    keyword_list = [k.strip() for k in args.keywords.split(",") if k.strip()]

    send_init_message(args.interval, args.slack_webhook, args.dingtalk_webhook)

    while True:
        log_with_time("Querying data...")
        monitor(keyword_list, args.slack_webhook, args.dingtalk_webhook)
        time.sleep(args.interval * 60)

if __name__ == "__main__":
    main()