# 导入所需的库
import os  # 用于获取环境变量
import json  # 用于JSON数据处理
import requests  # 用于发送HTTP请求
from loguru import logger  # 用于日志记录

def send_wechat_notification(message, title="库街区自动签到任务"):
    """
    通过企业微信机器人发送通知消息
    
    Args:
        message (str): 要发送的消息内容
        title (str, optional): 消息标题，默认为"库街区自动签到任务"
    
    Returns:
        None
    
    Note:
        需要在环境变量中设置 WECHAT_WEBHOOK_URL
        消息将以 Markdown 格式发送
    """
    # 从环境变量获取企业微信机器人的Webhook URL
    webhook_url = os.getenv("WECHAT_WEBHOOK_URL")
    
    # 如果未设置Webhook URL，记录警告并退出
    if not webhook_url:
        logger.warning("未设置企业微信机器人的Webhook URL，跳过通知发送。")
        return
    
    # 构造要发送的消息数据
    data = {
        "msgtype": "markdown",  # 消息类型为markdown
        "markdown": {
            "content": f"## {title}\n{message}"  # 消息内容，包含标题和正文
        }
    }
    
    try:
        # 发送POST请求到Webhook URL
        response = requests.post(
            webhook_url,
            json=data,
            headers={"Content-Type": "application/json"}
        )
        # 检查响应状态码
        if response.status_code != 200:
            logger.error(f"发送通知失败：{response.text}")
    except Exception as e:
        # 捕获并记录所有可能的异常
        logger.error(f"发送通知时发生错误：{str(e)}")
