import os
import sys
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import requests

import random
import time

from loguru import logger
from pydantic import BaseModel, Field

from ext_bark import send_bark_notification

from ext_wechat import send_wechat_notification



class Response(BaseModel):
    code: int = Field(..., alias="code", description="返回值")
    msg: str = Field(..., alias="msg", description="提示信息")
    success: Optional[bool] = Field(None, alias="success", description="token有时才有")
    data: Optional[Any] = Field(None, alias="data", description="请求成功才有")


class KurobbsClientException(Exception):
    """库街区客户端异常。"""
    pass


class KurobbsClient:
    FIND_ROLE_LIST_API_URL = "https://api.kurobbs.com/user/role/findRoleList"
    SIGN_URL = "https://api.kurobbs.com/encourage/signIn/v2"
    USER_SIGN_URL = "https://api.kurobbs.com/user/signIn"
    FORUM_LIST_URL = "https://api.kurobbs.com/forum/list"

    SHARE_TASK_URL = "https://api.kurobbs.com/encourage/level/shareTask"
    LIKE_URL = "https://api.kurobbs.com/forum/like"
    POST_DETAIL_URL = "https://api.kurobbs.com/forum/getPostDetail"
    TASK_PROCESS_URL = "https://api.kurobbs.com/encourage/level/getTaskProcess"

    def __init__(self, token: str, account_name: str = "默认账号"):
        self.token = token
        self.account_name = account_name
        self.result: Dict[str, str] = {}
        self.exceptions: List[Exception] = []

    def get_headers(self) -> Dict[str, str]:
        """获取API请求所需的请求头。"""
        return {
            "osversion": "Android",
            "devcode": "39BAFA5213054623682C1EE76533416163075BFC",
            "countrycode": "CN",
            "ip": "192.168.199.159",
            "model": "SM-G9730",
            "source": "android",
            "lang": "zh-Hans",
            "version": "2.3.2",
            "versioncode": "2320",
            "token": self.token,
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/3.10.0",
        }

    def make_request(self, url: str, data: Dict[str, Any]) -> Response:
        """发送POST请求到指定URL。"""
        headers = self.get_headers()
        response = requests.post(url, headers=headers, data=data)
        res = Response.model_validate_json(response.content)
        logger.debug(res.model_dump_json(indent=2, exclude={"data"}))
        return res

    def get_user_game_list(self, game_id: int) -> List[Dict[str, Any]]:
        """获取用户游戏列表。"""
        data = {"gameId": game_id}
        res = self.make_request(self.FIND_ROLE_LIST_API_URL, data)
        return res.data

    def checkin(self) -> Response:
        """执行签到操作。"""
        user_game_list = self.get_user_game_list(3)

        date = datetime.now().month
        data = {
            "gameId": user_game_list[0].get("gameId", 2),
            "serverId": user_game_list[0].get("serverId", None),
            "roleId": user_game_list[0].get("roleId", 0),
            "userId": user_game_list[0].get("userId", 0),
            "reqMonth": f"{date:02d}",
        }
        return self.make_request(self.SIGN_URL, data)

    def sign_in(self) -> Response:
        """执行社区签到操作。"""
        return self.make_request(self.USER_SIGN_URL, {"gameId": 2})

    def get_post_list(self) -> List[Dict[str, Any]]:
        """获取帖子列表。"""
        data = {
            "forumId": 10,
            "gameId": 3,
            "pageIndex": 1,
            "pageSize": 20,
            "searchType": 1,
            "timeType": 0
        }
        res = self.make_request(self.FORUM_LIST_URL, data)
        return res.data.get("postList", [])

    def share_task(self) -> Response:
        """执行分享任务。"""
        return self.make_request(self.SHARE_TASK_URL, {"gameId": 3})

    def like_post(self, post: Dict[str, Any], like_type: int = 1) -> Response:
        """点赞或取消点赞帖子。"""
        data = {
            "forumId": post.get("gameForumId"),
            "gameId": 3,
            "likeType": 1,
            "operateType": like_type,  # 1为点赞，2为取消点赞
            "postCommentId": 0,
            "postCommentReplyId": 0,
            "postId": post.get("postId"),
            "postType": post.get("postType"),
            "toUserId": post.get("userId")
        }
        return self.make_request(self.LIKE_URL, data)

    def view_post(self, post: Dict[str, Any]) -> Response:
        """浏览帖子。"""
        data = {
            "isOnlyPublisher": 0,
            "postId": post.get("postId"),
            "showOrderType": 2
        }
        return self.make_request(self.POST_DETAIL_URL, data)

    def get_task_process(self) -> Response:
        """获取任务进度。"""
        user_id = json.loads(base64.b64decode(self.token.split(".")[1]).decode("utf-8")).get("userId")
        return self.make_request(self.TASK_PROCESS_URL, {"gameId": 0, "userId": user_id})

    def _process_sign_action(
        self,
        action_name: str,
        action_method: Callable[[], Response],
        success_message: str,
        failure_message: str,
    ):
        """
        处理日常任务操作的通用逻辑。

        :param action_name: 操作名称（用于存储结果）
        :param action_method: 操作的方法
        :param success_message: 执行任务成功时的消息
        :param failure_message: 执行任务失败时的消息
        """
        resp = action_method()
        if resp.success:
            # 将API返回的msg添加到结果消息中
            self.result[action_name] = f"{success_message}（{resp.msg}）"
        else:
            # 将API返回的msg添加到错误消息中
            self.exceptions.append(KurobbsClientException(f"{failure_message}（{resp.msg}）"))

    def start(self):
        # 执行奖励签到
        self._process_sign_action(
            action_name="checkin",
            action_method=self.checkin,
            success_message="签到奖励签到成功",
            failure_message="签到奖励签到失败",
        )

        # 执行社区签到
        self._process_sign_action(
            action_name="sign_in",
            action_method=self.sign_in,
            success_message="社区签到成功",
            failure_message="社区签到失败",
        )
        # 添加3秒延迟
        time.sleep(3)

        # 执行分享任务
        self._process_sign_action(
            action_name="share",
            action_method=self.share_task,
            success_message="分享任务完成",
            failure_message="分享任务失败",
        )
        # 添加3秒延迟
        time.sleep(3)
        
        # 获取帖子列表
        posts = self.get_post_list()
        if posts:
            # 随机选择5篇不同的帖子进行点赞
            like_posts = random.sample(posts, min(5, len(posts)))
            for post in like_posts:
                # 点赞帖子
                self._process_sign_action(
                    action_name=f"like_{post['postId']}",
                    action_method=lambda: self.like_post(post, like_type=1),
                    success_message=f"点赞帖子{post['postId']}完成",
                    failure_message=f"点赞帖子{post['postId']}失败",
                )
                # 添加3秒延迟
                time.sleep(3)

                # 取消点赞
                self._process_sign_action(
                    action_name=f"unlike_{post['postId']}",
                    action_method=lambda: self.like_post(post, like_type=2),
                    success_message=f"取消点赞帖子{post['postId']}完成",
                    failure_message=f"取消点赞帖子{post['postId']}失败",
                )
                # 添加3秒延迟
                time.sleep(3)

            # 随机选择3篇不同的帖子进行浏览
            view_posts = random.sample(posts, min(3, len(posts)))
            for post in view_posts:
                self._process_sign_action(
                    action_name=f"view_{post['postId']}",
                    action_method=lambda: self.view_post(post),
                    success_message=f"浏览帖子{post['postId']}完成",
                    failure_message=f"浏览帖子{post['postId']}失败",
                )
                # 添加3秒延迟
                time.sleep(3)

        self._log()

    @property
    def msg(self):
        return ", ".join(self.result.values()) + "!"

    def _log(self):
        """记录结果并抛出异常（如果有）。"""
        if msg := self.msg:
            logger.info(msg)
        if self.exceptions:
            raise KurobbsClientException(", ".join(map(str, self.exceptions)))


def configure_logger(debug: bool = False):
    """根据调试模式配置日志记录器。"""
    logger.remove()  # 移除默认的日志配置
    log_level = "DEBUG" if debug else "INFO"
    logger.add(sys.stdout, level=log_level)


def main():
    """主函数，处理命令行参数并启动签到流程。"""
    debug = os.getenv("DEBUG", False)
    configure_logger(debug=debug)

    # 获取所有账号的token
    accounts = [
        ("账号1", os.getenv("TOKEN")),
        ("账号2", os.getenv("TOKEN2"))
    ]

    all_results = []
    has_error = False

    # 遍历所有账号进行签到
    for account_name, token in accounts:
        if not token:
            logger.warning(f"{account_name}的token未设置，跳过")
            continue

        try:
            kurobbs = KurobbsClient(token=token, account_name=account_name)
            kurobbs.start()
            if kurobbs.msg:
                all_results.append(kurobbs.msg)
        except KurobbsClientException as e:
            error_msg = f"{account_name}签到失败：{str(e)}"
            logger.error(error_msg, exc_info=False)
            all_results.append(error_msg)
            has_error = True
        except Exception as e:
            error_msg = f"{account_name}发生未知错误：{str(e)}"
            logger.error(error_msg)
            all_results.append(error_msg)
            has_error = True

    # 发送通知
    if all_results:
        notification_message = "\n".join(all_results)
        send_wechat_notification(notification_message)

    if has_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
