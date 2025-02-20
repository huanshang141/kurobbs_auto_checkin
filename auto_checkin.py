import os
import sys
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import requests
from loguru import logger
from pydantic import BaseModel, Field

from ext_bark import send_bark_notification


class Response(BaseModel):
    code: int = Field(..., alias="code", description="返回值")
    msg: str = Field(..., alias="msg", description="提示信息")
    success: Optional[bool] = Field(None, alias="success", description="token有时才有")
    data: Optional[Any] = Field(None, alias="data", description="请求成功才有")


class KurobbsClientException(Exception):
    """Custom exception for Kurobbs client errors."""
    pass


class KurobbsClient:
    FIND_ROLE_LIST_API_URL = "https://api.kurobbs.com/user/role/findRoleList"
    SIGN_URL = "https://api.kurobbs.com/encourage/signIn/v2"
    USER_SIGN_URL = "https://api.kurobbs.com/user/signIn"

    def __init__(self, token: str, account_name: str = "默认账号"):  # 修改这里，添加默认值
        self.token = token
        self.account_name = account_name
        self.result: Dict[str, str] = {}
        self.exceptions: List[Exception] = []

    def get_headers(self) -> Dict[str, str]:
        """Get the headers required for API requests."""
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
        """Make a POST request to the specified URL with the given data."""
        headers = self.get_headers()
        response = requests.post(url, headers=headers, data=data)
        res = Response.model_validate_json(response.content)
        logger.debug(res.model_dump_json(indent=2, exclude={"data"}))
        return res

    def get_user_game_list(self, game_id: int) -> List[Dict[str, Any]]:
        """Get the list of games for the user."""
        data = {"gameId": game_id}
        res = self.make_request(self.FIND_ROLE_LIST_API_URL, data)
        return res.data

    def checkin(self) -> Response:
        """Perform the check-in operation."""
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
        """Perform the sign-in operation."""
        return self.make_request(self.USER_SIGN_URL, {"gameId": 2})

    def _process_sign_action(
        self,
        action_name: str,
        action_method: Callable[[], Response],
        success_message: str,
        failure_message: str,
    ):
        """
        Handle the common logic for sign-in actions.

        :param action_name: The name of the action (used to store the result).
        :param action_method: The method to call for the sign-in action.
        :param success_message: The message to log on success.
        :param failure_message: The message to log on failure.
        """
        resp = action_method()
        if resp.success:
            self.result[action_name] = success_message
        else:
            self.exceptions.append(KurobbsClientException(failure_message))

    def start(self):
        """Start the sign-in process."""
        self._process_sign_action(
            action_name="checkin",
            action_method=self.checkin,
            success_message="签到奖励签到成功",
            failure_message="签到奖励签到失败",
        )

        self._process_sign_action(
            action_name="sign_in",
            action_method=self.sign_in,
            success_message="社区签到成功",
            failure_message="社区签到失败",
        )

        self._log()

    @property
    def msg(self):
        return ", ".join(self.result.values()) + "!"

    def _log(self):
        """Log the results and raise exceptions if any."""
        if msg := self.msg:
            logger.info(msg)
        if self.exceptions:
            raise KurobbsClientException(", ".join(map(str, self.exceptions)))


def configure_logger(debug: bool = False):
    """Configure the logger based on the debug mode."""
    logger.remove()  # Remove default logger configuration
    log_level = "DEBUG" if debug else "INFO"
    logger.add(sys.stdout, level=log_level)


def main():
    """Main function to handle command-line arguments and start the sign-in process."""
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
            logger.warning(f"{account_name} 的token未设置，跳过")
            continue

        try:
            kurobbs = KurobbsClient(token=token, account_name=account_name)  # 使用关键字参数
            kurobbs.start()
            if kurobbs.msg:
                all_results.append(kurobbs.msg)
        except KurobbsClientException as e:
            error_msg = f"{account_name} 签到失败: {str(e)}"
            logger.error(error_msg, exc_info=False)
            all_results.append(error_msg)
            has_error = True
        except Exception as e:
            error_msg = f"{account_name} 发生未知错误: {str(e)}"
            logger.error(error_msg)
            all_results.append(error_msg)
            has_error = True

    # 发送通知
    if all_results:
        notification_message = "\n".join(all_results)
        send_bark_notification(notification_message)

    if has_error:
        sys.exit(1)


if __name__ == "__main__":
    main()
