# OWASP 安全速查/备忘表

Origin/原文: [CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries).

OWASP CheatSheet 的内容是专业，全面且简练的,  适合安全攻防、开发、设计、SDL等多个方向的技术人员阅读。遂决定对其进行完整的翻译，一来锻炼自己的英语能力，二来可以查漏补缺。Enjoy!

**说明: 标题和文章内容中的标记[D], 属译者补充内容，通常认为存在欠缺知识点或原文难于理解时，会打上标记并进行内容补充，以便阅读理解**



## 章节

>Total Docs: 75篇
>
>Finish: 11篇

下面的分类基于个人认知，为了方便整理相关内容和透视知识点。 

欢迎有不同的分类思考，文章若为肉，分类即为体，好的形体会带来新的认知和阅读体验。

* 常见安全问题
  * 业务功能
    * [忘记密码](./cheatsheets/Forgot_Password_Cheat_Sheet.md) - 100%
    * [选用安全问题](./cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md) - 100%
    
  * 枚举
    * [防范凭证填充(撞库)](./cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md) - 100%
    
    * [防范不安全的直接对象引用(IDOR)](./cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md) - 100%, update 2021.12.07
    
  * 注入
    * [防范注入](./cheatsheets/Injection_Prevention_Cheat_Sheet.md) - 100%
    * [防范LDAP注入](./cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md) - 100%
    * [防范OS命令注入](./cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md) - 100%
    * [防范SQL注入](./cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md) - 100%
    
  * 浏览器
    * [防范点击劫持](./cheatsheets/Clickjacking_Defense_Cheat_Sheet.md) - 1%
    * [内容安全策略](./cheatsheets/Content_Security_Policy_Cheat_Sheet.md) - 1%
    * [防范跨站请求伪造(CSRF)](./cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) - 1%
    * [防范基于DOM的XSS](./cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md) - 1%
    * [XSS过滤绕过(逃逸)](./cheatsheets/XSSFilterEvasionCheatSheet.md) - 1%
    * [防范XSS](./cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md) - 1%
    * [防范跨站泄露(xs-leak)](./cheatsheets/XS_Leaks_Cheat_Sheet.md) - 1%
    
  * 文件操作

    * [文件上传](./cheatsheets/File_Upload_Cheat_Sheet.md) - 1%

  * (反)序列化操作

    * [反序列化](./cheatsheets/Deserialization_Cheat_Sheet.md) - 100%

  * 网络操作

    * [防范服务端请求伪造(SSRF)](./cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md) - 1%

  * 典型问题
  
    * [自动绑定(变量覆盖)](./cheatsheets/Mass_Assignment_Cheat_Sheet.md) - 1%
    * [防范未验证的重定向和转发](./cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md) - 100%
    * [防范XML外部实体(XXE)](./cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md) - 1%
  
* 设计安全

  *  基础架构
    * [软件定义基础架构(IaC)安全](./cheatsheets/Infrastructure_as_Code_Security_CheatSheet.md) - 1%
  * 数据存储
    * [存储加密](./cheatsheets/Cryptographic_Storage_Cheat_Sheet.md) - 1%
    * [密码存储](./cheatsheets/Password_Storage_Cheat_Sheet.md) - 1%
  * 数据结构
    * XML
      * [XML安全](./cheatsheets/XML_Security_Cheat_Sheet.md) - 1%
  * 异常处理
    * [错误处理](./cheatsheets/Error_Handling_Cheat_Sheet.md) - 1%
  * 日志机制
    * [日志机制](./cheatsheets/Logging_Cheat_Sheet.md) - 1%
    * [应用日志词汇表](./cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.md) - 100%
  * 输入机制
    * [输入验证](./cheatsheets/Input_Validation_Cheat_Sheet.md) - 1%
    * [参数化查询](./cheatsheets/Query_Parameterization_Cheat_Sheet.md) - 1%
  * 兜底/应急机制
    * [虚拟补丁](./cheatsheets/Virtual_Patching_Cheat_Sheet.md) - 1%

* 服务安全

  * 数据库服务
    * [数据库安全](./cheatsheets/Database_Security_Cheat_Sheet.md) - 1%
  * 微服务
    * [微服务安全](./cheatsheets/Microservices_security.md) - 1%
    * [基于微服务的安全-Arch文档](./cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.md) - 1%
  * 应用服务
    * [WEB服务安全](./cheatsheets/Web_Service_Security_Cheat_Sheet.md) - 1%
  * 容器服务
    * [docker安全](./cheatsheets/Docker_Security_Cheat_Sheet.md) - 1% 
    * [Kubernetes安全](./cheatsheets/Kubernetes_Security_Cheat_Sheet.md) - 1%
    * [NodeJS docker](./cheatsheets/NodeJS_Docker_Cheat_Sheet.md) - 1%

* 基础/组件安全

  * 可用性
    * [拒绝服务](./cheatsheets/Denial_of_Service_Cheat_Sheet.md) - 100%
  * 通信
    * [HTTP严格传输安全(HSTS)](./cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md) - 1%
    * [Pinning](./cheatsheets/Pinning_Cheat_Sheet.md) - 1%
    * [TLS Cipher String](./cheatsheets/TLS_Cipher_String_Cheat_Sheet.md) - 1%
    * [传输层防护](./cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md) - 1%

  * 接口化数据交互
    * [GraphQL](./cheatsheets/[GraphQL_Cheat_Sheet.md](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/GraphQL_Cheat_Sheet.md)) - 1%
    * [AJAX安全](./cheatsheets/AJAX_Security_Cheat_Sheet.md) - 100%
    * [REST评估](./cheatsheets/REST_Assessment_Cheat_Sheet.md) - 1%
    * [REST安全](./cheatsheets/REST_Security_Cheat_Sheet.md) - 1%
  * 供应链/包管理
    * [第三方JavaScript(依赖库)管理](./cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md) - 1%
    * [脆弱依赖管理](./cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md) - 1%
    * [npm安全](./cheatsheets/npm_Security_CheatSheet.md) - 1%

* 语言安全
  * JS
    * [Nodejs安全](./cheatsheets/Nodejs_Security_Cheat_Sheet.md) - 1%
  * JAVA
    * [bean validation规范](./cheatsheets/Bean_Validation_Cheat_Sheet.md) - 1%
    * [java防范注入](./cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.md) - 1%
    * [java认证授权服务(JAAS)](./cheatsheets/JAAS_Cheat_Sheet.md) - 1%
    * [java下JWT算法](./cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md) - 1%
  * C/C++/C#/.NET
    * [DotNet安全](./cheatsheets/DotNet_Security_Cheat_Sheet.md) - 1%
    * [基于C的增强防御工具链](./cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.md) - 1%
  * PHP
    * [PHP配置](./cheatsheets/PHP_Configuration_Cheat_Sheet.md) - 1%
    * [Laravel框架](./cheatsheets/Laravel_CheatSheet.md) - 1%
  * Ruby
    * [Ruby on Rails](./cheatsheets/Ruby_on_Rails_Cheat_Sheet.md) - 1%
  * 前端
    * [HTML5](./cheatsheets/HTML5_Security_Cheat_Sheet.md) - 1%
    * [保护级联样式](./cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.md) - 1%
  * 通用
    * [安全断言标记语言(SAML)](./cheatsheets/SAML_Security_Cheat_Sheet.md) - 1%
  
* 安全管控
  * [访问控制](./cheatsheets/Access_Control_Cheat_Sheet.md) - 50%
  * [密钥管理](./cheatsheets/Key_Management_Cheat_Sheet.md) - 1%
  * [会话管理](./cheatsheets/Session_Management_Cheat_Sheet.md) - 1%
  * [认证](./cheatsheets/Authentication_Cheat_Sheet.md) - 1%
  * [多因素认证](./cheatsheets/Multifactor_Authentication_Cheat_Sheet.md) - 1%
  * [授权](./cheatsheets/Authorization_Cheat_Sheet.md) - 1%
  * [业务授权](./cheatsheets/Transaction_Authorization_Cheat_Sheet.md) - 1%
  
* SDL流程
  * [基线(恶意)用例](./cheatsheets/Abuse_Case_Cheat_Sheet.md) - 20%
  * 需求: [D]安全需求基线
  * 设计: [威胁建模](./cheatsheets/Threat_Modeling_Cheat_Sheet.md) - 1%
  * 设计: [攻击面分析(风险识别)](./cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)  - 1%
  * 编码: [D]扫描、审计
  * 转测: [D]渗透测试
  * 转测: [D]漏洞回归
  
* 安全自动化

  * [授权测试自动化](./cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md) - 1%

* 安全运营
  * [漏洞披露](./cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.md) - 1%
  
* 安全合规
  * [用户隐私保护](./cheatsheets/User_Privacy_Protection_Cheat_Sheet.md) - 1%
  * [D]网络安全法 - 1%



## 更迭方案

对照原文更新时间点: 2021.12.07。

以当前commit为起点，脚本检查cheatsheets, assets目录变更情况，人工对变更的文件和内容进行翻译与更新后，重置起点。

文章中的"待规划" 代表原文该处标记未来补充或者和前面重复，待原文补充后再进行翻译。

* PDF: 待规划
* 在线阅读: 待规划



## 项目结构

* 文章目录 cheatsheets
* 草稿 cheatsheets_draft
* 归档内容 cheatsheets_excluded
* 资源文件 assets
* 主页 README.md



## 翻译团队

* Djerryz



## 建议与反馈

任何翻译，文字语法上的错误，或技术细节，欢迎提交issue进行探讨。
