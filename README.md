# OWASP安全速查表

&emsp;&emsp;本项目是在自身的安全认知基础上，对[CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries)内容进行分类，整理，完善而成。阅读OWASP CheatSheet的过程中，发现其内容是专业，全面与简练的。对于没有安全攻防实战的开发人员等，在实现安全动作或防范安全漏洞时，可以不求甚解，结合文章阐述的场景、原理与最佳实践等，快速提升安全质量以避免踩坑。

&emsp;&emsp;OWASP安全速查表的目标是帮助阅读者构建更加安全的应用程序，涵盖了"常见安全问题","常见防御措施","语言特性","数据结构","安全管控","环境安全","SDL流程","运营","合规"等多个方面的安全实践；同时，对于未参照安全实践所实现的业务和场景,攻击者可以反向思考，分析会存在哪些潜在的攻击面与脆弱性。

&emsp;&emsp;对于安全行业从业者，大都有自己的知识文档或速查表。本系列的文章的价值在于，CheatSheetSeries项目作为OWASP维护的项目，集成许多优秀安全人员的智慧与经验，他山之石，可以攻玉，通过阅读与学习，可以查漏补缺。

* PDF: 待规划

* 在线阅读: 待规划



## 章节

> Total Docs: 73篇  **标记 [D] 为译者补充内容**
>
> 完成度: 6/73

* 安全问题
  * 业务功能
    * [忘记密码](./cheatsheets/Forgot_Password_Cheat_Sheet.md) - 100%
    * [选用安全问题](./cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md) - 100%
  * 枚举类
    * [防范凭证填充(撞库)](./cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.md) - 100%
  * 业务/权限逻辑
    * [防范不安全的直接对象引用(IDOR)](./cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md) - 100%
  * 注入类
    * [防范注入](./cheatsheets/Injection_Prevention_Cheat_Sheet.md) - 100%
    * [防范LDAP注入](./cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md) - 100%
    * [防范OS命令注入](./cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md) - 100%
    * [防范SQL注入](./cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md) - 1%
  * 客户端/浏览器类
    * [点击劫持防御](./cheatsheets/Clickjacking_Defense_Cheat_Sheet.md) - 1%
    * [内容安全策略](./cheatsheets/Content_Security_Policy_Cheat_Sheet.md) - 1%
    * [防范跨站请求伪造(CSRF)](./cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) - 1%
    * [防范基于DOM的XSS](./cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md) - 1%
    * [XSS过滤绕过(逃逸)](./cheatsheets/XSSFilterEvasionCheatSheet.md) - 1%
  * 典型问题
    * [反序列化](./cheatsheets/Deserialization_Cheat_Sheet.md) - 1%
    * [文件上传](./cheatsheets/File_Upload_Cheat_Sheet.md) - 1%
    * [自动绑定(变量覆盖)](./cheatsheets/Mass_Assignment_Cheat_Sheet.md) - 1%
    * [防范服务端请求伪造(SSRF)](./cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md) - 1%
    * [未验证的重定向和转发](./cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md) - 1%
    * [防范XML外部实体(XXE)](./cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md) - 1%
  * 可用性
    * [拒绝服务](./cheatsheets/Denial_of_Service_Cheat_Sheet.md) - 1%
* 防御措施
  * 数据
    * [存储加密](./cheatsheets/Cryptographic_Storage_Cheat_Sheet.md) - 1%
    * [密码存储](./cheatsheets/Password_Storage_Cheat_Sheet.md) - 1%
  * 数据库
    * [数据库安全](./cheatsheets/Database_Security_Cheat_Sheet.md) - 1%
  * 通信
    * [HTTP严格传输安全(HSTS)](./cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.md) - 1%
    * [Pinning](./cheatsheets/Pinning_Cheat_Sheet.md) - 1%
    * [TLS Cipher String](./cheatsheets/TLS_Cipher_String_Cheat_Sheet.md) - 1%
    * [传输层防护](./cheatsheets/Transport_Layer_Protection_Cheat_Sheet.md) - 1%
  * 微服务
    * [微服务安全](./cheatsheets/Microservices_security.md) - 1%
    * [基于微服务的安全-Arch文档](./cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.md) - 1%
  * 接口化数据交互
    * [GraphQL](./cheatsheets/[GraphQL_Cheat_Sheet.md](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/GraphQL_Cheat_Sheet.md)) - 1%
    * [AJAX安全](./cheatsheets/AJAX_Security_Cheat_Sheet.md) - 100%
    * [REST评估](./cheatsheets/REST_Assessment_Cheat_Sheet.md) - 1%
    * [REST安全](./cheatsheets/REST_Security_Cheat_Sheet.md) - 1%
  * 架构
    * [软件定义基础架构(IaC)安全](./cheatsheets/Infrastructure_as_Code_Security_CheatSheet.md) - 1%
  * 供应链/包管理
    * [第三方JavaScript(依赖库)管理](./cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.md) - 1%
    * [脆弱依赖管理](./cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.md) - 1%
    * [npm安全](./cheatsheets/npm_Security_CheatSheet.md) - 1%
  * 通用
    * [输入验证](./cheatsheets/Input_Validation_Cheat_Sheet.md) - 1%
    * [错误处理](./cheatsheets/Error_Handling_Cheat_Sheet.md) - 1%
    * [应用日志词汇表](./cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.md) - 100%
    * [日志机制](./cheatsheets/Logging_Cheat_Sheet.md) - 1%
    * [参数化查询](./cheatsheets/Query_Parameterization_Cheat_Sheet.md) - 1%
    * [安全断言标记语言(SAML)](./cheatsheets/SAML_Security_Cheat_Sheet.md) - 1%
    * [虚拟补丁](./cheatsheets/Virtual_Patching_Cheat_Sheet.md) - 1%
    * [WEB服务安全](./cheatsheets/Web_Service_Security_Cheat_Sheet.md) - 1%
  * 自动化
    * [授权测试自动化](./cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.md) - 1%
* 语言特性
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
* 数据结构
  * XML
    * [XML安全](./cheatsheets/XML_Security_Cheat_Sheet.md) - 1%
* 安全管控
  * [访问控制](./cheatsheets/Access_Control_Cheat_Sheet.md) - 50%
  * [密钥管理](./cheatsheets/Key_Management_Cheat_Sheet.md) - 1%
  * [会话管理](./cheatsheets/Session_Management_Cheat_Sheet.md) - 1%
  * [认证](./cheatsheets/Authentication_Cheat_Sheet.md) - 1%
  * [多因素认证](./cheatsheets/Multifactor_Authentication_Cheat_Sheet.md) - 1%
  * [授权](./cheatsheets/Authorization_Cheat_Sheet.md) - 1%
  * [业务授权](./cheatsheets/Transaction_Authorization_Cheat_Sheet.md) - 1%
* 环境安全
  * 容器
    * [docker安全](./cheatsheets/Docker_Security_Cheat_Sheet.md) - 1% 
    * [Kubernetes安全](./cheatsheets/Kubernetes_Security_Cheat_Sheet.md) - 1%
    * [NodeJS docker](./cheatsheets/NodeJS_Docker_Cheat_Sheet.md) - 1%
* SDL流程
  * [基线(恶意)用例](./cheatsheets/Abuse_Case_Cheat_Sheet.md) - 20%
  * 需求: [D]安全需求基线
  * 设计: [威胁建模](./cheatsheets/Threat_Modeling_Cheat_Sheet.md) - 1%
  * 设计: [攻击面分析(风险识别)](./cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.md)  - 1%
  * 编码: [D]扫描、审计
  * 转测: [D]渗透测试
  * 转测: [D]漏洞回归
* 运营
  * [漏洞披露](./cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.md) - 1%
* 合规
  * [用户隐私保护](./cheatsheets/User_Privacy_Protection_Cheat_Sheet.md) - 1%



## 更迭方案

当前commit: Commits on Aug 16, 2021。

以当前commit为起点，脚本检查cheatsheets, assets目录变更情况，人工对变更的文件和内容进行翻译与更新后，重置起点。

文章中的"待规划" 代表原文该处标记未来补充或者和前面重复，后续大概率会更新的地方。



## 项目结构

* 文章目录 cheatsheets
* 草稿 cheatsheets_draft
* 归档内容 cheatsheets_excluded
* 资源文件 assets
* 主页 README.md



## 翻译团队

* Djerryz



## 建议与反馈

任何翻译，文字语法上的错误，或者技术细节，欢迎提交issue进行探讨。
