# 防范LDAP注入

## 介绍

本备忘单的重点是为防止应用程序中的LDAP注入缺陷提供清晰、简单、可操作的指导。

LDAP注入通过利用web应用程序根据用户输入构造LDAP语句的场景实现的一种攻击。当应用程序无法正确清理用户输入时，可以通过类似于[SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)的技术修改LDAP语句.

LDAP注入攻击可能导致向未经授权的查询授予权限，并在LDAP树中修改内容。

有关LDAP注入攻击的更多信息，请访问[LDAP注入](https://owasp.org/www-community/attacks/LDAP_Injection).

[LDAP注入](https://owasp.org/www-community/attacks/LDAP_Injection)攻击常见的原因有两个:

1. 缺少更安全、参数化的LDAP查询接口

2. 系统对用户进行身份验证场景下广泛的使用LDAP

主要防御手段：

* 使用正确的LDAP编码函数转义所有变量

其他防御措施：

* 使用一个框架（如[LINQtoAD](https://archive.codeplex.com/?p=linqtoad))自动转义

## 主要防御

### 防御选项1：使用正确的LDAP编码函数转义所有变量

LDAP存储名称的主要方式是基于DN（可分辨名称）。您可以将其视为唯一标识符。它们有时用于访问资源，如用户名。

DN可能如下所示

`cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu`

或

`uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com`

在DN中，某些字符被视为特殊字符。

[详尽清单](https://ldapwiki.com/wiki/DN%20Escape%20Values)包含：`\ # + < > , ; " =`和前导空格或尾随空格。

可分辨名称中允许且不需要转义的某些“特殊”字符包括：

```text
* ( ) . & - _ [ ] ` ~ | @ $ % ^ ? : { } ! '
```

每个DN正好指向一个条目，这有点像RDBMS中的一行。对于每个条目，将有1个或多个类似于RDBMS列的属性。如果您对通过LDAP搜索用户的某些属性感兴趣，您可以使用搜索过滤器进行搜索。

在搜索筛选器中，可以使用标准布尔逻辑获取与任意约束匹配的用户列表。搜索过滤器是用波兰语表示法（又称前缀表示法）编写的。

例子：

```text
(&(ou=Physics)(|
(manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu)
))
```

在应用程序代码中构建LDAP查询时，必须转义添加到任何LDAP查询中的任何不受信任的数据。LDAP转义有两种形式，编码LDAP查询和编码LDAP DN（可分辨名称）。正确的转义取决于您是正在清理搜索筛选器的输入，还是正在使用DN作为类用户名的凭据去访问某些资源。

#### 安全JAVA转义示例

- [Prevent LDAP injection](https://wiki.sei.cmu.edu/confluence/spaces/flyingpdf/pdfpageexport.action?pageId=88487534).
- [Legacy OWASP ESAPI for Java DefaultEncoder which includes encodeForLDAP(String) and encodeForDN(String)](https://github.com/ESAPI/esapi-java-legacy/blob/develop/src/main/java/org/owasp/esapi/reference/DefaultEncoder.java).

#### 安全 C Sharp .NET TBA 示例

[.NET AntiXSS](https://blogs.msdn.microsoft.com/securitytools/2010/09/30/antixss-4-0-released/) (现在的Encoder类)  具有LDAP编码函数，包括`Encoder.LdapFilterEncode（string）`、`Encoder.ldapDifferentizedNameEncode（string）`和`Encoder.ldapDifferentizedNameEncode（string，bool，bool）`。

`Encoder.LdapFilterEncode` 根据[RFC4515](https://tools.ietf.org/search/rfc4515)对输入进行编码，其中不安全值转换为`\XX`，其中`XX`是不安全字符的表示形式。

`Encoder.LdapDistinguishedNameEncode` 根据 [RFC2253](https://tools.ietf.org/html/rfc2253) 对输入进行编码,其中不安全字符转换为`#XX`，其中`XX`表示不安全字符，逗号、加号、引号、斜杠、小于号和大于号使用斜杠符号（`\X`）转义。除此之外，输入字符串开头的空格或八进制（`#`)与字符串结尾的空格一样被`\`转义。

`LdapDistinguishedNameEncode(string, bool, bool)` 提供初始或结束字符转义规则的关闭功能，如要将转义的可分辨名称片段连接到完整的可分辨名称中间。

### 防御选项2: 使用能够自动防止LDAP注入的框架

安全NET示例

[LINQ to Active Directory](https://linqtoad.codeplex.com) 在生成LDAP查询时提供自动LDAP编码。

### 防御选项3: 补充防御

除了采用两种主要防御中的一种，我们还建议采用所有这些额外防御，以便提供纵深防御。这些额外的防御措施包括：

- **最低特权**
- **白名单输入验证**

#### 最低特权

要将成功的LDAP注入攻击的潜在危害降至最低，您应该将分配给环境中LDAP绑定帐户的权限降至最低。 

#### 白名单输入验证

输入验证可用于检测未经授权的输入，然后再将其传递到LDAP查询。有关更多信息，请参阅 [Input Validation Cheat Sheet](Input_Validation_Cheat_Sheet.md).

## 相关文章

- OWASP article on [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection) Vulnerabilities.
- OWASP article on [Preventing LDAP Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html).
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) article on how to [Test for LDAP Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/06-Testing_for_LDAP_Injection.html) Vulnerabilities.