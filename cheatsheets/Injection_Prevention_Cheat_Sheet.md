# 防范注入

## 介绍

本文的重点是提供清晰、简单、可操作的指导，以防止应用程序中出现所有类型的注入缺陷。不幸的是,  注入攻击，尤其是[SQL注入](HTTPS:/OWASP.Org/WaveCalpIs/Atthasks/Sql注入)，是非常普遍存在的。 

应用程序可访问性是保护和预防注入缺陷需要考虑的一个非常重要的因素。公司/企业中只有少数应用程序是在内部开发的，而大多数应用程序都来自外部。开源应用程序至少提供了修复问题的机会，但闭源代码应用程序需要不同的方法来解决注入缺陷。

当应用程序向解释器发送不受信任的数据时，就会出现注入缺陷。注入缺陷非常普遍，特别是在遗留代码中，通常在SQL查询、LDAP查询、XPath查询、操作系统命令、程序参数等中可以发现它们。在检查代码时很容易发现注入缺陷，但测试相较而言更难发现。扫描器和模糊测试工具可以帮助攻击者找到它们。

为了确保可访问性， 必须采取不同的措施来修复这些问题。解决源代码本身的问题，甚至重新设计应用程序的某些部分，这始终是最好的方法。但是，如果源代码不可用，或者修复遗留软件的问题根本不经济，那么只有虚拟补丁才有意义。

## 程序类型

在一家公司内通常可以看到三类应用程序。这三种类型用于确定预防/修复注入缺陷所需采取的措施。

### A1: 新程序

新的web应用程序处于设计阶段或早期开发阶段。

### A2: 生成环境下的开源程序

一个已经生产的应用程序，可以很容易地进行调整。模型-视图-控制器（MVC）类型的应用程序是具有易于访问的应用程序体系结构的一个示例。

### A3: 生成环境下的闭源程序

一种生产性应用程序，不能或很难修改。

## 注入的多种形式

有几种针对不同技术的注入形式，包括SQL查询、LDAP查询、XPath查询和OS命令。

### 查询语言

最著名的注入形式是SQL注入，攻击者通过注入修改现有的数据库查询。有关更多信息，请参阅[SQL注入预防备忘单](SQL_Injection_Prevention_Cheat_Sheet.md)。

同样的，LDAP、SOAP、XPath和基于REST的查询也容易遭受数据检索或控制绕过的注入攻击。

#### SQL注入

SQL注入攻击通过数据输入，如从客户端（浏览器）传输到web应用程序，实现“注入”部分或完整的SQL查询。

成功的SQL注入攻击可以从数据库读取敏感数据、修改数据库数据（插入/更新/删除）、对数据库执行管理操作（如关闭DBMS）、恢复DBMS文件系统上现有的给定文件的内容或将文件写入文件系统，在某些情况下，可以直接执行系统命令。SQL注入是注入攻击的一种，其中SQL命令被注入到数据层输入中，以影响预定义SQL命令的执行。 

SQL注入攻击可分为以下三类：

- **带内:** 使用和注入SQL代码的相同数据通道获取数据。这是最直接的攻击类型，其中检索到的数据直接返回在应用程序中。
- **带外:** 使用不同的通道获取数据（例如，生成包含查询结果的电子邮件并发送给测试机）。
- **推理或盲注:** 没有实际的数据传输，但测试人员可以通过发送特定请求并观察数据库服务器的结果行为来重建信息。

##### 如何发现该问题

###### 在代码评审期间

请检查对数据库的任何查询是否未通过预编译完成。

如果正在进行动态语句构造，请检查输入的数据是否被限定于语句的一部分，无法逃逸并产生额外的歧义。

审核员应始终在SQL Server存储过程中查找sp_execute、execute或exec的用法。对于其他数据库的类似功能，需要类似的审核指南。

###### 自动化测试

下面的大多数情况和技术都可以使用一些工具以自动化的方式执行。在本文中，测试人员可以找到如何使用[SQLMap](https://wiki.owasp.org/index.php/Automated_Audit_using_SQLMap)执行自动审计的信息。

同样静态的代码分析(SAST)数据流规则可以检测未初始化的用户控制输入是否可以改变SQL查询。

###### 存储过程注入

在存储过程中使用动态SQL时，应用程序必须正确清理用户输入，以消除代码注入的风险。如果未进行清理，用户可能将在存储过程中输入并执行的恶意SQL。

###### 时延利用技术

当测试人员发现盲SQL注入情况时，时延利用技术非常有用，即使这种情况无法直观获取注入结果。这种技术包括发送一个注入的查询，如果条件为true，测试人员可以监控服务器响应所需的时间。如果有延迟，测试人员可以假设条件查询的结果为真。这种利用技术在不同的DBMS中可能有所不同（请查看对应的DBMS特定部分）。

```text
http://www.example.com/product.php?id=10 AND IF(version() like '5%', sleep(10), 'false'))--
```

在本例中，测试人员正在检查MySql版本是否为5.x，若是，则服务器的响应将会延迟10秒进行。测试机可以增加延迟时间并监控响应。测试人员也不需要等待响应。有时，他们可以设置一个非常高的值（例如100），并在几秒钟后取消请求。 

###### 带外利用技术

当测试人员发现盲SQL注入情况时，时延利用技术非常有用，即使这种情况无法直观获取注入结果。该技术包括使用DBMS函数来执行带外连接，并将注入查询的结果作为请求的一部分传递给测试人员的服务器。与基于错误的技术一样，每个DBMS都有自己的功能。检查特定的DBMS部分。

##### 补救措施

###### 防御选项1：预编译（通过参数化查询） 

预编译可确保攻击者即使攻击者插入了SQL命令也无法更改查询的意图。在下面的安全示例中，如果攻击者输入用户名`tom' or '1'='1`，参数化查询将不会受到攻击，而是查找与与字符串`tom' or '1'='1`完全匹配的用户名。 

###### 防御选项2：存储过程

预编译和存储过程之间的区别在于，存储过程的SQL代码被定义并存储在数据库本身中，然后从应用程序调用。

这两种技术在防止SQL注入方面具有相同的效果，因此您的组织应该选择最适合您的方法。存储过程在SQL注入中并不总是安全的。但在安全实现方面，某些标准存储过程的编程构造与使用参数化查询具有相同的效果，这是大多数存储过程语言的标准。

*注意:* '安全实现'表示存储过程不包括任何不安全的动态SQL生成。

###### 防御选项3：白名单输入验证

SQL查询无论哪个部分都不应作为变量拼接的合法位置，例如表或列的名称以及排序顺序指示符（ASC或DESC）。在这种情况下，输入验证或查询重新设计是最合适的防御措施。对于表或列的名称，理想情况下，这些值来自代码，而不是来自用户参数。

但是，如果使用用户参数值使表名和列名不同，则参数值应映射到合法/预期的表名或列名，以确保未验证的用户输入不会在查询中存在。请注意，这是设计不佳的症状，如果时间允许，应考虑完全重写。

###### 防御选项4：转义所有用户提供的输入

只有在上述任何一项都不可行的情况下，才应将此技术用作最后手段。输入验证可能是一个更好的选择，因为与其他防御措施相比，这种方法是脆弱的，我们不能保证它在所有情况下都会阻止所有SQL注入。

这种技术是在将用户输入放入查询之前对其进行转义。改造遗留历史代码时，实现输入验证经济成本较高的情况下，可以考虑使用。

##### 示例代码 - Java

###### 安全的JAVA预编译示例

下面的代码示例使用`PreparedStatement`,Java下一种参数化查询的实现,来执行等价的数据库查询。

```java
// This should REALLY be validated too
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

我们已经展示了Java中的示例，但实际上所有其他语言，包括Cold Fusion和经典ASP，都支持参数化查询接口。 

###### 安全的JAVA数据存储过程示例

下面的代码示例使用`CallableStatement`（存储过程接口的Java实现）来执行相同的数据库查询。须在数据库中预定义`sp_getAccountBalance`存储过程，并实现与上面定义的查询相同的功能。 

```java
// This should REALLY be validated
String custname = request.getParameter("customerName");
try {
 CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
 cs.setString(1, custname);
 ResultSet results = cs.executeQuery();
 // Result set handling...
} catch (SQLException se) {
 // Logging and error handling...
}
```

#### LDAP注入

LDAP注入攻击，常出现于web的应用程序根据用户输入构造LDAP语句的场景。当应用程序无法正确清理用户输入时，可以通过类似于 [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)的技术修改LDAP语句 LDAP注入攻击可导致向未经授权的查询授予权限，并在LDAP树中修改内容。有关LDAP注入攻击的更多信息，请访问 [LDAP injection](https://owasp.org/www-community/attacks/LDAP_Injection).

[LDAP injection](https://owasp.org/www-community/attacks/LDAP_Injection)攻击很常见，原因有两个：

1. 缺少更安全、参数化的LDAP查询接口
2. 广泛使用LDAP对系统中的用户进行身份验证。

##### 如何发现该问题

###### 在代码评审期间

请对LDAP的任何查询检查是否转义了特殊字符，请参阅 [here](LDAP_Injection_Prevention_Cheat_Sheet.md#defense-option-1-escape-all-variables-using-the-right-ldap-encoding-function).

###### 自动化测试

OWASP [ZAP](https://www.zaproxy.org/) 等工具，具有用于检测LDAP注入问题的扫描模块。

##### 补救措施

###### 使用正确的LDAP编码函数转义所有变量

LDAP存储名称的主要方式是基于DN（[可分辨名称](https://ldapwiki.com/wiki/Distinguished%20Names)). 您可以将其视为唯一标识符。它们有时用于访问资源，如用户名。

DN可能如下所示

```text
cn=Richard Feynman, ou=Physics Department, dc=Caltech, dc=edu
```

或

```text
uid=inewton, ou=Mathematics Department, dc=Cambridge, dc=com
```

在DN中，某些字符被视为特殊字符。如：`\ # + < > , ; " =`和前导空格或尾随空格

每个DN正好指向一个条目，这有点像RDBMS中的一行。对于每个条目，将有一个或多个类似于RDBMS列的属性。如果您有兴趣通过LDAP搜索用户的某些属性，您可以使用搜索筛选器。在搜索筛选器中，您可以使用标准布尔逻辑获取与任意约束匹配的用户列表。搜索筛选器使用波兰语表示法（又称前缀表示法）编写。

例如：

```text
(&(ou=Physics)(| (manager=cn=Freeman Dyson,ou=Physics,dc=Caltech,dc=edu)
(manager=cn=Albert Einstein,ou=Physics,dc=Princeton,dc=edu) ))
```

在应用程序代码中构建LDAP查询时，必须转义添加到任何LDAP查询中的任何不受信任的数据。LDAP转义有两种形式，编码LDAP查询和编码LDAP DN（可分辨名称）。正确的转义取决于您是正在清理搜索筛选器的输入，还是正在使用DN作为类用户名的凭据去访问某些资源。

##### JAVA 示例

###### 安全的JAVA LDAP转义示例

```java
public String escapeDN (String name) {
 //From RFC 2253 and the / character for JNDI
 final char[] META_CHARS = {'+', '"', '<', '>', ';', '/'};
 String escapedStr = new String(name);
 //Backslash is both a Java and an LDAP escape character,
 //so escape it first
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\");
 //Positional characters - see RFC 2253
 escapedStr = escapedStr.replaceAll("\^#","\\\\\\\\#");
 escapedStr = escapedStr.replaceAll("\^ | $","\\\\\\\\ ");
 for (int i=0 ; i < META_CHARS.length ; i++) {
        escapedStr = escapedStr.replaceAll("\\\\" +
                     META_CHARS[i],"\\\\\\\\" + META_CHARS[i]);
 }
 return escapedStr;
}
```

请注意，反斜杠字符是Java字符串及正则表达式转义字符。

```java
public String escapeSearchFilter (String filter) {
 //From RFC 2254
 String escapedStr = new String(filter);
 escapedStr = escapedStr.replaceAll("\\\\\\\\","\\\\\\\\5c");
 escapedStr = escapedStr.replaceAll("\\\\\*","\\\\\\\\2a");
 escapedStr = escapedStr.replaceAll("\\\\(","\\\\\\\\28");
 escapedStr = escapedStr.replaceAll("\\\\)","\\\\\\\\29");
 escapedStr = escapedStr.replaceAll("\\\\" +
               Character.toString('\\u0000'), "\\\\\\\\00");
 return escapedStr;
}
```

#### XPath注入

TODO

### 脚本语言

web应用程序中使用的所有脚本语言都有一种形式的“eval”调用，它在运行时接收代码并执行。如果代码是使用未验证和未转义的用户输入构造而成的，则可能会发生代码注入，从而允许攻击者破坏应用程序逻辑并最终获得本地访问权限。

每次使用脚本语言时，“高级”脚本语言的实际实现都是使用“低级”语言（如C）完成的。如果脚本语言在数据处理代码中有缺陷，'[空字节注入](http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection)'攻击向量可被用来访问内存中的其他区域，从而导致成功的攻击。

### 操作系统命令

OS命令注入可以通过web界面实现在web服务器上执行OS命令的技术。用户通过web界面提供操作系统命令的功能以执行系统命令。

任何未正确净化的web界面都会受到此攻击。通过执行操作系统命令，用户可以上传恶意程序，甚至获取密码。当在应用程序的设计和开发过程中注重对应的安全性时，OS命令注入是可以预防的。

#### 如何发现该问题

##### 在代码评审期间

检查是否调用了任何命令执行方法，以及是否将未验证的用户输入作为该命令的数据。

此外，在URL查询参数的末尾加上分号，然后再加上操作系统命令，将执行该命令。`%3B`是URL编码并解码为分号。这是因为`；`被解释为命令分隔符。

例如：`http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

如果应用程序以`/etc/passwd`文件的输出进行响应，那么您就知道攻击已经成功。许多web应用程序扫描程序都可以用来测试这种攻击，因为它们会注入各种命令并测试响应。

同样静态的代码分析工具检查不受信任的用户输入到web应用程序中的数据流，并检查数据是否随后输入到一个危险的方法中，该方法将用户输入作为命令执行。

#### 补救措施

如果认为对用户提供系统命令的功能不可避免，则应在软件中使用以下两层防御措施，以防止攻击

1. **参数化** - 如果可用，请使用结构化机制自动强制执行数据和命令之间的分离。这些机制可以帮助提供相关的引用、编码。 
2. **输入验证** - 应验证命令值和相关参数。命令及其参数的需要验证程度不同:
    - 对于使用的**命令**，必须根据允许的命令列表对其进行验证
    - 对于命令的**参数**，应使用以下选项对其进行验证：
        - 正向或“白名单”输入验证 - 明确定义了允许的参数 Positive or "allow list" input validation - where are the arguments allowed explicitly defined
        - 白名单正则表达式 - 其中显式定义了允许的良好字符列表和字符串的最大长度。确保像 **& | ; $ > < \` \ !** 这样的元字符不是正则表达式的一部分。例如，以下正则表达式只允许小写字母和数字，不包含元字符。长度也被限制为3-10个字符：`^[a-z0-9]{3,10}$`
    - 对于命令的**参数值**, 应单引号包裹，并对变量里的单引号转义为 `\'\\\'\`  -- [D] (可以思考下为什么不是转义为`\'`, 后续有机会展开分享)

#### JAVA 示例

##### 错误用法

```java
ProcessBuilder b = new ProcessBuilder("C:\DoStuff.exe -arg1 -arg2");
```

在本例中，命令和参数作为一个字符串传递，从而易于操作该表达式和注入的恶意字符串。 

##### 正确用法

下面时更正后的工作目录启动流程的示例。命令和每个参数分别传递。这使得验证每个术语变得容易，并降低了插入恶意字符串的风险。

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");
Map<String, String> env = pb.environment();
pb.directory(new File("TrustedDir"));
Process p = pb.start();
```

### 网络协议

 Web应用程序通常与网络守护进程（如SMTP、IMAP、FTP）通信，其中用户输入成为通信流的一部分。在这里，可以注入命令序列来滥用已建立的会话。 

## 防御注入的规则

### 规则 \#1 (执行正确的输入验证)

执行正确的输入验证。建议使用适当且规范化的“允许列表”(白名单)输入验证，注意，这**并不是一种完全的防御**，因为许多应用程序在其输入中需要特殊字符。

### 规则 \#2 (使用安全的API)

这儿安全的API，可以泛化理解使用安全的函数，比如使用预编译查询函数就比拼接的字符串查询安全 --[D]

首选安全的API，它完全避免直接使用解释器并提供参数化接口。小心某些API，例如存储过程，它们虽是参数化的，仍然可能在幕后引入注入问题。

### 规则\#3 (上下文转义用户数据)

如果参数化API不可用，则在使用该解释器之前对输入数据包含的特定转义语法和特殊字符进行仔细的转义。

## 其他注入速查表

[SQL Injection Prevention Cheat Sheet](SQL_Injection_Prevention_Cheat_Sheet.md)

[OS Command Injection Defense Cheat Sheet](OS_Command_Injection_Defense_Cheat_Sheet.md)

[LDAP Injection Prevention Cheat Sheet](LDAP_Injection_Prevention_Cheat_Sheet.md)

[Injection Prevention Cheat Sheet in Java](Injection_Prevention_in_Java_Cheat_Sheet.md)