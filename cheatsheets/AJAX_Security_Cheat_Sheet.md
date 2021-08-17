# AJAX 安全

## 介绍

本文作为AJAX安全知识的启动，有望在后面进行持续的更新和拓展，以便对特定AJAX框架和技术提供更详细的信息。

### 客户端 (JavaScript)

#### 使用.innerText 而非 .innerHtml

使用 `.innerText` 将阻止大部分的XSS问题，因为其会自动对文本进行编码.

> (D)注: 这儿应该是指HTML编码

#### 不要使用eval

`eval()` 函数是有害的，绝不应使用它。 当我们需要使用eval时，考虑下是不是你的设计存在问题。

#### 数据规范化 (read: 使用前进行编码)

当需要将数据用于构建HTML,script,CSS,XML.JSON,等内容时. 确保你考虑过数据必须表达出其本义并保持其逻辑意义

在以这种方式使用之前，数据应该被正确的编码，以防止注入样式等问题，并确保保留逻辑意义。

[Check out the OWASP Java Encoder Project.](https://owasp.org/www-project-java-encoder/)

#### 不依赖客户端的安全逻辑

似乎你忘记了，用户时可以控制客户端的逻辑的。我可以使用许多的浏览器插件去设置断点，代码跳过，数值变更，等等。不要依赖客户端的逻辑。

#### 不依赖客户端的业务逻辑

和上述安全逻辑一样，确保在服务端实现了真正的业务规则/逻辑，而不是让用户可以直接在客户端侧轻松的绕过逻辑检查以及做一些愚蠢，糟糕或代价高昂的事情。

#### 避免编写序列化的代码

实现起来很困难不是吗，而且一个小小的错误也可能导致严重的安全问题。好在已经有大量的框架来提供这一功能。

链接参阅 [JSON page](http://www.json.org/) 。

#### 避免动态的构建XML和JSON

就像构建HTML和SQL一样，你的构建可能导致XML注入的bug，所以请远离这种设计或尝试使用编码库、安全的JSON或XML库实现构建，以确保数据中属性和元素的安全。

- [XSS (Cross Site Scripting) Prevention](Cross_Site_Scripting_Prevention_Cheat_Sheet.md)
- [SQL Injection Prevention](SQL_Injection_Prevention_Cheat_Sheet.md)

#### 不要向客户端传递机密数据

客户端所能知道的任何数据，用户同样可以知道，所以请在服务端上保留所有这些机密的信息。

#### 不要在客户端代码实现加密

在服务器上使用TLS/SSL和加密！

#### 不要在客户端执行影响安全性的逻辑

安全是一个整体，如果你不想陷入麻烦中，我想你不会去破坏安全逻辑。

### 服务端

#### 使用CSRF防护

请参与 [Cross-Site Request Forgery (CSRF) Prevention](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)

#### 注意在就浏览器上防御JSON劫持

##### 回顾Angular JSON劫持防御机制

参阅AngularJS文档的[JSON Vulnerability Protection](https://docs.angularjs.org/api/ng/service/$http#json-vulnerability-protection)章节。

##### 返回的对象最外部始终为JSON结构

外部的原句为JSON字符对象:

**可利用的**

> (D)注: 最外部原句为list, 内部有JSON

```json
[{"object": "inside an array"}]
```

**不可利用的:**

> (D)注: 外部为JSON

```json
{"object": "not inside an array"}
```

**同样不可利用的:**

```json
{"result": [{"object": "inside an array"}]}
```

#### 避免在服务端上编写序列化代码

记住ref 与 value的类型! 确保对已引入的库进行了了审核

#### 用户可以直接调用服务

即使您只期望AJAX客户端代码可以调用对应的服务，但实际用户不借助AJAX客户端也可以调用这些服务。

确保你验证了输入，并将调用一视同仁，正因他们都属于用户控制下的使用方式。

#### 避免手工构建XML或是JSON，请使用框架

使用框架更加安全，手动操作容易存在安全问题

#### Webservices使用JSON和XML方案

您需要使用第三方库使得Webservices使用JSON和XML方案

