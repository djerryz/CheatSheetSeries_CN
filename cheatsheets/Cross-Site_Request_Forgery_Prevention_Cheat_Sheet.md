# 防范跨站请求伪造(CSRF)

> ([D] -- 2年前，参加阿里1面的时候对于CSRF的攻防相关询问的比较多，算是值得深入学习的一个知识点)

## 介绍

[跨站请求伪造(CSRF)](https://owasp.org/www-community/attacks/csrf)是当恶意网站、电子邮件、博客、即时消息或程序利用用户的web浏览器在受信任的网站上执行不必要的操作时，会发生的一种攻击。CSRF攻击之所以有效，是因为浏览器请求自动包含所有cookie，包括会话cookie。因此，如果用户通过了站点的身份验证，则站点无法区分合法授权请求和伪造请求。如果使用了适当的授权，则可以阻止此攻击，这意味着需要验证请求者身份和权限的质询响应机制。

成功的CSRF攻击的影响受限于应用程序暴露多少存在漏洞的功能接口和用户的权限。例如，此攻击可能导致资金转移、更改密码或使用用户凭据进行购买。实际上，CSRF攻击被攻击者用来让目标系统在受害者不知情的情况下通过受害者的浏览器执行功能，至少在未经授权的事务被提交之前是这样。

简言之，应对CSRF进行防护应遵循以下原则：

- **检查您的框架是否具有[内置CSRF保护](#use-built-in-or-existing-csrf-implementations-for-csrf-protection)，并使用它**
    - **如果框架没有内置的CSRF保护，则将[CSRF令牌](#token-based-mitigation)添加到所有状态变更请求（在站点上引起操作的请求）中，并在后端验证它们** 

- **对于有状态软件，请使用[同步器令牌模式](#synchronizer-token-pattern)**
- **对于无状态软件，请使用[双重提交Cookie](#double-submit-cookie)**
- **实施[纵深防御缓解措施](#defense-in-depth-techniques)部分中的至少一项缓解措施** 
    - **考虑会话Cookie的[SameSite Cookie属性](#samesite-cookie-attribute)** ，但注意不要专门为domain设置Cookie，因为这会引入一个安全漏洞，该域的所有子域都共享该Cookie。当子域具有不在您控制范围内的域的CNAME时，这尤其是一个问题。
    -  **考虑为高度敏感的操作实施[基于用户交互的保护](#user interaction-based csrf defense)**
    - **考虑[使用自定义请求标头](#use-of-custom-request-headers)** 
    - **考虑[用标准头验证origin](#verifying-origin-with-standard-headers)**
-  **请记住，任何跨站点脚本(XSS) 都可以用来击败所有CSRF缓解技术** 
    - **有关如何防止XSS缺陷的详细指导，请参阅OWASP [防范XSS](./Cross_Site_Scripting_Prevention_Cheat_Sheet.md)**

- **不要将GET请求用于状态更改操作**
    - **如果您出于任何原因这样做，请保护这些资源免受CSRF的影响** 

##  基于令牌的缓解措施

(synchronizer token pattern) [同步器令牌模式](#synchronizer-token-pattern)是缓解CSRF的最流行和推荐的方法之一。 

### 使用内置或现有的CSRF实现进行CSRF保护

同步器令牌防御已构建在许多框架中。强烈建议在尝试构建自定义令牌生成系统之前，研究您使用的框架是否具有默认实现CSRF保护的选项。例如，.NET具有[内置保护](https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-2.1)，其向CSRF脆弱资源添加令牌。在使用这些内置CSRF保护之前,您需要负责正确配置（如密钥管理和令牌管理）以便生成的令牌可以保护易受CSRF攻击的资源。

### Synchronizer Token Pattern(同步器令牌模式)

CSRF令牌应在服务器端生成。它们可以在每个用户会话或每个请求中生成一次。请求令牌比会话令牌更安全，因为攻击者可利用被盗令牌的有效时间范围最小。然而，这可能会导致可用性问题。例如，“后退”按钮浏览器功能经常受到阻碍，因为上一页可能包含不再有效的令牌。与上一页的交互将导致服务器上出现CSRF误报安全事件。会话令牌在初始生成该令牌后，该值便存储在会话中，并用于每个后续请求，直到会话过期。


当客户端发出请求时，服务器端组件必须验证请求中令牌的存在性和有效性，并与用户会话中找到的令牌进行比较。如果在请求中未找到令牌，或者提供的值与用户会话中的值不匹配，则应中止请求，终止用户会话，并将事件记录为正在进行的潜在CSRF攻击。

CSRF令牌应为：

* 每个用户会话都是唯一的。
* 秘密
* 不可预测 （由[安全方法](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#rule---use-cryptographically-secure-pseudo-random-number-generators-csprng)生成的大随机值）

CSRF令牌阻止CSRF，因为没有令牌，攻击者无法创建对后端服务器的有效请求。

**不应使用Cookie传输CSRF令牌.**

CSRF令牌可以通过隐藏字段、头添加，并且可以与表单和AJAX调用一起使用。确保令牌未泄漏到服务器日志或URL中。GET请求中的CSRF令牌可能在多个位置泄漏，例如浏览器历史记录、日志文件、记录HTTP请求第一行的网络设备，以及受保护站点链接到外部站点时的Referer头。

例如:

``` html
<form action="/transfer.do" method="post">
<input type="hidden" name="CSRFToken" value="OWY4NmQwODE4ODRjN2Q2NTlhMmZlYWEwYzU1YWQwMTVhM2JmNGYxYjJiMGI4MjJjZDE1ZDZMGYwMGEwOA==">
[...]
</form>
```

通过JavaScript在自定义HTTP请求头中插入CSRF令牌被认为比在隐藏字段表单参数中添加令牌更安全，因为它[使用自定义请求头](#use-of-custom-request-headers)。

### Double Submit Cookie (双重提交Cookie)

如果在服务器端维护CSRF令牌的状态有问题，另一种防御方法是使用双提交cookie技术。这种技术易于实现，并且是无状态的。在这种技术中，我们在cookie和请求参数中发送一个随机值，服务器验证cookie值和请求值是否匹配。当用户访问时（甚至在进行身份验证以防止登录CSRF之前），该站点应生成一个（密码安全的）伪随机值，并将其设置为用户机器上的cookie，与会话标识符分开。然后，站点要求每个事务请求都包含此伪随机值作为隐藏表单值（或其他请求参数/头）。如果两者在服务器端匹配，则服务器将其作为合法请求接受，如果两者不匹配，则会拒绝该请求。

由于子域可以向父域写入cookie，并且可以通过普通HTTP连接为域设置cookie，因此只要您确保子域完全安全并且只接受HTTPS连接，此技术就可以工作。


为了增强此解决方案的安全性，将令牌包含在加密的cookie中-而不是身份验证cookie（因为它们通常在子域中共享）-然后在服务器端将其与用于AJAX调用的隐藏表单字段或参数/头中的令牌进行匹配（在解密加密cookie之后）。这是因为如果没有必要的信息（如加密密钥），子域无法构造出加密后的cookie。


加密cookie的一个更简单的替代方案是使用只有服务器知道的密钥HMAC令牌，并将该值放入cookie中。这类似于加密cookie（两者都只需要服务器持有的知识），但计算强度低于加密和解密cookie。无论使用加密还是HMAC，攻击者都无法在不知道服务器机密的情况下从普通令牌重新创建cookie值。

## 纵深防御技术

### SameSite Cookie 属性

SameSite是一个cookie属性（类似于HTTPOnly、Secure等），旨在减轻CSRF攻击。其定义见[RFC6265bis](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7). 此属性帮助浏览器决定是否随跨站点请求一起发送Cookie。此属性的可能值为'Lax'、'Strict'或'None'。


严格的值将防止浏览器在所有跨站点浏览上下文中将cookie发送到目标站点，即使在访问常规链接时也是如此。例如，对于一个类似GitHub的网站，这意味着如果登录用户点击了公司论坛或电子邮件上发布的私人GitHub项目的链接，GitHub将无法收到会话cookie，用户将无法访问该项目。然而，银行网站不希望允许外部网站链接任何交易页面，因此严格的标志将是最合适的。

 维护用户登录会话的网站使用默认的Lax值，可以方便用户从外部链接到达后，提供安全性和可用性之间的合理平衡。在上述GitHub场景中，当跟踪来自外部网站的常规链接时，会话cookie将被允许，同时在易于CSRF的请求方法（如POST）中阻止它。只有在Lax模式下被允许的跨站点请求才具有顶级导航且被认为是[安全](https://tools.ietf.org/html/rfc7231#section-4.2.1)的HTTP方法。


有关`SameSite`值的更多详细信息，请从[rfc](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02)查看以下[部分](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1).


使用此属性的Cookie示例：

```text
Set-Cookie: JSESSIONID=xxxxx; SameSite=Strict
Set-Cookie: JSESSIONID=xxxxx; SameSite=Lax
```

现在，所有桌面浏览器和几乎所有移动浏览器都支持`SameSite`属性。要跟踪实现它的浏览器和属性的使用情况，请参阅以下[service](https://caniuse.com/#feat=same-site-cookie-attribute)。请注意，Chrome已经[宣布](https://blog.chromium.org/2019/10/developers-get-ready-for-new.html)他们将在Chrome 80上默认标记Cookie为`SameSite=Lax`（将于2020年2月开始），Firefox和Edge都计划效仿。此外，标记为`SameSite=None`的Cookie需要`安全`标志。


需要注意的是，该属性应作为一个附加层*深度防御*概念来实现。该属性通过支持它的浏览器保护用户，并包含以下[部分](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-02#section-5.3.7.1)中提到的两种绕过该属性的方法. 此属性不应取代具有CSRF令牌。相反，它应该与该令牌共存，以便以更稳健的方式保护用户。

### 通过标准头验证Origin

这种缓解有两个步骤，都依赖于检查HTTP请求头值。

1. 确定请求来自的来源（source origin）。可以通过Origin 或Referer 头完成。

2. 确定请求要去的源（target origin）。


在服务器端，我们验证两者是否匹配。如果他们这样做了，我们将该请求视为合法的（意味着它是同一来源的请求），如果他们不这样做，我们将丢弃该请求（意味着该请求来自跨域）。这些头的可靠性来自这样一个事实，即它们不能通过编程（使用带有XSS漏洞的JavaScript）进行更改，因为它们属于[禁止的头](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name)列表，这意味着只有浏览器才能设置它们

([D] 可以简单理解为通过Referer校验请求发起者，看是不是我们预期的发起者, 确实是不错的防御措施)

#### 识别 Source Origin (通过 Origin/Referer header)

##### 检查 Origin Header

如果存在Origin头，请验证其值是否与目标Origin匹配。与Referer不同，Origin头将出现在源自HTTPS URL的HTTP请求中。

##### 检查 Referer Header

如果不存在Origin头，请验证Referer标头中的主机名(host)是否与目标Origin匹配。这种CSRF缓解方法也通常用于未经验证的请求，例如在建立会话状态之前发出的请求，这是跟踪同步令牌所必需的。

在这两种情况下，请确保目标Origin检查很强。例如，如果您的站点是 `example.org` , 那么需要确保`example.org.attacker.com` 无法通过Origin检查（即，通过Origin的尾部/后面进行完整匹配，以确保与整个Origin匹配）。

如果这两个头都不存在，则可以接受或阻止请求。我们建议**阻止**。或者，您可能希望记录所有此类实例，监视它们的用例/行为，然后只有在获得足够的信心后才开始阻止请求。



#### 识别 Target Origin

您可能认为确定目标Origin很容易，但通常情况下并非如此。第一种想法是简单地从请求中的URL获取目标源（即，其主机名和端口`#`）。但是，应用程序服务器经常位于一个或多个代理之后，并且原始URL与应用程序服务器实际接收的URL不同。如果您的应用程序服务器由其用户直接访问，那么在URL中使用Origin就可以了，您已经准备好了。 

如果您支持代理，则有许多选项需要考虑。

* **将应用程序配置为只知道其目标origin**：它是您的应用程序，因此您可以找到其目标origin，并在某些服务器配置条目中设置该值。这将是最安全的方法，因为它是在服务器端定义的，所以它是一个可信的值。但是，如果您的应用程序部署在许多地方，例如开发、测试、QA、生产，以及可能的多个生产实例，则维护该应用程序可能会有问题。为这些情况中的每一种设置正确的值可能很困难，但如果您可以通过一些中心配置并提供实例从中获取值，那就太好了！（**注意**：确保集中配置存储安全维护，因为您的CSRF防御的主要部分依赖于它。）
* **使用Host 头值**：如果您希望应用程序找到自己的目标，这样就不必为每个部署的实例配置它，我们建议使用Host标头。Host 头的目的是包含请求的目标origin 。但是，如果您的应用程序服务器位于代理后面，则代理很可能会将主机头值更改为代理后面URL的目标origin ，这与原始URL不同。此修改的Host 头origin 与原始origin 或Referer 头中的origin 不匹配。
* **使用X-Forwarded-Host标头值**：为了避免代理更改Host头的问题，还有另一个标头称为X-Fordered-Host，其目的是包含代理收到的原始Host头值。大多数代理将在X-Forwarded-Host标头中传递原始Host头值。

当请求中存在origin 或referrer 头时，此缓解措施可以正常工作。虽然这些头在**大多数**时间都包含在内，很少有用例不包含它们（大多数是出于保护用户隐私/调整浏览器生态系统的正当原因）。以下列出了一些用例：

- Internet Explorer 11不会跨受信任区域的站点在CORS请求上添加Origin头。Referer标头将仍然是UI来源的唯一指示。
- 在[302 redirect cross-origin](https://stackoverflow.com/questions/22397072/are-there-any-browsers-that-set-the-origin-header-to-null-for-privacy-sensitiv)的实例中，Origin 不包括在重定向请求中，因为这可能被视为不应发送到其他源的敏感信息。
- 有一些[隐私上下文](https://wiki.mozilla.org/Security/Origin#Privacy-Sensitive_Context)会将Origin 设置为"null"，请参见下面的[此处](https://www.google.com/search?q=origin+header+sent+null+value+site%3Astackoverflow.com&oq=origin+header+sent+null+value+site%3Astackoverflow.com)
- 所有跨源请求都包含origin头，但对于同源请求，在大多数浏览器中，它仅包含在POST/DELETE/PUT中。**注意**：虽然不理想，但许多开发人员使用GET请求来执行状态更改操作。
- Referer头也不例外。也有多个用例省略了referer头（[1](https://stackoverflow.com/questions/6880659/in-what-cases-will-http-referer-be-empty), [2](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer), [3](https://en.wikipedia.org/wiki/HTTP_referer#Referer_hiding), [4](https://seclab.stanford.edu/websec/csrf/csrf.pdf)和[5](https://www.google.com/search?q=referrer+header+sent+null+value+site:stackoverflow.com)）。众所周知，负载均衡器、代理和嵌入式网络设备由于隐私原因，会剥离Referer头。

通常，一小部分流量属于上述类别([1-2%](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html))任何企业都不想失去这些流量。为了使这项技术更具可用性，互联网上使用的一种流行技术是，如果 Origin/referrer匹配您配置的域列表 "OR" 空值（示例[此处](http://homakov.blogspot.com/2012/04/playing-with-referer-origin-disquscom.html), 用于覆盖上述未发送这些标头的边缘情况），则接受请求。请注意，攻击者可以利用此漏洞进行攻击，但人们更喜欢使用此技术作为深度防御措施，因为部署此技术所需的工作量较小。

#### Cookie with __Host- prefix

这个问题的另一个解决方案是对带有CSRF令牌的Cookie使用`Cookie前缀`。如果cookie具有`__Host-`前缀，例如, `Set-Cookie: __Host-token=RANDOM; path=/; Secure` ,然后cookie：

* 无法从另一个子域写入。

* 必须具有路径`/`。

* 必须标记为安全（即，不能通过未加密的HTTP发送）。

截至2020年7月，cookie前缀[除Internet Explorer外，所有主要浏览器都支持](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Browser_compatibility).


请参阅[Mozilla开发者网络](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives)和[IETF草案](https://tools.ietf.org/html/draft-west-cookie-prefixes-05)有关cookie前缀的更多信息。

### 使用自定义请求头

添加CSRF令牌、双重提交cookie和值、加密令牌或涉及更改UI的其他防御通常会很复杂或有问题。另一种特别适合AJAX或API端点的防御方法是使用**自定义请求头**。这种防御依赖于[同源策略（SOP）](https://en.wikipedia.org/wiki/Same-origin_policy)限制只能使用JavaScript添加自定义标头，并且只能在其Origin下JS生效并使用。默认情况下，浏览器不允许JavaScript使用自定义头进行跨源请求。


如果您的系统是这种情况，您可以简单地验证所有服务器端AJAX端点上是否存在此头和值，以防止CSRF攻击。这种方法具有双重优势，通常不需要更改UI，也不引入任何服务器端状态，这对REST服务特别有吸引力。如果愿意，您可以随时添加自己的**自定义头**和值。


这种技术显然适用于AJAX调用，但您仍然需要使用本文中描述的方法（如令牌）来保护`<form>`标记。此外，CORS配置也应该是健壮的，以使此解决方案有效工作（因为来自其他域请求的自定义头会触发预检前的CORS检查）。

### 基于用户交互的CSRF防御

虽然这里提到的所有技术都不需要任何用户交互，但有时让用户参与交易以防止未经授权的操作（通过CSRF或其他方式伪造）更容易或更合适。以下是一些在正确实施时可作为强CSRF防御的技术示例。

* ~~重新验证~~授权机制（密码或更高级别）

* 一次性令牌

* 验证码（首选没有用户交互或视觉模式匹配的较新型的验证码）


虽然这些都是非常强大的CSRF防御，但它可以对用户体验产生重大影响。因此，它们通常仅用于安全关键操作（如密码更改、汇款等），以及本备忘单中讨论的其他防御措施。

## Login CSRF

大多数开发人员倾向于忽略登录表单上的CSRF漏洞，因为他们认为CSRF将不适用于登录表单，因为用户在该阶段没有经过身份验证，但是这种假设并不总是正确的。CSRF漏洞仍然可能出现在用户未经身份验证的登录表单上，但影响和风险不同。

例如，如果攻击者使用CSRF使用攻击者的账户使目标受害者的身份在购物网站上经过验证，然后受害者输入其信用卡信息，则攻击者可能能够使用受害者存储的卡片详细信息购买物品。有关登录CSRF和其他风险的更多信息，请参阅[本文](https://seclab.stanford.edu/websec/csrf/csrf.pdf)第3节。

登录CSRF可以通过创建预会话（用户经过身份验证之前的会话）并在登录表单中包含令牌来缓解。您可以使用上述任何技术生成令牌。请记住，一旦用户通过身份验证，预会话就不能转换为真实会话-应销毁会话，并创建新会话以避免[会话固定攻击](http://www.acrossecurity.com/papers/session_fixation.pdf),该技术在[跨站点请求伪造的鲁棒防御第4.1节](https://seclab.stanford.edu/websec/csrf/csrf.pdf)中进行了描述.

## Java 参考案例

下面是[JEE web筛选器](https://github.com/righettod/poc-csrf/blob/master/src/main/java/eu/righettod/poccsrf/filter/CSRFValidationFilter.java)为本备忘单中描述的一些概念提供了示例参考。它实现了以下无状态缓解措施（[OWASP.CSRFGuard](https://github.com/aramrami/OWASP-CSRFGuard)，覆盖有状态方法）。

* 使用标准头验证同一来源

* 双重提交cookie

* SameSite cookie属性

**请注意**它仅作为参考样本，并不完整（例如：当origin 和referrer 头检查成功时，它没有用于引导控制流的块，也没有用referrer 头的端口/主机/协议级验证）。建议开发人员在此参考示例的基础上构建完整的缓解措施。在检查CSRF是否有效之前，开发人员还应实现身份验证和授权机制。


完整来源位于[此处](https://github.com/righettod/poc-csrf)并提供可运行的POC。

## 自动将CSRF令牌包含为AJAX请求头的JavaScript指南

以下指南认为 **GET**, **HEAD** 和**OPTIONS** 方法是安全操作。因此，**GET**、**HEAD**和**OPTIONS**方法AJAX调用不需要附加CSRF令牌头。但是，如果谓词用于执行状态更改操作，则它们还需要CSRF令牌头（尽管这是一种不好的做法，应该避免）。

**POST**、**PUT**、**PATCH**和**DELETE**方法是状态更改谓词，应该在请求中附加一个CSRF令牌。下面的指南将演示如何在JavaScript库中创建重写，以便在上述状态更改方法的每个AJAX请求中自动包含CSRF令牌。

### 将CSRF令牌值存储在DOM中

CSRF令牌可以包含在`<meta>`标记中，如下所示。页面中的所有后续调用都可以从这个`<meta>`标记中提取CSRF令牌。它还可以存储在JavaScript变量中或DOM上的任何位置。但是，不建议将其存储在Cookie或浏览器本地存储中。


以下代码段可用于将CSRF令牌包含在`<meta>`标记中：

```html
<meta name="csrf-token" content="{{ csrf_token() }}">
```

填充content属性的确切语法取决于web应用程序的后端编程语言。

### 覆盖默认值并设置自定义头

几个JavaScript库允许覆盖默认设置，以便将自定义头自动添加到所有AJAX请求中。

#### XMLHttpRequest (JavaScript原生)

可以重写XMLHttpRequest的open() 方法，以便在下次调用`open() `方法时设置`anti-csrf-token`头。下面定义的函数`csrfSafeMethod()`将过滤掉安全的HTTP方法，并仅向不安全的HTTP方式添加头。


这可用如下代码段所示完成：

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");
    function csrfSafeMethod(method) {
        // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS)$/.test(method));
    }
    var o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(){
        var res = o.apply(this, arguments);
        var err = new Error();
        if (!csrfSafeMethod(arguments[0])) {
            this.setRequestHeader('anti-csrf-token', csrf_token);
        }
        return res;
    };
 </script>
```

#### AngularJS

AngularJS允许为HTTP操作设置默认头。更多文档可在AngularJS的[$httpProvider](https://docs.angularjs.org/api/ng/provider/)文档中找到。

```html
<script>
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    var app = angular.module("app", []);

    app.config(['$httpProvider', function ($httpProvider) {
        $httpProvider.defaults.headers.post["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.put["anti-csrf-token"] = csrf_token;
        $httpProvider.defaults.headers.patch["anti-csrf-token"] = csrf_token;
        // AngularJS does not create an object for DELETE and TRACE methods by default, and has to be manually created.
        $httpProvider.defaults.headers.delete = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
        $httpProvider.defaults.headers.trace = {
            "Content-Type" : "application/json;charset=utf-8",
            "anti-csrf-token" : csrf_token
        };
      }]);
 </script>
```

此代码段已在AngularJS版本1.7.7中进行了测试。

#### Axios

 [Axios](https://github.com/axios/axios)允许我们为POST、PUT、DELETE和PATCH操作设置默认头。 

```html
<script type="text/javascript">
    var csrf_token = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    axios.defaults.headers.post['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.put['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.delete['anti-csrf-token'] = csrf_token;
    axios.defaults.headers.patch['anti-csrf-token'] = csrf_token;

    // Axios does not create an object for TRACE method by default, and has to be created manually.
    axios.defaults.headers.trace = {}
    axios.defaults.headers.trace['anti-csrf-token'] = csrf_token
</script>
```

此代码段已在Axios版本0.18.0中进行了测试。

#### JQuery

JQuery公开了一个名为$.ajaxSetup()的函数，可用于将`anti-csrf-token`头添加到AJAX请求中。用于`$.ajaxSetup()`的文档可以在这里找到。下面定义的函数`csrfSafeMethod()`将过滤掉安全的HTTP方法，并仅向不安全的HTTP方式添加头。


通过采用以下代码段，可以将jQuery配置为自动将令牌添加到所有请求头中。这为基于AJAX的应用程序提供了简单方便的CSRF保护：

```html
<script type="text/javascript">
    var csrf_token = $('meta[name="csrf-token"]').attr('content');

    function csrfSafeMethod(method) {
        // these HTTP methods do not require CSRF protection
        return (/^(GET|HEAD|OPTIONS)$/.test(method));
    }

    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("anti-csrf-token", csrf_token);
            }
        }
    });
</script>
```

此代码段已使用jQuery版本3.3.1进行了测试。

## 引用

### CSRF

- [OWASP Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/csrf)
- [Mozilla Web Security Cheat Sheet](https://infosec.mozilla.org/guidelines/web_security#csrf-prevention)
- [Common CSRF Prevention Misconceptions](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/september/common-csrf-prevention-misconceptions/)
- [Robust Defenses for Cross-Site Request Forgery](https://seclab.stanford.edu/websec/csrf/csrf.pdf)
- For Java: OWASP [CSRF Guard](https://owasp.org/www-project-csrfguard/) or [Spring Security](https://docs.spring.io/spring-security/site/docs/5.5.x-SNAPSHOT/reference/html5/#csrf)
- For PHP and Apache: [CSRFProtector Project](https://owasp.org/www-project-csrfprotector/)
- For AngularJS: [Cross-Site Request Forgery (XSRF) Protection](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection)
