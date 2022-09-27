# 防范XSS

## 介绍

本备忘单提供了防止XSS漏洞的指南。 

跨站点脚本（XSS）这个名称实际描述并不准确，该名称源于早期版本的攻击，其中跨站点窃取数据是攻击的主要焦点。从那时起，它已经扩展到包括基本上任何内容的注入，但我们仍然将其称为XSS。XSS很严重，可能导致帐户冒充、观察用户行为、加载外部内容、窃取敏感数据等。 

 **此备忘单列出了防止或限制XSS影响的技术。没有任何一种技术可以解决XSS问题。使用正确的防御技术组合是防止XSS的必要条件** 



## 框架安全

使用现代web框架构建的应用程序中出现的XSS错误更少。这些框架引导开发人员走向良好的安全实践，并通过使用模板、自动转义等方法帮助缓解XSS。也就是说，开发人员需要意识到在不安全地使用框架时可能出现的问题，例如：

* 框架用来直接操作DOM的 *逃生舱(escape hatches)* [D]关于逃生舱的相关介绍https://www.bilibili.com/video/av677410092/
* React下使用`dangerouslySetInnerHTML` ，传递未经清理的HTML内容
* React下未经专门验证的数据传递给 `javascript:` 或 `data:` 做为其URL部分
* Angular的 `bypassSecurityTrustAs*`函数 
* 模板注入 
* 过时的框架插件或组件 
* 以及更多 

了解您的框架是如何阻止XSS的，以及它在哪里存在差距。有时，您需要在框架提供的保护之外做一些事情。这就是输出编码和HTML Sanitization的关键所在。OWASP正在为React、Vue和Angular生成特定于框架的备忘单。



## XSS防御理念

要使XSS攻击成功，攻击者需要在网页中插入并执行恶意内容。web应用程序中的每个变量都需要保护。确保**所有变量**通过验证，然后进行转义或格式化，这就是所谓的抵制完美注入。任何不经过这个过程的变量都是一个潜在的弱点。框架确保变量正确验证、转义或清理变得容易。 

然而，框架并不完美，像React和Angular这样的流行框架中仍然存在安全漏洞。输出编码和HTML Sanitization有助于解决这些差距。 



## 输出编码

当您需要完全按照用户键入的数据安全显示数据时，建议使用输出编码。变量不应解释为代码而应是文本。本节介绍了每种形式的输出编码，在哪里使用它，以及在哪里避免完全使用动态变量。


当您希望在用户键入数据时显示数据时，首先使用框架的默认输出编码保护。大多数框架都内置了自动编码和转义函数。


如果您没有使用框架或需要弥补框架中的空白，那么应该使用输出编码库。用户界面中使用的每个变量都应该通过输出编码函数传递。附录中包含输出编码库列表。


有许多不同的输出编码方法，因为浏览器解析HTML、JS、URL和CSS的方式不同。使用错误的编码方法可能会带来缺陷或损害应用程序的功能。



### HTML Context的输出编码

“HTML Context”是指在两个基本HTML标记之间插入变量，如`<div>`或`<b>`。例如

```HTML
<div> $varUnsafe </div>
```

攻击者可以修改呈现为`$varUnsafe`的数据。例如，这可能导致在网页中加入攻击向量。

```HTML
<div> <script>alert`1`</script> </div> // Example Attack
```

为了安全地将变量添加到HTML上下文中，请在将该变量添加到web模板时对其使用HTML实体编码。


下面是一些特定字符的编码值示例。


如果使用JavaScript写入HTML，请查看`.textContent`属性，因为它是**安全Sink**，将自动进行HTML实体编码。

```HTML
&    &amp;
<    &lt;
>    &gt;
"    &quot;
'    &#x27;
```



### HTML Attribute Contexts的输出编码

“HTML Attribute Contexts”是指在HTML属性值中放置变量。您可能希望这样做来更改超链接、隐藏元素、为图像添加alt text或更改内联CSS样式。您应该对放置在大多数HTML属性中的变量实施对应HTML属性编码。**安全Sink**部分提供了安全HTML属性列表。

```HTML
<div attr="$varUnsafe">
<div attr=”*x” onblur=”alert(1)*”> // Example Attack
```

使用引号（如`"`"或`'`）来括住变量至关重要。引用会使更改变量操作的上下文变得困难，这有助于防止XSS。引用还会显著减少需要编码的字符集，使应用程序更可靠，编码更容易实现。

如果使用JavaScript写入HTML属性，请查看`.setAttribute`和`[attribute]`方法, 它们将自动进行HTML属性编码。只要属性名称是硬编码且无害的，例如`id`或`class`，这些就是**安全Sinks**。通常，接受JavaScript控制的属性（如`onClick`）接受了不受信任的属性值时是**不安全**的。



### JavaScript Contexts的输出编码

“JavaScript Contexts”是指将变量放入内联JavaScript，然后将其嵌入HTML文档中。这在大量使用嵌入自定义JavaScript的网站程序中很常见。


在JavaScript中放置变量的唯一“安全”位置是在“带引号的数据值”内。所有其他上下文都是不安全的，您不应该在其中放置变量数据。


“引用数据值”示例

```HTML
<script>alert('$varUnsafe’)</script>
<script>x=’$varUnsafe’</script>
<div onmouseover="'$varUnsafe'"</div>
```

使用`\xHH`格式对所有字符进行编码。编码库通常具有`EncodeForJavaScript`或类似代码来支持此函数。


请查看[OWASP Java Encoder JavaScript编码示例](https://owasp.org/www-project-java-encoder/)以获取正确JavaScript使用示例, 通过最少的编码行为。

对于JSON，请验证`Content-Type`头是`application/JSON`而不是`text/html`，以防止XSS。([D] 测试中常见的技巧)



### CSS Contexts的输出编码

“CSS Contexts”是指放置在内联CSS中的变量。当您希望用户能够自定义其网页的外观时，这种情况很常见。CSS功能惊人，已被用于多种类型的攻击。变量只能放在CSS属性值中。其他“CSS Contexts”是不安全的，您不应该在其中放置变量数据。

```HTML
<style> selector { property : $varUnsafe; } </style>
<style> selector { property : "$varUnsafe"; } </style>
<span style="property : $varUnsafe">Oh no</span>
```

如果您使用JavaScript更改CSS属性，请s使用`style.property = x`。这是一个**安全Sink**，将自动对其中的数据进行CSS编码。



### URL Contexts的输出编码

“URL Contexts”是指放置在URL中的变量。最常见的情况是，开发人员会将参数或URL fragment添加到URL构建中，然后在某些操作中显示或使用该URL。那么就需要对这些场景使用的URL编码。 

```HTML
<a href="http://www.owasp.org?test=$varUnsafe">link</a >
```

使用`%HH`编码格式对所有字符进行编码。确保所有属性都被完全引用，与JS和CSS相同。

#### 常见错误

在某些情况下，您会在不同的上下文中使用URL。最常见的是将其添加到`<a>`标记的`href`或`src`属性中。在这些场景中，您应该进行URL编码，然后进行HTML属性编码。

```HTML
url = "https://site.com?data=" + urlencode(parameter)
<a href='attributeEncode(url)'>link</a>
```

如果使用JavaScript构造URL查询值，请考虑使用`window.encodeURIComponent(x)`。这是一个**安全Sink**，将自动对其中的数据进行URL编码。 



### 危险Contexts

输出编码并不总是完美。它不会总是阻止XSS。这些情况被称为**危险Contexts**。危险上下文包括：

```HTML
<script>Directly in a script</script>
<!-- Inside an HTML comment -->
<style>Directly in CSS</style>
<div ToDefineAnAttribute=test />
<ToDefineATag href="/test" />
```

其他值得注意的地方:

- 函数调用
- 如在这样的CSS { background-url : “javascript:alert(xss)”; }代码中处理并过滤url
- 所有JavaScript事件处理程序（`onclick`、`onerror`和`onmouseover`）。
- 不安全的JS函数，如`eval`、`setInterval`和`setTimeout`

不要将变量放入危险的上下文中，即使使用输出编码，也无法完全防止XSS攻击。



## HTML Sanitization

有时用户需要编写HTML。一种方案是允许用户在所见即所得编辑器中更改内容的样式或结构。此处的输出编码将阻止XSS，但会破坏应用程序的预期功能。不会渲染样式。在这些情况下，应该使用HTML Sanitization。


HTML Sanitization将从变量中去除危险的HTML，并返回一个安全的HTML字符串。OWASP建议将[DOMPrify](https://github.com/cure53/DOMPurify)用于HTML Sanitization。

```js
let clean = DOMPurify.sanitize(dirty);
```

还有一些事情需要考虑：

* 如果您对内容进行清理，然后再进行修改，那您可真是大聪明

* 如果您对内容进行清理，然后将其发送到库以供使用，请检查它是否以某种方式改变了该字符串。否则，您的安全措施将再次无效。

* 您必须定期修补DOMPrify或您使用的其他HTML Sanitization库。浏览器功能变更，并定期发现是否有新增的绕过方式。



## 安全Sinks

安全专业人员经常谈论来sources和sinks。如果你污染了一条河流，它就会顺流而下。计算机安全也是如此。XSS sink是将变量放置到网页中的位置。


幸运的是，许多可以放置变量的sink都是安全的。这是因为这些sink将变量视为文本，永远不会执行它。尝试重构代码以删除对不安全sink（如innerHTML）的引用，而使用textContent或value。

```js
elem.textContent = dangerVariable;
elem.insertAdjacentText(dangerVariable);
elem.className = dangerVariable;
elem.setAttribute(safeName, dangerVariable);
formfield.value = dangerVariable;
document.createTextNode(dangerVariable);
document.createElement(dangerVariable);
elem.innerHTML = DOMPurify.sanitize(dangerVar);
```

**安全的HTML属性包括:** `align`, `alink`, `alt`, `bgcolor`, `border`, `cellpadding`, `cellspacing`, `class`, `color`, `cols`, `colspan`, `coords`, `dir`, `face`, `height`, `hspace`, `ismap`, `lang`, `marginheight`, `marginwidth`, `multiple`, `nohref`, `noresize`, `noshade`, `nowrap`, `ref`, `rel`, `rev`, `rows`, `rowspan`, `scrolling`, `shape`, `span`, `summary`, `tabindex`, `title`, `usemap`, `valign`, `value`, `vlink`, `vspace`, `width`.

全面列表，请查看 [DOMPurify allowlist](https://github.com/cure53/DOMPurify/blob/main/src/attrs.js)



## 其他控制措施

框架安全保护、输出编码和HTML Sanitization将为应用程序提供最佳保护。OWASP在所有情况下都建议这样做。

除上述内容外，考虑采用以下控制措施。

* Cookie属性-这些属性更改JavaScript和浏览器与Cookie的交互方式。Cookie属性试图限制XSS攻击的影响，但不会阻止恶意内容的执行或解决漏洞的根因。

* 内容安全策略-通过allowlist阻止加载内容。实现很容易出错，所以它不应该是您的主要防御机制。使用CSP作为额外的防御层，并查看[此处为cheatsheet](./Content_Security_Policy_Cheat_Sheet.html).

* Web应用程序防火墙-这些防火墙查找已知的攻击字符串并阻止它们。WAF不可靠，定期发现新的绕过技术。WAF也不能解决XSS漏洞的根因。此外，WAF还遗漏了一类专门操作客户端的XSS漏洞。不建议使用WAF来阻止XSS，尤其是基于DOM的XSS。



### XSS防御规则总结

以下HTML片段演示了如何在各种不同的上下文中安全地呈现不受信任的数据。

| 数据类型 | 上下文                           | 代码示例                                                     | 防御措施                                                     |
| -------- | -------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| String   | HTML Body                        | `<span>UNTRUSTED DATA </span>`                               | HTML实体编码 (rule \#1).                                     |
| String   | 安全的HTML 属性                  | `<input type="text" name="fname" value="UNTRUSTED DATA ">`   | 积极的HTML实体编码（规则\#2），仅将不受信任的数据放入安全的属性中，严格验证不安全属性，如background、ID和name |
| String   | GET 值                           | `<a href="/site/search?value=UNTRUSTED DATA ">clickme</a>`   | URL编码 (rule \#5).                                          |
| String   | 不可信的URL杯设置在SRC或HREF属性 | `<a href="UNTRUSTED URL ">clickme</a> <iframe src="UNTRUSTED URL " />` | 规范化输入、URL验证、安全URL验证、仅允许列出http和HTTPS URL（避免使用JavaScript协议打开新窗口）、属性编码器。 |
| String   | CSS 值                           | `HTML <div style="width: UNTRUSTED DATA ;">Selection</div>`  | 严格的结构验证（规则\#4），CSS十六进制编码，良好的CSS功能设计。 |
| String   | JavaScript 变量                  | `<script>var currentValue='UNTRUSTED DATA ';</script> <script>someFunction('UNTRUSTED DATA ');</script>` | 确保JavaScript变量被引用、JavaScript十六进制编码、JavaScript Unicode编码、避免反斜杠编码（`\"`或`\'`或`\\`） |
| HTML     | HTML Body                        | `<div>UNTRUSTED HTML</div>`                                  | HTML验证 (JSoup, AntiSamy, HTML Sanitizer...).               |
| String   | DOM XSS                          | `<script>document.write("UNTRUSTED INPUT: " + document.location.hash );<script/>` | [防范基于DOM的XSS](./DOM_based_XSS_Prevention_Cheat_Sheet.md) |



### 输出编码规则总结

输出编码的目的（因为它与跨站点脚本有关）是将不受信任的输入转换为安全形式，其中输入的数据将被显示为用户的**数据**，而不是杯浏览器执行为**代码**。下图详细列出了停止跨站点脚本所需的关键输出编码方法。

| 编码类型        | 编码机制                                                     |
| --------------- | ------------------------------------------------------------ |
| HTML 实体编码   | 将`&` 转换为`&amp;`, 将`<` 转换为`&lt;`, 将`>` 转换为 `&gt;`, 将`"` 转换为 `&quot;`, 将`'` 转换为 `&#x27;`, 将`/` 转换为`&#x2F;` |
| HTML 属性编码   | 除字母数字字符外，使用HTML实体对所有字符编码成类似`&#xHH；`的格式，包括空格。（**HH**=十六进制值） |
| URL 编码        | 标准百分比编码，请参见[此处](http://www.w3schools.com/tags/ref_urlencode.asp). URL编码只能用于编码参数值，而不能用于编码URL的整个URL或路径片段。 |
| JavaScript 编码 | 除字母数字字符外，使用`\uXXXX` 的unicode编码格式（**X**=整数）对所有字符进行编码。 |
| CSS Hex 编码    | CSS编码支持`\XX`和`\XXXXXX`。如果下一个字符继续编码序列，使用双字符编码可能会导致问题。有两种解决方案：（a）在CSS编码后添加空格（CSS解析器将忽略）（b）通过对值进行零填充来使用可能的全部CSS编码。 |



## 相关文章

**XSS Attack Cheat Sheet:**

The following article describes how to exploit different kinds of XSS Vulnerabilities that this article was created to help you avoid:

- OWASP: [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html).

**Description of XSS Vulnerabilities:**

- OWASP article on [XSS](https://owasp.org/www-community/attacks/xss/) Vulnerabilities.

**Discussion on the Types of XSS Vulnerabilities:**

- [Types of Cross-Site Scripting](https://owasp.org/www-community/Types_of_Cross-Site_Scripting).

**How to Review Code for Cross-site scripting Vulnerabilities:**

- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/) article on [Reviewing Code for Cross-site scripting](https://wiki.owasp.org/index.php/Reviewing_Code_for_Cross-site_scripting) Vulnerabilities.

**How to Test for Cross-site scripting Vulnerabilities:**

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) article on testing for Cross-Site Scripting vulnerabilities.
- [XSS Experimental Minimal Encoding Rules](https://wiki.owasp.org/index.php/XSS_Experimental_Minimal_Encoding_Rules)