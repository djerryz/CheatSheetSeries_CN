# 防范基于DOM的XSS

## 介绍

在研究XSS（跨站点脚本）时，有三种公认的[XSS](https://owasp.org/www-community/attacks/xss/)形式:

- [反射或存储](https://owasp.org/www-community/attacks/xss/#stored-and-reflected-xss-attacks)
- [基于DOM的XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS).



[防范XSS备忘单](Cross_Site_Scripting_Prevention_Cheat_Sheet.md) 在解决反射和存储XSS方面做得很好。此备忘单针对基于DOM（文档对象模型）的XSS做了响应扩展。

为了理解基于DOM的XSS，我们需要看到反射式XSS、存储式XSS与基于DOM XSS之间的根本区别。主要区别在于在应用程序中攻击注入的位置不同。 

反射和存储XSS是服务器端注入问题，而基于DOM的XSS是客户端（浏览器）端注入问题。


要知道，所有这些代码都实际来源于服务器，这意味着无论XSS缺陷的类型如何，应用程序所有者都有责任确保其免受XSS攻击。此外，XSS攻击总是在浏览器中**执行**。

反射式/存储式XSS的区别在于将攻击载荷添加或注入应用程序的位置不同 ([D]反射可理解为每次请求响应中带入攻击载荷，而存储可理解为请求中的攻击载荷被持久化存储与程序，对于特定的请求均会携带攻击载荷于响应中)。使用Reflected/Stored，在服务器端处理请求时，将攻击载荷注入到应用程序中，这种不受信任的输入被动态添加到HTML中。对于DOM XSS，攻击直接注入到以客户端运行的应用程序。

当浏览器呈现HTML和任何其他相关内容（如CSS或JavaScript）时，它会为不同类型的输入匹配对应的渲染上下文，并且每个上下文遵循不同的规则。渲染上下文实际与HTML标记及其属性的解析相关。

- 渲染上下文的HTML解析器决定了数据在页面上的呈现和布局，并且可以进一步细分为HTML、HTML属性、URL和CSS的标准上下文。
- 执行上下文的JavaScript或VBScript解析器与脚本代码的解析和执行相关。每个解析器都有不同的、独立的语义，因为它们可能执行脚本代码，这使得在各种上下文中创建一致的规则来缓解漏洞变得困难。由于执行上下文中每个子文本（HTML、HTML属性、URL和CSS）中编码值的含义和处理方式不同，使得情况更为复杂。

在本文中，我们将HTML、HTML属性、URL和CSS上下文称为子文本，因为这些上下文中的每一个都可以实现在JavaScript上下文中执行访问和设置的动作。

在JavaScript代码中，主要上下文是JavaScript，但如果攻击者使用正确的标记和上下文结束字符，他可以尝试使用等效的JavaScript DOM方法攻击其他4个上下文。

以下是发生在JavaScript上下文和HTML子文本中的示例漏洞：

```html
 <script>
 var x = '<%= taintedVar %>';
 var d = document.createElement('div');
 d.innerHTML = x;
 document.body.appendChild(d);
 </script>
```

让我们依次查看执行上下文的各个子上下文。

## 规则 #1 - 在将不受信任的数据插入执行上下文中的HTML子文本之前，先进行HTML转义，然后进行JavaScript转义

有几种方法和属性可用于在JavaScript中直接呈现HTML内容。这些方法构成了可执行上下文中的HTML子文本。如果这些方法提供了不受信任的输入，则可能会导致XSS漏洞。例如：

### 案例-危险的HTML方法

#### 属性

```javascript
 element.innerHTML = "<HTML> Tags and markup";
 element.outerHTML = "<HTML> Tags and markup";
```

#### 方法

```javascript
 document.write("<HTML> Tags and markup");
 document.writeln("<HTML> Tags and markup");
```

### 解决方案

要使DOM中的HTML动态更新安全，我们建议：

 1. HTML编码，然后
 2. 对所有不可信输入进行JavaScript编码，如以下示例所示：

```javascript
 var ESAPI = require('node-esapi');
 element.innerHTML = "<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>";
 element.outerHTML = "<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>";
```

```javascript
 var ESAPI = require('node-esapi');
 document.write("<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>");
 document.writeln("<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTML(untrustedData))%>");
```

## 规则 \#2 - 在将不受信任的数据插入执行上下文中的HTML属性子文本之前，进行JavaScript转义

执行上下文中的HTML属性*子文本*与标准编码规则不同。在HTML属性渲染上下文中对HTML属性编码的规则是必要的，以缓解尝试逃逸出HTML属性或尝试添加其他可以到导致XSS的额外属性。


当您在DOM执行上下文中时，只需要对不执行代码的HTML属性（事件处理、CSS和URL属性以外的属性）进行JavaScript编码。

例如，一般规则是对不受信任的数据（来自数据库、HTTP请求、用户、后端系统等的数据）编码后放置于HTML属性中。这是在渲染上下文中输出数据时要采取的适当步骤，但是在执行上下文中使用HTML属性编码会破坏应用程序的数据显示。

### 案例 - SAFE but BROKEN

```javascript
 var ESAPI = require('node-esapi');
 var x = document.createElement("input");
 x.setAttribute("name", "company_name");
 // In the following line of code, companyName represents untrusted user input
 // The ESAPI.encoder().encodeForHTMLAttribute() is unnecessary and causes double-encoding
 x.setAttribute("value", '<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForHTMLAttribute(companyName))%>');
 var form1 = document.forms[0];
 form1.appendChild(x);
```

问题是，如果companyName的值为"Johnson & Johnson"。输入文本字段中显示的内容将是 “Johnson&amp；Johnson”。在上述情况下使用适当编码只是JavaScript编码，以防止攻击者关闭单引号和内衬代码，或逃到HTML并创建新的脚本标记。



### 案例 - SAFE and FUNCTIONALLY CORRECT

```javascript
 var ESAPI = require('node-esapi');
 var x = document.createElement("input");
 x.setAttribute("name", "company_name");
 x.setAttribute("value", '<%=ESAPI.encoder().encodeForJavascript(companyName)%>');
 var form1 = document.forms[0];
 form1.appendChild(x);
```

需要注意的是，当设置不执行代码的HTML属性时，该值被直接设置在HTML元素的属性中，因此不必担心注入。

 

## 规则 \#3 - 当在执行上下文中将不受信任的数据插入到事件处理程序和JavaScript代码子文本要注意

将动态数据放在JavaScript代码中尤其危险，因为与其他编码相比，JavaScript编码在处理数据相对于其他编码方式会具有不同的语义。在许多情况下，JavaScript编码不能阻止执行上下文中的攻击。例如，JavaScript编码的字符串即使是JavaScript编码的，也会执行。


因此，主要建议是**避免在此上下文中包含不受信任的数据**。如果您必须这样做，下面的示例描述了一些有效和无效的方法。

```javascript
var x = document.createElement("a");
x.href="#";
// In the line of code below, the encoded data on the right (the second argument to setAttribute)
// is an example of untrusted data that was properly JavaScript encoded but still executes.
x.setAttribute("onclick", "\u0061\u006c\u0065\u0072\u0074\u0028\u0032\u0032\u0029");
var y = document.createTextNode("Click To Test");
x.appendChild(y);
document.body.appendChild(x);
```

`setAttribute（name_string，value_string）`方法很危险，因为它隐式地将*value_string*转换为*name_string*的DOM属性数据类型。


在上面的例子中，属性名是一个JavaScript事件处理程序，因此属性值被隐式转换为JavaScript代码并执行。在上面的例子中，JavaScript编码不会减轻基于DOM的XSS的影响。

其他将代码作为字符串类型的JavaScript方法也会遇到类似的问题（“setTimeout”、“setInterval”、“new Function”等）。这与HTML标记（HTML解析器）的事件处理程序属性中的JavaScript编码形成鲜明对比，在HTML标记的情况下 JavaScript编码可以减轻XSS的影响，例如：

```html
<!-- Does NOT work  -->
<a id="bb" href="#" onclick="\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029"> Test Me</a>
```

相对于使用`Element.setAttribute（…）`设置DOM属性的另一种方法是直接设置属性。直接设置事件处理程序属性将允许JavaScript编码减轻基于DOM的XSS。请注意，将不受信任的数据直接放到命令执行上下文中总是危险的设计。

``` html
<a id="bb" href="#"> Test Me</a>
```

``` javascript
//The following does NOT work because the event handler is being set to a string.
//"alert(7)" is JavaScript encoded.
document.getElementById("bb").onclick = "\u0061\u006c\u0065\u0072\u0074\u0028\u0037\u0029";

//The following does NOT work because the event handler is being set to a string.
document.getElementById("bb").onmouseover = "testIt";

//The following does NOT work because of the encoded "(" and ")".
//"alert(77)" is JavaScript encoded.
document.getElementById("bb").onmouseover = \u0061\u006c\u0065\u0072\u0074\u0028\u0037\u0037\u0029;

//The following does NOT work because of the encoded ";".
//"testIt;testIt" is JavaScript encoded.
document.getElementById("bb").onmouseover = \u0074\u0065\u0073\u0074\u0049\u0074\u003b\u0074\u0065\u0073
                                            \u0074\u0049\u0074;

//The following DOES WORK because the encoded value is a valid variable name or function reference.
//"testIt" is JavaScript encoded
document.getElementById("bb").onmouseover = \u0074\u0065\u0073\u0074\u0049\u0074;

function testIt() {
   alert("I was called.");
}
```

JavaScript中还有其他地方接受JavaScript编码作为有效的可执行代码。

```javascript
 for(var \u0062=0; \u0062 < 10; \u0062++){
     \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
     .\u0077\u0072\u0069\u0074\u0065\u006c\u006e
     ("\u0048\u0065\u006c\u006c\u006f\u0020\u0057\u006f\u0072\u006c\u0064");
 }
 \u0077\u0069\u006e\u0064\u006f\u0077
 .\u0065\u0076\u0061\u006c
 \u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074
 .\u0077\u0072\u0069\u0074\u0065(111111111);
```

或

```javascript
 var s = "\u0065\u0076\u0061\u006c";
 var t = "\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0031\u0029";
 window[s](t);
```

因为JavaScript是基于国际标准（ECMAScript）的，所以除了替代字符串表示（字符串转义）之外，JavaScript编码还支持编程结构和变量中的国际字符。

然而，HTML编码的情况正好相反。HTML标记元素定义良好，不支持同一标记的替代表示。因此，不能使用HTML编码来允许开发人员使用`＜a＞`标记的替代表示。([D] 可以理解为 `<a>` 这个tag只能这么用，编码了再用就不会被当作html的tag元素！)

### HTML编码的解禁(Disarming)性质 HTML Encoding's Disarming Nature

通常，HTML编码用于修改放置在HTML和HTML属性上下文中的HTML标记。

工作示例（无HTML编码）：

```html
<a href="..." >
```

正常编码示例（不工作–DNW）：

```html
&#x3c;a href=... &#x3e;
```

HTML编码示例，以突出与JavaScript编码值（DNW）的根本区别：

```html
<&#x61; href=...>
```

如果HTML编码遵循与JavaScript编码相同的语义。上面的的代码即可用于渲染一条链接。这种差异使得JavaScript编码在我们对抗XSS的斗争中不太可行。

## 规则 \#4 - 将不受信任的数据插入执行上下文中的CSS属性子文本之前，进行JavaScript转义

通常，从CSS上下文执行JavaScript需要将`JavaScript:attackCode（）`传递给CSS的`url（）`方法或在CSS的`expression（）下直接构造出javascript代码。


根据我的经验，从执行上下文（JavaScript）调用`expression（）`函数已被禁用。为了减轻对CSS的`url（）`方法的影响，请确保您对传递给CSS`url（）`方法的数据进行了url编码。

```javascript
var ESAPI = require('node-esapi');
document.body.style.backgroundImage = "url(<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(companyName))%>)";
```

## 规则 \#5 - 在将不受信任的数据插入到执行上下文中的URL属性子文本之前，先进行URL转义，然后进行JavaScript转义

在执行和渲染上下文中解析URL的逻辑看起来是相同的。因此，执行（DOM）上下文中URL属性的编码规则几乎没有变化。

```javascript
var ESAPI = require('node-esapi');
var x = document.createElement("a");
x.setAttribute("href", '<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(userRelativePath))%>');
var y = document.createTextElement("Click Me To Test");
x.appendChild(y);
document.body.appendChild(x);
```

如果使用完整的URL，则这将导致链接无效，因为协议标识符（`http:`或`javascript:`）中的冒号将被URL编码，以防止调用`http`和`javascript`协议。

## 规则 \#6 - 使用安全的JavaScript函数或属性填充DOM

在不得不使用不受信任的数据填充DOM时，最基本的安全方法是使用安全赋值属性`textContent`。


下面是一个安全使用的示例。

```html
<script>
element.textContent = untrustedData;  //does not execute code
</script>
```

## 规则 \#7 - 修复DOM跨站点脚本漏洞

修复基于DOM的跨站点脚本的最佳方法是使用正确的输出方法（sink）。例如，如果要使用用户输入并写入到`div tag`下的元素，请不要使用`innerHtml`，而是使用`innerText`或`textContent`([D] 举个现实的例子，clash RCE问题的修复  [[AOH 011\]ClashForWindows RCE链 深析](https://mp.weixin.qq.com/s/5cv9KSRHUhsHxC7Yik1Rig))。这将解决基于DOM的XSS漏洞的正确方法。

**在危险源（如eval）中使用用户可控的输入总是一个坏主意。99%的情况下，这表明编程实践不好或懒惰，所以不要这样做，而是尝试净化输入**


最后，为了解决初始代码中的问题，我们可以简单地使用`element.textContent`输出内容，而不是总是试图选择一个正确的编码进行输出，这是一个麻烦且容易出错的问题。

```html
<b>Current URL:</b> <span id="contentholder"></span>
...
<script>
document.getElementById("contentholder").textContent = document.baseURI;
</script>
```

它做了同样的事情，但这次它不易受到基于DOM的跨站点脚本漏洞的攻击。



## 使用JavaScript开发安全应用程序的指南

基于DOM的XSS非常难以抵御，因为它的攻击面很大，而且浏览器之间缺乏标准化。


以下指南旨在为开发人员开发基于Web的JavaScript应用程序（Web 2.0）时提供指南，以避免XSS。



### 指南 \#1 - 不受信任的数据只能作为可显示的文本处理

避免将不受信任的数据视为JavaScript代码中的代码或标记。

### 指南 \#2 - 在构建模板化JavaScript时，始终将不受信任的数据用引号包裹为字符串进行JavaScript编码和定界

在输入应用程序时，始终使用JavaScript将不受信任的数据编码和分隔为带引号的字符串，如下例所示。

```javascript
var x = "<%= Encode.forJavaScript(untrustedData) %>";
```

### 指南 \#3 - 使用document.createElement（“…”）、element.setAttribute（“……”，“value”）、element.appendChild（…）和类似方法构建动态接口

`document.createElement("...")`, `element.setAttribute("...","value")`, `element.appendChild(...)` 和类似的是构建动态接口的安全方法。


请注意，`element.setAttribute`仅对有限数量的属性安全。


危险属性包括作为命令执行上下文的任何属性，如`onclick` or `onblur`.


安全属性的示例包括：`align`, `alink`, `alt`, `bgcolor`, `border`, `cellpadding`, `cellspacing`, `class`, `color`, `cols`, `colspan`, `coords`, `dir`, `face`, `height`, `hspace`, `ismap`, `lang`, `marginheight`, `marginwidth`, `multiple`, `nohref`, `noresize`, `noshade`, `nowrap`, `ref`, `rel`, `rev`, `rows`, `rowspan`, `scrolling`, `shape`, `span`, `summary`, `tabindex`, `title`, `usemap`, `valign`, `value`, `vlink`, `vspace`, `width`.

### 指南 \#4 - 避免将不受信任的数据发送到HTML渲染方法中

避免使用不受信任的数据填充以下方法。

1. `element.innerHTML = "...";`
2. `element.outerHTML = "...";`
3. `document.write(...);`
4. `document.writeln(...);`

### 指南 \#5 - 避免将数据传递给许多方法的隐式`eval()`下

确保传递给这些方法的任何不受信任的数据是：

1. 用字符串分隔符分隔

2. 包含在闭包中或基于使用情况采用N级的JavaScript编码

3. 包装在自定义函数中

请确保遵循上面的步骤3，以确保不受信任的数据不会发送到自定义函数中的危险方法，或者通过添加额外的编码层来处理它。



#### 使用闭包 (来自 Gaz 的建议)

下面的示例说明了使用闭包来避免双重JavaScript编码 （[D] 有点难以翻译与理解)

```javascript
 var ESAPI = require('node-esapi');
 setTimeout((function(param) { return function() {
          customFunction(param);
        }
 })("<%=ESAPI.encoder().encodeForJavascript(untrustedData)%>"), y);
```

另一种选择是使用N级编码。

#### N-级编码

代码如下所示，只需要对输入数据进行双重JavaScript编码。

```javascript
setTimeout("customFunction('<%=doubleJavaScriptEncodedData%>', y)");
function customFunction (firstName, lastName)
     alert("Hello" + firstName + " " + lastNam);
}
```

`doubleJavaScriptEncodedData`的第一层JavaScript编码（执行时）会反转单引号。


然后，`setTimeout`的隐式`eval`反转另一层JavaScript编码，将正确的值传递给`customFunction`

之所以只需要双层JavaScript编码，是因为`customFunction`函数本身没有将输入传递给另一个隐式或显式调用的`eval`方法。

如果将*firstName*传递给另一个显式或隐式调用`eval（）`的JavaScript方法，则需要将上面的`<%=doubleJavaScriptEncodedData%>`更改为`<%=tripleJavaScriptEncode Data%>`。


一个重要的实现注意事项是，如果JavaScript代码试图在字符串比较中使用双倍或三倍编码的数据，则该值可能会根据数据在传递到if比较之前经过的`eval（）`的数量以及该值被JavaScript编码的次数被解释为不同的值。


如果**A**是双JavaScript编码的，则下面的**If**检查将返回false。

``` javascript
 var x = "doubleJavaScriptEncodedA";  //\u005c\u0075\u0030\u0030\u0034\u0031
 if (x == "A") {
    alert("x is A");
 } else if (x == "\u0041") {
    alert("This is what pops");
 }
```

这引出了一个有趣的设计点。理想情况下，采用编码并避免上述问题的正确方法是为将数据带进应用程序的输出上下文进行服务器端编码。


然后客户端编码（使用JavaScript编码库，如[node-esapi](https://github.com/ESAPI/node-esapi/)）对于传递不可信数据的单个子文本（DOM方法）。


以下是如何使用它们的一些示例：

```javascript
//server-side encoding
var ESAPI = require('node-esapi');
var input = "<%=ESAPI.encoder().encodeForJavascript(untrustedData)%>";
```

```javascript
//HTML encoding is happening in JavaScript
var ESAPI = require('node-esapi');
document.writeln(ESAPI.encoder().encodeForHTML(input));
```

一种选择是利用JavaScript库中的ECMAScript 5不可变属性。

Gaz（Gareth）提供的另一个选项是使用特定的代码构造来限制匿名闭包的可变性。


示例如下：

```javascript
function escapeHTML(str) {
     str = str + "''";
     var out = "''";
     for(var i=0; i<str.length; i++) {
         if(str[i] === '<') {
             out += '&lt;';
         } else if(str[i] === '>') {
             out += '&gt;';
         } else if(str[i] === "'") {
             out += '&#39;';
         } else if(str[i] === '"') {
             out += '&quot;';
         } else {
             out += str[i];
         }
     }
     return out;
}
```

### 指南 \#6 - 仅在表达式的右侧使用不受信任的数据

仅在表达式的右侧使用不受信任的数据，尤其是看起来像代码并且可能传递给应用程序的数据（例如，`location` and `eval()`）。

```javascript
window[userDataOnLeftSide] = "userDataOnRightSide";
```

在表达式左侧使用不受信任的用户数据允许攻击者破坏window对象的内部和外部属性，而在表达式右侧使用用户输入则不允许直接操作该对象。



### 指南 \#7 - 在DOM中进行URL编码时，请注意字符集问题

当在DOM中进行URL编码时，请注意字符集问题，因为JavaScript DOM中的字符集没有明确定义（Mike Samuel）。



### 指南 \#8 - 使用对象\[x\]访问器时限制对对象属性的访问

使用`object[x]`访问器时，限制对对象属性的访问（Mike Samuel）。换句话说，在不受信任的输入和指定的对象属性之间添加一个间接级别。


以下是使用映射类型的问题示例：

```javascript
var myMapType = {};
myMapType[<%=untrustedData%>] = "moreUntrustedData";
```

编写上述代码的开发人员试图向`myMapType`对象添加其他键值元素。然而，攻击者可能会利用这一点来破坏`myMapType`对象的内部和外部属性。


更好的方法是使用以下方法：

```javascript
if (untrustedData === 'location') {
  myMapType.location = "moreUntrustedData";
}
```

### 指南 \#9 - 在ECMAScript 5 canopy或沙盒中运行JavaScript

在ECMAScript 5 [canopy](https://github.com/jcoglan/canopy) 或者沙盒中运行JavaScript，使JavaScript API更难被破坏（Gareth Heyes和John Stevens）。


一些JavaScript沙盒/sanitizers的示例：

- [js-xss](https://github.com/leizongmin/js-xss)
- [sanitize-html](https://github.com/apostrophecms/sanitize-html)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [MDN - HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API)
- [OWASP Summit 2011 - DOM Sandboxing](https://owasp.org/www-pdf-archive/OWASPSummit2011DOMSandboxingBrowserSecurityTrack.pdf)

### 指南 \#10 - 不要eval() JSON将其转换为原生JavaScript对象

不要使用`eval（）`JSON将其转换为原生JavaScript对象。而是使用`JSON.toJSON（）`和`JSON.parse（）`（Chris Schmidt）。



## 与减轻基于DOM的XSS相关的常见问题

### 复杂的上下文

在许多情况下，上下文并不总是很容易辨别。

```html
<a href="javascript:myFunction('<%=untrustedData%>', 'test');">Click Me</a>
 ...
<script>
Function myFunction (url,name) {
    window.location = url;
}
</script>
```

在上面的示例中，在渲染URL上下文（`a` tag的`href`属性）中, 一开始的不可信数据随后被JavaScript执行上下文（`JavaScript:`协议处理），该上下文将不可信数据传递给执行URL子文本（`myFunction`下的`window.location`）。

由于数据是在JavaScript代码中引入并传递给URL子文本的，因此适当的服务器端编码如下：

```html
<a href="javascript:myFunction('<%=ESAPI.encoder().encodeForJavascript(ESAPI.encoder().encodeForURL(untrustedData)) %>', 'test');">
Click Me</a>
 ...
```

或者，如果您将ECMAScript 5与JavaScript客户端编码库一起使用，则可以执行以下操作：

```html
<!-- server side URL encoding has been removed.  Now only JavaScript encoding on server side. -->
<a href="javascript:myFunction('<%=ESAPI.encoder().encodeForJavascript(untrustedData)%>', 'test');">Click Me</a>
 ...
<script>
Function myFunction (url,name) {
    var encodedURL = ESAPI.encoder().encodeForURL(url);  //URL encoding using client-side scripts
    window.location = encodedURL;
}
</script>
```

### 编码库的不一致性

有许多开源编码库：

1. OWASP [ESAPI](https://owasp.org/www-project-enterprise-security-api/)
2. OWASP [Java Encoder](https://owasp.org/www-project-java-encoder/)
3. Apache Commons Text [StringEscapeUtils](https://commons.apache.org/proper/commons-text/javadocs/api-release/org/apache/commons/text/StringEscapeUtils.html), replace one from [Apache Commons Lang3](https://commons.apache.org/proper/commons-lang/apidocs/org/apache/commons/lang3/StringEscapeUtils.html)
4. [Jtidy](http://jtidy.sourceforge.net/)
5. 您公司的自定义实现的编码库

一些人处理阻止列表，而另一些人忽略重要字符，如 "&lt;" 和"&gt;".


Java Encoder是一个活跃的项目，支持HTML、CSS和JavaScript编码。

ESAPI是少数在允许列表上工作并编码所有非字母数字字符的系统之一。重要的是使用一个编码库，该库可以了解哪些字符可以用于利用各自上下文中的漏洞。与所需的正确编码相关的误解比比皆是。



### 编码的错误概念

许多安全培训课程和论文提倡盲目使用HTML编码来解决XSS。


这在逻辑上似乎是一个谨慎的建议，因为JavaScript解析器不理解HTML编码。


但是，如果从web应用程序返回的页面使用content type为`text/xhtml`或文件类型扩展名`*.xhtml`,则HTML编码可能无法减轻XSS的影响。


例如：

```html
<script>
&#x61;lert(1);
</script>
```

上面的HTML编码值仍然可以执行。如果这还不足以记住，那么必须记住，当使用DOM元素的value属性检索编码时，编码会丢失。


让我们看一下示例页面和脚本：

```html
<form name="myForm" ...>
  <input type="text" name="lName" value="<%=ESAPI.encoder().encodeForHTML(last_name)%>">
 ...
</form>
<script>
  var x = document.myForm.lName.value;  //when the value is retrieved the encoding is reversed
  document.writeln(x);  //any code passed into lName is now executable.
</script>
```

最后还有一个问题，JavaScript中通常安全的某些方法在某些上下文中可能不安全。

### 通常安全的方法

一个被认为是安全的属性的例子是`innerText`。


一些论文或指南主张使用它作为`innerHTML`的替代品，以减轻`innerHTML`中的XSS。然而，根据应用`innerText`的标记，代码可以执行。

```html
<script>
 var tag = document.createElement("script");
 tag.innerText = "<%=untrustedData%>";  //executes code
</script>
```

`innerText`功能最初由Internet Explorer引入，在所有主要浏览器供应商采用后，于2016年在HTML标准中正式指定。 

### 使用变体分析检测DOM XSS

**漏洞代码:**

```
<script>
var x = location.hash.split("#")[1];
document.write(x);
</script>
```

用于识别上述dom xss的Semgrep规则[链接](https://semgrep.dev/s/we30).