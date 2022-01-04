# 未验证的重定向和转发

## 介绍

当web应用程序接受不受信任的输入时，可能会导致web应用程序将请求重定向到不受信任的的URL，实现未验证的重定向和转发。通过将站点重定向到不受信任的恶意URL，攻击者可以成功发起钓鱼欺诈并窃取用户凭据。


由于包含恶意URL的链接的域名与原始站点相同，因此从外观而言实现网络钓鱼会更可信。未经验证的重定向和转发攻击还可用于恶意访问URL，该URL将绕过应用程序的访问控制检查，然后将攻击者转发到他们通常无法访问的特权功能。

## 安全的URL重定向

当我们想要将用户自动的重定向到其他页面（没有访问者的动作，比如点击超链接），你通常可能按照如下的代码实现功能：

Java

```java
response.sendRedirect("http://www.mysite.com");
```

PHP

```php
<?php
/* Redirect browser */
header("Location: http://www.mysite.com");
/* Exit to prevent the rest of the code from executing */
exit;
?>
```

ASP .NET

```csharp
Response.Redirect("~/folder/Login.aspx")
```

Rails

```ruby
redirect_to login_path
```

在上面的案例中，URL正在代码中显式声明，攻击者无法对其进行操作。

## 危险的URL重定向

以下示例展示了不安全的重定向和转发的代码实现

### 危险重定向案例-1

下面的Java代码从名为“URL”的参数接收URL（[GET或POST](https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getParameter-java.lang.String-)）并重定向到该URL： 

```java
response.sendRedirect(request.getParameter("url"));
```

下面的PHP代码（通过名为“URL”的参数）从查询字符串中获取URL，然后将用户重定向到该URL。

此外,如果用户将浏览器配置为忽略重定向 ,`header()`函数后面的PHP代码将继续执行，因此他们可能能够访问页面的其余部分。([D] 即访问php剩下的代码逻辑，场景的场景就是鉴权失败要跳到登陆页，这儿通过忽略可以继续往下走逻辑，应该是表达这个意思)

```php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
```

C\# .NET 类似的漏洞代码:

```csharp
string url = request.QueryString["url"];
Response.Redirect(url);
```

Rails下:

```ruby
redirect_to params[:url]
```

如果没有验证或通过额外的控制方法来确认URL，则上述代码容易受到攻击。通过将用户重定向到恶意网站，此漏洞可被用作钓鱼欺诈的一部分。


如果未实现验证功能，恶意用户可能会创建超链接，将用户重定向到未验证的恶意网站，例如：

```text
 http://example.com/example.php?url=http://malicious.example.com
```

用户看到指向原始受信任站点（`example.com`）的链接，但没有意识到一个被接管的重定向正在发生

### 危险重定向案例-2

基于[ASP .NET MVC 1 & 2](https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/preventing-open-redirection-attacks)的站点，尤其容易受到开放重定向攻击。为了避免此漏洞，您需要使用MVC 3。

ASP.NET MVC 2 开发的应用程序通常有如下登录操作的代码， 如下所示。成功登录后，控制器返回到returnUrl的重定向。您可以看到，没有对returnUrl参数执行任何验证。

ASP.NET MVC 2 登录操作 在`AccountController.cs`（有关上下文，请参阅上面提供的Microsoft文档链接）：

```csharp
[HttpPost]
 public ActionResult LogOn(LogOnModel model, string returnUrl)
 {
   if (ModelState.IsValid)
   {
     if (MembershipService.ValidateUser(model.UserName, model.Password))
     {
       FormsService.SignIn(model.UserName, model.RememberMe);
       if (!String.IsNullOrEmpty(returnUrl))
       {
         return Redirect(returnUrl);
       }
       else
       {
         return RedirectToAction("Index", "Home");
       }
     }
     else
     {
       ModelState.AddModelError("", "The user name or password provided is incorrect.");
     }
   }

   // If we got this far, something failed, redisplay form
   return View(model);
 }
```

### 危险重定向案例-3

当应用程序允许用户在站点的不同部分之间自定义转发请求时，应用程序必须检查用户是否有权访问URL，确保是适当的URL请求，再执行转发功能。


如果应用程序未能执行这些检查，攻击者创建的URL可能会绕过应用程序的访问控制检查，然后将攻击者转发到通常不允许的管理功能。

例如:

```text
http://www.example.com/function.jsp?fwd=admin.jsp
```

下面的代码是一个Java servlet，它将接收一个`GET`请求，包含名为`fwd`的URL参数，并将请求重定向到该参数值对应的地址。

servlet [从请求中](https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getParameter-java.lang.String-) 获取参数值，并在响应浏览器之前完成服务端处理转发的过程。

```java
public class ForwardServlet extends HttpServlet
{
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
                    throws ServletException, IOException {
    String query = request.getQueryString();
    if (query.contains("fwd"))
    {
      String fwd = request.getParameter("fwd");
      try
      {
        request.getRequestDispatcher(fwd).forward(request, response);
      }
      catch (ServletException e)
      {
        e.printStackTrace();
      }
    }
  }
}
```

## 防范未验证的重定向和转发

安全的使用重定向和转发可以通过多种方式实现：

* 最简单的，避免使用重定向与转发
* 如果使用，尽量不允许URL被用户可控
* 在可能的情况下，让用户提供短名称、ID或令牌，并将其映射到服务器端对应的完整目标URL
  * 这提供了最高程度的保护，以防止篡改URL攻击
  * 请注意，这可能引入枚举漏洞，当用户通过循环查找所有可能的ID，发现对应的重定向目标 ([D] 原文是不会引入，我的尝试是没有实现IDOR防御则会引入)
* 如果无法避免用户输入，请确保提供的**值**有效、适用于应用程序，并且对用户**授权**。
* 通过创建受信任URL列表（主机列表或正则表达式）来清理输入。
  * 这应该基于白名单方法，而不是黑名单。
* 强制所有重定向之前通过一个页面，通知用户他们将离开您的站点，并清楚显示目的地，然后让他们单击一个链接进行确认。

### 验证URLs

验证和清理用户输入以确定URL是否安全不是一项简单的任务。关于如何实现URL验证的详细说明，请参见 [in Server Side Request Forgery Prevention Cheat Sheet](Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md#application-layer)

## 参考

- [CWE Entry 601 on Open Redirects](http://cwe.mitre.org/data/definitions/601.html).
- [WASC Article on URL Redirector Abuse](http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse)
- [Google blog article on the dangers of open redirects](http://googlewebmastercentral.blogspot.com/2009/01/open-redirect-urls-is-your-site-being.html).
- [Preventing Open Redirection Attacks (C\#)](http://www.asp.net/mvc/tutorials/security/preventing-open-redirection-attacks).