# 忘记密码

## 介绍

为了实现完备的用户管理系统，系统常常集成有**忘记密码**服务，用于帮助用户重置密码。

尽管该功能看起来简单且容易实现，但其也是常见漏洞的来源，如著名的 [用户枚举攻击](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html)。

可快速参考以下用于保护忘记密码服务的简短指南:

- **为存在和不存在的帐户返回一致的消息。**
- **确保用户响应消息所用的时间是一致的。**
- **结合侧信道传达重置密码的方法。**
- **最简单、最快的实现可以使用 [URL令牌 ](#URL令牌)的方式。**
- **确保生成的令牌或代码是：**
    - **使用安全加密算法随机生成。**
    - **足够长以防止暴力攻击。**
    - **被安全存储。**
    - **一次性使用，并在适当期限后过期。**
- **除非给出有效令牌，在这之前不要变更用户状态(如锁定账号购买)**

> 注：侧信道如手机验证码

本文重点是关于重置用户密码。有关重置多因素身份验证(MFA)的指导，请参阅 [多因素认证](Multifactor_Authentication_Cheat_Sheet.md#resetting-mfa)。

## 忘记密码服务

 密码重置过程可分为两个主要步骤，在以下章节中详细介绍。 

### 忘记密码请求

当用户使用忘记密码服务并输入用户名或电子邮件时，应遵循以下步骤实施安全流程：

-  为存在和不存在的帐户返回一致的消息。 

- 确保响应在一致的时间内返回，以防止攻击者枚举存在的帐户。这可以通过使用异步调用或确保遵循相同的逻辑来实现，而不是使用快速退出方法。

  > 注: 类似于时间差分攻击， 无论是真或假分支尽量多走代码，而不是假分支直接就return返回，这样时间上会比真分支快很多

- 对于提交验证处实施保护，如对于验证码，实现速率限制或其他控制措施。

- 采用常用的安全措施，如 [防范SQL注入](SQL_Injection_Prevention_Cheat_Sheet.md) 和 [输入验证](Input_Validation_Cheat_Sheet.md)。

### 用户重置密码

一旦用户通过提供令牌（通过电子邮件发送）或 (短信)验证码（通过SMS或其他机制发送）证明其身份时，他们应将密码重置为新的安全密码。为确保这一步骤，应采取以下措施： 

- 用户应键入两次来确认他们想要设置的密码。
- 确保安全密码策略已实现，并且与应用程序的其余部分一致。
- 按照 [密码存储](Password_Storage_Cheat_Sheet.md) 更新并存储密码.
- 向用户发送电子邮件，通知他们密码已重置（不要将新密码通过电子邮件发送！）。
- 一旦他们设置了新密码，用户就应该通过正常的机制进行登录。不要自动登录用户，因为这会增加身份验证和会话处理代码的复杂性，并增加引入新漏洞的可能性。
- 询问用户是否要使所有现有会话无效，或自动使会话无效。

## 方法

为了允许用户请求密码重置，您需要有某种方法来识别用户，或者有一种方法通过侧通道与他们联系。

这可以通过以下任一方法完成：

- [URL令牌 ](#URL令牌)
- [PINs](#pins)
- [离线方法](#离线方法)
- [安全问题](#安全问题)

为了更大程度的保证，用户即其声称的用户，以上的方法可以搭配使用。无论如何，您必须确保用户始终有办法恢复他们的账户，即使需要通过联系到支撑团队并向团队证明其身份。

### 通用安全实践

必须为重置标识符（令牌、验证码、PIN等）采用良好的安全实践。 有些要点不适用于 [离线方法](#离线方法)，例如生存期限制。 所有的令牌，验证码应遵循:

- 选用密码学安全随机数生成器，参见 [存储加密](./cheatsheets/Cryptographic_Storage_Cheat_Sheet.md)。
    - 也可使用JWT代替随机令牌，尽管该算法可能引入额外的漏洞，具体情况参见[java下JWT算法](./cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.md)。
- 足够长以防止爆破攻击。
- 关联到数据库中的单个用户。
- 使用后失效。
-  以安全的方式存储，如 [密码存储](Password_Storage_Cheat_Sheet.md) 中所述。 

### URL令牌

URL令牌在URL的查询字符串中传递，通常通过电子邮件发送给用户。该过程概述如下： 

1. 向用户生成令牌并将其附加到URL查询字符串中。
2.  通过电子邮件将此令牌发送给用户。 
   - 不要创建依赖[Host](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host)头的重置链接，避免[Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)攻击。 URL应该是硬编码的，应该被验证属于受信任域名列表范围内的。 
   - 确保URL链接使用HTTPS.
3. 用户收到电子邮件，并浏览访问带有令牌的URL。
   - 确保重置密码页面通过 `noreferrer` 值添加[Referrer Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)标签，用于避免[referrer leakage](https://portswigger.net/kb/issues/00500400_cross-domain-referer-leakage)的情况.
   - 实施恰当的防护，以防止用户爆破URL下的令牌，例如请求速率限制等措施。
4. 若有必要，可以执行额外的验证步骤，例如要求用户回答[安全问题](#安全问题)
5. 用户创建新密码后需要二次确认。并确保实现了应用程序中其他地方所使用的相同密码策略。 

*注意:* URL令牌也可以参照[PINs](#pins)的过程用于创建一个受限会话状态。可以根据开发人员的需求和专业知识做出决定。

### PINs

PINs是通过侧通道（如SMS）发送给用户的数字（6到12位之间）。 

1. 生成一个PIN.
2. 通过SMS或其他机制将其发送给用户。
   -  用空格分隔PIN可以让用户更容易阅读和输入。 
3. 用户在密码重置页面上输入PIN及其用户名。
4. 该PIN创建一个仅允许用户重置密码的有限会话。
5. 用户创建新密码后需要二次确认。并确保实现了应用程序中其他地方所使用的相同密码策略。

> 注: 这儿和我们常用的短线找回还是有差异的，一般我们是先填写用户，找回填写手机，然后收到验证码，进行验证

### 离线方法

离线方法与其他方法不同，它允许用户重置密码，而无需从后端请求特殊标识符（如令牌或PIN）。然而，身份认证的过程仍然需要在后端进行以确保请求动作是合法的。离线方法是通过在注册，或用户想要配置该功能时，返回给用户的特定标识符。

该标识符应该脱机并以安全的方式存储(如密码管理器)，并且后端要正确的遵循[通用安全实践](#通用安全实践)。实现方式可以是通过[硬件OTP令牌](Multifactor_Authentication_Cheat_Sheet.md#硬件OTP令牌), [证书](Multifactor_Authentication_Cheat_Sheet.md#证书)，或其他适用于企业内部使用的方式。该内容不在本文讨论范围内。

> 注: 标识符即身份验证标识字符

#### 备份码

 注册后应向用户提供备份码，用户应将其离线存储在安全的地方（如密码管理器）。一些采用该方法的公司[Google](https://support.google.com/accounts/answer/1187538), [GitHub](https://help.github.com/en/github/authenticating-to-github/recovering-your-account-if-you-lose-your-2fa-credentials), and [Auth0](https://auth0.com/docs/mfa/guides/reset-user-mfa#recovery-codes).

在实施此方法时，应遵循以下实践：

- 最小长度为8位，12位，以提高安全性。
- 用户在任何给定的时间都应该有多个恢复码，以确保其中一个可以正常工作（大多数服务会提供给用户十个备份码）。
- 实现允许用户将被可能第三方窃取的恢复码设置为失效的功能。
- 应实施速率限制和其他保护，以防止攻击者爆破备份码。

### 安全问题

 安全问题不应被用作重置密码的唯一机制，因为它们的答案通常很容易被攻击者猜测或获得。但是，结合本文讨论的其他方法使用时，可以提供额外一层安全校验。当选择安全问题机制时，请确保安全问题的选用参考 [选用安全问题](./cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.md) 文章。

## 账户锁定

对于针对忘记密码的攻击，不该通过锁定用户的方式作为回应/防御，因为这可被用于针对已知的用户名造成拒绝访问。关于账户锁定，参考 [认证](Authentication_Cheat_Sheet.md) 。