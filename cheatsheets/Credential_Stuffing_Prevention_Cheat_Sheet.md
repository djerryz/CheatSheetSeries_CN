# 防范凭证填充(撞库)

## 介绍 

本文涵盖了两种常见的针对身份认证相关的攻击防御方式，即凭证填充和密码喷洒。尽管这些攻击是独立的、不同的，但在许多情况下，为防范这些攻击而实施的防御措施是相同的，而且它们在防范暴力破解方面也是有效的。下面列出了这些不同攻击的概要：

| 攻击类型 | 描述 |
|-------------|-------------|
| 暴力破解 | 针对单个帐户测试字典或其他来源的多个密码。 |
| 凭证填充 | 测试从另一个网站的漏洞中获取的用户名/密码组。 |
| 密码喷洒 | 针对大量不同帐户测试单个弱密码。 |

> 注：
>
> 凭证填充中文常用撞库表示这类攻击
>
> 补充学习资料：
>
> https://www.cloudflare.com/zh-cn/learning/bots/what-is-credential-stuffing/

## 多因素认证

多因素身份验证（MFA）是迄今为止针对大多数密码相关攻击的最佳防御，包括凭证填充和密码喷洒，微软的分析表明，它可以阻止[99.9%的账户泄露](https://techcommunity.microsoft.com/t5/Azure-Active-Directory-Identity/Your-Pa-word-doesn-t-matter/ba-p/731984)。因此，应尽可能实施该计划；然而，根据应用程序的受众，强制使用MFA可能不实际或不可行。

为了平衡可用性和安全性，可以将多因素身份验证与其他技术相结合，以便仅在有理由怀疑是在不合法的特定情况下进行的登录尝试，才需要第二因素身份验证，例如来自：

- 新的浏览器/设备或IP地址.
- 不寻常的国家或地点.
- 被认为不受信任的特定国家/地区.
- 出现在已知禁用列表上的IP地址.
- 尝试登录到多个帐户的IP地址.
- 似乎是脚本化而非手动的登录尝试.

此外，对于企业应用程序，可以将已知的受信任IP范围添加到允许列表中，以便用户从这些范围连接时不需要MFA。 

## Alternative Defenses

Where it is not possible to implement MFA, there are many alternative defenses that can be used to protect against credential stuffing and password spraying. In isolation none of these are as effective as MFA, however if multiple defenses are implemented in a layered approach, they can provide a reasonable degree of protection. In many cases, these mechanisms will also protect against brute-force or password spraying attacks.

Where an application has multiple user roles, it may be appropriate to implement different defenses for different roles. For example, it may not be feasible to enforce MFA for all users, but it should be possible to require that all administrators use it.

### 辅助密码、PIN和安全问题

As well as requiring a user to enter their password when authenticating, they can also be prompted to provide additional security information such as:

- A PIN
- Specific characters from a secondary passwords or memorable word
- Answers to [security questions](Choosing_and_Using_Security_Questions_Cheat_Sheet.md)

It must be emphasised that this **does not** constitute multi-factor authentication (as both factors are the same - something you know). However, it can still provide a useful layer of protection against both credential stuffing and password spraying where proper MFA can't be implemented.

### 验证码

Requiring a user to solve a CAPTCHA for each login attempt can help to prevent automated login attempts, which would significantly slow down a credential stuffing or password spraying attack. However, CAPTCHAs are not perfect, and in many cases tools exist that can be used to break them with a reasonably high success rate.

To improve usability, it may be desirable to only require the user solve a CAPTCHA when the login request is considered suspicious, using the same criteria discussed above.

### IP禁用列表

Less sophisticated attacks will often use a relatively small number of IP addresses, which can be block-listed after a number of failed login attempts. These failures should be tracked separately to the per-user failures, which are intended to protect against brute-force attacks. The block list should be temporary, in order to reduce the likelihood of permanently blocking legitimate users.

Additionally, there are publicly available block lists of known bad IP addresses which are collected by websites such as [AbuseIPDB](https://www.abuseipdb.com) based on abuse reports from users.

Consider storing the last IP address which successfully logged in to each account, and if this IP address is added to a block list, then taking appropriate action such as locking the account and notifying the user, as it likely that their account has been compromised.

### 设备指纹

Aside from the IP address, there are a number of different factors that can be used to attempt to fingerprint a device. Some of these can be obtained passively by the server from the HTTP headers (particularly the "User-Agent" header), including:

- Operating system
- Browser
- Language

Using JavaScript it is possible to access far more information, such as:

- Screen resolution
- Installed fonts
- Installed browser plugins

Using these various attributes, it is possible to create a fingerprint of the device. This fingerprint can then be matched against any browser attempting to login to the account, and if it doesn't match then the user can be prompted for additional authentication. Many users will have multiple devices or browsers that they use, so it is not practical to block attempts that do not match the existing fingerprints.

The [fingerprintjs2](https://github.com/Valve/fingerprintjs2) JavaScript library can be used to carry out client-side fingerprinting.

It should be noted that as all this information is provided by the client, it can potentially be spoofed by an attacker. In some cases spoofing these attributes is trivial (such as the "User-Agent") header, but in other cases it may be more difficult to modify these attributes.

### 要求不可预测的用户名

Credential stuffing attacks rely on not just the re-use of passwords between multiple sites, but also the re-use of usernames. A significant number of websites use the email address as the username, and as most users will have a single email address they use for all their accounts, this makes the combination of an email address and password very effective for credential stuffing attacks.

Requiring users to create their own username when registering on the website makes it harder for an attacker to obtain valid username and password pairs for credential stuffing, as many of the available credential lists only include email addresses. Providing the user with a generated username can provide a higher degree of protection (as users are likely to choose the same username on most websites), but is user friendly. Additionally, care needs to be taken to ensure that the generated username is not predictable (such as being based on the user's full name, or sequential numeric IDs), as this could make enumerating valid usernames for a password spraying attack easier.

## 纵深防御

The following mechanisms are not sufficient to prevent credential stuffing or password spraying attacks; however they can be used to make the attacks more time consuming or technically difficult to implement. This can be useful to defend against opportunistic attackers, who use off-the-shelf tools and are likely to be discouraged by any technical barriers, but will not be sufficient against a more targeted attack.

### 多步骤登录过程

The majority of off-the-shelf tools are designed for a single step login process, where the credentials are POSTed to the server, and the response indicates whether or not the login attempt was successful. By adding additional steps to this process, such as requiring the username and password to be entered sequentially, or requiring that the user first obtains a random [CSRF Token](Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md) before they can login, this makes the attack slightly more difficult to perform, and doubles the number of requests that the attacker must make.

### 要求可执行Javascript并禁用Headless浏览器

Most tools used for these types of attacks will make direct POST requests to the server and read the responses, but will not download or execute JavaScript that was contained in them. By requiring the attacker to evaluate JavaScript in the response (for example to generate a valid token that must be submitted with the request), this forces the attacker to either use a real browser with an automation framework like Selenium or Headless Chrome, or to implement JavaScript parsing with another tool such as PhantomJS. Additionally, there are a number of techniques that can be used to identify [Headless Chrome](https://antoinevastel.com/bot%20detection/2018/01/17/detect-chrome-headless-v2.html) or [PhantomJS](https://blog.shapesecurity.com/2015/01/22/detecting-phantomjs-based-visitors/).

Please note that blocking visitors who have JavaScript disabled will reduce the accessibility of the website, especially to visitors who use screen readers. In certain jurisdictions this may be in breach of equalities legislation.

### 识别已泄露的密码 

When a user sets a new password on the application, as well as checking it against a list of known weak passwords, it can also be checked against passwords that have previously been breached. The most well known public service for this is [Pwned Passwords](https://haveibeenpwned.com/Passwords). You can host a copy of the application yourself, or use the [API](https://haveibeenpwned.com/API/v2#PwnedPasswords).

In order to protect the value of the source password being searched for, Pwned Passwords implements a [k-Anonymity model](https://en.wikipedia.org/wiki/K-anonymity) that allows a password to be searched for by partial hash. This allows the first 5 characters of a SHA-1 password hash to be passed to the API.

### 通知用户异常安全事件

When suspicious or unusual activity is detected, it may be appropriate to notify or warn the user. However, care should be taken that the user does not get overwhelmed with a large number of notifications that are not important to them, or they will just start to ignore or delete them.

For example, it would generally not be appropriate to notify a user that there had been an attempt to login to their account with an incorrect password. However, if there had been a login with the correct password, but which had then failed the subsequent MFA check, the user should be notified so that they can change their password.

Details related to current or recent logins should also be made visible to the user. For example, when they login to the application, the date, time and location of their previous login attempt could be displayed to them. Additionally, if the application supports concurrent sessions, the user should be able to view a list of all active sessions, and to terminate any other sessions that are not legitimate.

## 引用

- [OWASP Credential Stuffing Article](https://owasp.org/www-community/attacks/Credential_stuffing)
- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- Project: [OAT-008 Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing), which is one of 20 defined threats in the [OWASP Automated Threat Handbook](https://owasp.org/www-pdf-archive/Automated-threat-handbook.pdf) this project produced.