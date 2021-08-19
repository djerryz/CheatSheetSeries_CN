# 访问控制

## 介绍

本文的重点是提供清晰，简单，可操作的指导，用于提升应用程序在实现访问控制时的安全性。目标是在实现web程序的访问控制功能的设计，编码和运营阶段，去指导开发人员，审阅者，设计师和架构师等角色实现安全实践。

### 什么是授权?

授权是访问特定资源 的请求被授予或拒绝的过程。值得注意的是，授权不等同于身份认证 - 这些术语和定义常被混淆。认证是提供和验证身份的过程。授权包括用于确定用户(或主体) 可以访问哪些功能和数据的执行规则，以确保在认证成功后正确分配对应的权限。

可以概括为:
> 对于该**身份标识**，在该**时刻**，请求的**动作**是**被允许**的

其中:

- **身份标识 **用于保证当请求者发起请求时，可以通过质询挑战, 这意味着拥有身份标识者刚刚完成挑战/响应机制，并可以在身份方面佐证拥其所申明的身份。 If the challenge occurred before the request there is no assurance, acknowledging there may be a trusted session, but without assurance through via _challenge_ there can only be an unverified identity making this request
- **动作** The purpose for an authorization mechanism, a requester is attempting to perform an action that is sensitive, requires elevated privileges, or has some other implication like user privacy or _material_ impacts to the business.
- **被允许** means the identity has been checked for permission to perform the action, using Access Controls.
- **时刻** is extremely meaningful for the security characteristics of Authorization because it is the responsibility of the server to verify that the request is being processed _now_ and that is when the request was made. If it was made earlier being replayed now, or has been time skewed to a future time, the server should reject the request as it is not relevant to the current Authorization context.

### 什么是访问控制?

Web程序需要通过访问控制去允许用户(以不同的权限)去使用该应用。它们需要管理员去管理应用的访问控制规则和向用户或其他实体授予权限或权力。各种访问控制方案是可选的。要选择最合适的方案，需要执行风险评估以便识别您的应用下的威胁和脆弱性，从而找到适合您的应用的访问控制方案。

### 访问控制策略

为何需要在web开发中引入访问控制策略?

制定访问控制策略的目的是确保向架构师、设计师、开发人员和支持团队清楚地描述安全需求，以便以一致的方式设计和实现访问控制功能。 

### 基于角色的访问控制 (RBAC)

在基于角色的访问控制（RBAC）中，访问决策基于个人在组织或用户群中的角色和职责所确定。 

定义角色的过程通常基于分析组织的基本目标和结构，并且通常与安全策略相关联。 例如，在医疗组织中，用户可能存在许多不同的角色，包括医生，护士，服务员，患者等。这些成员需要不同级别的访问权限才能执行其功能，但web事务的类型及被允许的上下文也因安全策略和相关法规（HIPAA、Gramm-Leach-Bliley等）的不同而有很大差异。

该方案优点:

- 根据组织结构分配角色，重点是组织安全策略
- 易于使用
- 易于管理
- 内置于大多数框架中
- 与职责分离和最少特权等安全原则保持一致

此方案可能遇到的问题:

- 必须严格维护角色和访问的文档
- 除非有一种方法将角色与多租户功能需求（例如Active Directory中的OU）相关联，否则无法有效实施多租户
- 权限范围变化，比如，授予了比预期更多的访问和权限。或当未执行合适的访问审查和未及时撤销角色时，一个用户可能包含两个角色当中。
- 不支持基于数据的访问控制

使用 RBAC 的注意事项:

- 角色只能通过严格的签核步骤进行调整或委派.
- 当用户将其角色更改为另一个角色时，管理员必须确保撤销先前的访问权限，以便在任何给定时间点，用户只被分配给所需要的角色
- 必须通过严格的访问控制审查来保证RBAC

### 基于属性的访问控制 (ABAC)

在基于属性的访问控制（ABAC）中，访问决策基于请求主体的属性，而不是请求者所持有的身份标识。

Attributes come in various forms and are easiest summarized to be the metadata of data, rather than data itself. If you stored a user email the _attribute_ may be a reference to the database table in a relation database, or a primary key associated to the data that maps to the primary key of the identity in a key-value store or in disparate data stores, or another example is the index of a document store that holds the data.

许多现代的数据存储都提供了'label','tag',并实际上定义出元数据或头数据，可以通过RESTful API进行返回，这些都是很好的关于属性的例子。

该方案优点:

- 数据沿袭可被用于跟着原始访问来源或主要的真实访问来源 (亦可两者).
- 出于审计目的，简单的系统即可回答最难的数据访问问题. 谁可以或已经访问该数据?
- 通过身份标识访问数据并记录其属性时，可以实现抗否认性
- 属性能够实现非常高粒度和高水平的控制，可被灵活使用

此方案可能遇到的问题:

- 按照最低权限的原则设置特定的访问控制及策略的场景，通常对于ABAC而言，常会承担过度宽松策略，因为这种情况可能并阻力最小。
- 设置数据属性的开销，ABAC在实现时，常常会存在一组默认的，非常任意的属性，该属性应用于高级策略并广泛授予给用户。合适的ABAC在创建数据时会有适当对应的新数据属性,且默认的访问权限只分配给数据创建者，但这在某些模糊的情况下可能也不适用.问题关键在于，默认设置的级别通常高于安全所需的最低权限等场景

> 注: 某些模糊的情况下可能也不适用, 可能某些场景下，例如某A创建的数据，A对该数据没有权限，而只有A的管理者有读写权限，现实中A可能是一个数据桥梁?

使用 ABAC 的注意事项:

- Consider that good ABAC only works in scenarios where data is relatively static, or not frequently being created or changing in any way.
- ABAC works best when there are clear data owners who can permit others access to the data intentionally.
- Avoid starting ABAC when there is any chance new data can not be given a data owner to grant access, or when you find that data access defaults are overly permissive to excess of users or when the default attribute covers an excess of data.

### 基于组织的访问控制 (OrBAC)

For Organization-Based Access Control (OrBAC) to be relevant it is implied the access control policy spans many Organizations typical for a multi-tenant environment, where access decisions are based on an individual's express authorization to the target organization data because they are a member of a specific organization.

OrBAC is frequently confused with RBAC _because_ it's mechanism is semantically named 'Role' in many environments that inherit from Active Directory or newer cloud service providers that adopted the terminology of 'role'. For example if you work for a managed service provider and this gives you authority to the data of a client organization for the purposes of 'managing' it for the customer, or many customers, but you are not permitted the same authority for another specific customer. Then you may be using RoleA for CustomerA, RoleB for CustomerB, and a colleague uses RoleC for CustomerC but you cannot use RoleC.
This is OrBAC _not_ RBAC despite there being semantically named roles.

The advantages of using this methodology are:

- Purpose built solution for multi-tenant situations typical for professional services companies and managed service provider.
- Used in combination with other access control policy as an additional layer to provide customers with a level of trust and assurance.

Problems that can be encountered while using this methodology:

- When OrBAC is the only Access Control policy in place, it is far too overly permissive to be considered an appropriate security characteristic for Authorization purposes at the data access action, but completely appropriate for Authorization purposes to act on behalf of an organization without any specificity on what action can be permitted on the data at the stage or OrBAC decision.
- Certain limits may exist that means it is not feasible for all of the permitted customers to have their own 'Role' given to an individual that may actually be Authorized, so it is common in cases where customer number exceed the limitation for a new type of 'group of roles' to be used that span many organizations. When this occurs there is no longer any assurances that an individual organization can trust defeating the purpose of the OrBAC approach entirely

The areas of caution while using ABAC are:

- If you discover limitations that leads to groups of organizations to share a logical Authorization permission that can be granted, or decide to do so for usability reasons; you might not have any need for OrBAC because the benefit of OrBAC and the reason it exists is to provide individual assurance to the organizations being Authorized. Which cannot be assured when 2 or more organizations are bundled and shared together. Consider keeping your OrBAC strategy based on individual organizations and look to the second order access control strategy to solve the limitation or usability issues.

### 自主访问控制 (DAC)

Discretionary Access Control (DAC) is a means of restricting access to information based on the identity of users and/or membership in certain groups. Access decisions are typically based on the authorizations granted to a user based on the credentials they presented at the time of authentication (user name, password, hardware/software token, etc.). In most typical DAC models, the owner of the information or any resource can change its permissions at their discretion (thus the name).

A DAC framework can provide web application security administrators with the ability to implement fine-grained access control. This model can be a basis for data-based access control implementation

The advantages of using this model are:

- Easy to use
- Easy to administer
- Aligns to the principle of least privileges.
- Object owner has total control over access granted

Problems that can be encountered while using this methodology:

- Documentation of the roles and accesses has to be maintained stringently.
- Multi-tenancy can not be implemented effectively unless there is a way to associate the roles with multi-tenancy capability requirements, e.g. OU in Active Directory
- There is a tendency for scope creep to happen, e.g. more accesses and privileges can be given than intended for.

The areas of caution while using DAC are:

- While granting trusts
- Assurance for DAC must be carried out using strict access control reviews.

### 强制访问控制 (MAC)

Mandatory Access Control (MAC) ensures that the enforcement of organizational security policy does not rely on voluntary web application user compliance. MAC secures information by assigning sensitivity labels on information and comparing this to the level of sensitivity a user is operating at. MAC is usually appropriate for extremely secure systems, including multilevel secure military applications or mission-critical data applications.

The advantages of using this methodology are:

- Access to an object is based on the sensitivity of the object
- Access based on the need to know is strictly adhered to, and scope creep has minimal possibility
- Only an administrator can grant access

Problems that can be encountered while using this methodology:

- Difficult and expensive to implement
- Not agile

The areas of caution while using MAC are:

- Classification and sensitivity assignment at an appropriate and pragmatic level
- Assurance for MAC must be carried out to ensure that the classification of the objects is at the appropriate level.

### 基于权限的访问控制

The key concept in Permission Based Access Control is the abstraction of application actions into a set of *permissions*. A *permission* may be represented simply as a string-based name, for example, "READ". Access decisions are made by checking if the current user *has* the permission associated with the requested application action.

The *has* relationship between the user and permission may be satisfied by creating a direct relationship between the user and permission (called a *grant*), or an indirect one. In the indirect model, the permission *grant* is to an intermediate entity such as *user group*. A user is considered a member of a *user group* if and only if the user *inherits* permissions from the *user group*. The indirect model makes it easier to manage the permissions for a large number of users since changing the permissions assigned to the user group affects all members of the user group.

In some Permission Based Access Control systems that provide fine-grained domain object-level access control, permissions may be grouped into *classes*. In this model, it is assumed that each domain object in the system can be associated with a *class* which determines the permissions applicable to the respective domain object. In such a system a "DOCUMENT" class may be defined with the permissions "READ", "WRITE" and DELETE"; a "SERVER" class may be defined with the permissions "START", "STOP", and "REBOOT".