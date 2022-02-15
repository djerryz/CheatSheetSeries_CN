# 防范SQL注入

## 介绍

本文的重点是提供清晰、简单、可操作的指导，防止应用程序中的SQL注入缺陷.不幸的是，[SQL注入](https://owasp.org/www-community/attacks/SQL_Injection)攻击非常常见，这是由两个因素造成的：

1. SQL注入漏洞的显著流行([D] 可以理解为在互联网有大量的攻击资料以供学习)，以及 

2. 目标的吸引力（即数据库通常包含应用程序的所有有趣/关键数据）。 

有这么多成功的SQL注入攻击发生，这有点丢脸，因为在代码中避免SQL注入漏洞非常简单。

当软件开发人员创建动态数据库查询语句是包含了用户提供的输入，会引入SQL注入缺陷。避免SQL注入缺陷很简单。a）停止编写动态查询；和/或b) 防止包含恶意SQL语句的用户输入影响到原本的SQL查询语句的逻辑。

本文提供了一组简单的技术，通过避免这两个问题来防止SQL注入漏洞。这些技术实际上可以用于任何类型的数据库和任何编程语言。还有其他类型的数据库，比如XML数据库，它们可能有类似的问题（例如XPath和XQuery注入），这些技术也可以用来保护它们。

**主要防御:**

- **Option 1: 使用预编译 (参数化查询)**
- **Option 2: 存储过程的使用**
- **Option 3: 白名单验证输入**
- **Option 4: 转义所有用户提供的输入**

**补充防御:**

- **Also: 强制在最小权限下运行**
- **Also: 通过白名单对输入进行验证是一个辅助防御**
- ([D] WAF可以看成是一个黑名单的输入验证机制)

**不安全示例:**

SQL注入缺陷通常如下所示：

以下（Java）示例是不安全的，攻击者可以将代码注入数据库执行的查询语句中。未经验证的"customerName"参数被轻易的附加到查询中，攻击者可以通过该参数注入他们想要的任何SQL代码。不幸的是，这种访问数据库的方法太普遍了。

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = "
             + request.getParameter("customerName");
try {
    Statement statement = connection.createStatement( ... );
    ResultSet results = statement.executeQuery( query );
}
...
```

## 主要防御

### 防御选项 1: 预编译 (参数化查询)

使用带有变量绑定（又名参数化查询）的预处理语句是所有开发人员首先应该学习如何编写数据库查询的方式。它们编写简单，比动态查询更容易理解。参数化查询迫使开发人员首先定义所有SQL代码，然后将每个参数传递给查询。这种编码风格允许数据库区分代码和数据，而不管用户输入是什么。

预编译语句确保攻击者无法更改查询的意图，即使攻击者插入了SQL命令。在下面的安全示例中，如果攻击者输入用户名`tom'或'1'='1`，参数化查询将不会受到攻击，而是会查找与整个字符串`tom'或'1'='1`完全匹配的用户名。

针对具体语言的建议：

- Java EE – 将`PreparedStatement()`与绑定变量一起使用
- .NET – 使用预编译语句，如`SqlCommand()`或`OleDbCommand()`与绑定变量一起使用
- PHP – 强类型参数化查询下是PDO（使用bindParam()）
- Hibernate - 将`createQuery()`与绑定变量一起使用（在Hibernate中称为命名参数）
- SQLite - 使用`sqlite3_prepare()`创建 [statement object](http://www.sqlite.org/c3ref/stmt.html)

在极少数情况下，预编译可能损害到性能。遇到这种情况时，最好是a）强验证所有数据-白名单，或b）使用下面描述的特定于数据库供应商的转义方案转义所有用户提供的输入，而不是使用预编译。

**安全的JAVA预编译案例**:

下面的代码示例使用`PreparedStatement`,Java下一种参数化查询的实现，来执行等价的数据库查询操作。

```java
// This should REALLY be validated too
String custname = request.getParameter("customerName");
// Perform input validation to detect attacks
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname);
ResultSet results = pstmt.executeQuery( );
```

**安全的C\# .NET预编译案例**:

在.NET下，这更加简单。创建并执行查询语句的逻辑不会改变。只需使用`Parameters.Add()`将参数传递给查询语句即可，如图所示调用。

```csharp
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
try {
  OleDbCommand command = new OleDbCommand(query, connection);
  command.Parameters.Add(new OleDbParameter("customerName", CustomerName Name.Text));
  OleDbDataReader reader = command.ExecuteReader();
  // …
} catch (OleDbException se) {
  // error handling
}
```

我们已经展示了Java和.NET的相关示例，但实际上其他语言，包括Cold Fusion和经典的ASP，都支持参数化查询接口。甚至SQL抽象层，比如[Hibernate查询语言](http://hibernate.org/)（HQL）具有相同类型的注入问题（我们称之为[HQL注入](http://cwe.mitre.org/data/definitions/564.html)). HQL同样支持参数化查询，因此我们可以避免这个问题：

**Hibernate 查询语言 (HQL) 预编译 (命名参数) 案例**:

```java
//First is an unsafe HQL Statement
Query unsafeHQLQuery = session.createQuery("from Inventory where productID='"+userSuppliedParameter+"'");
//Here is a safe version of the same query using named parameters
Query safeHQLQuery = session.createQuery("from Inventory where productID=:productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter);
```

有关其他语言（包括Ruby、PHP、Cold Fusion和Perl）中的参数化查询示例，请参阅[参数化查询](./Query_Parameterization_Cheat_Sheet.md)或此[site](http://bobby-tables.com/).

开发人员倾向于喜欢预编译方法，因为所有的SQL代码都留在应用程序中。这使应用程序相对独立于数据库。

### 防御选项 2: 存储过程

存储过程并不总是安全的，不受SQL注入的影响。然而，某些标准存储过程编程结构在安全实现时与使用参数化查询具有相同的效果，这是大多数存储过程语言的标准。

它们要求开发人员只需使用自动参数化的参数构建SQL语句，除非开发人员做了一些很大程度上超出常规的事情。预处理语句和存储过程之间的区别在于，存储过程的SQL代码被定义并存储在数据库中，然后从应用程序中调用。这两种技术在防止SQL注入方面具有相同的效果，因此您的组织应该选择最适合您的方法。

注意：'安全实现'表示存储过程不包含任何不安全的动态SQL生成。开发人员通常不会在存储过程中生成动态SQL。然而，这是可以做到的，但应该避免。如果无法避免，存储过程必须使用本文所述的输入验证或正确转义，以确保所有用户提供给存储过程的输入不能用于将恶意的SQL代码注入到动态生成的查询语句。审核员应始终在SQL Server存储过程中查找sp_execute、execute或exec的用法。对于其他供应商的类似功能，需要类似的审核指南。

还有几种情况下，存储过程会增加风险。例如，在MS SQL server上，您有三个主要的默认角色：`db_datareader`、`db_datawriter`和`db_owner`。在存储过程开始使用之前，DBA会根据需要向Web服务的用户授予db_datareader或db_datawriter权限。但是，存储过程需要执行权限，默认情况下该角色不可用。在某些设置中，用户管理是集中的，但仅限于这3个角色，这会导致所有web应用都在db_owner 权限下运行，以便存储过程可以工作。当然，这意味着，如果服务器被破坏，攻击者对数据库拥有完全的权限，而以前他们可能只有读取权限。([D] 简单理解，即web应用实现存储过程可能需要更高的数据库权限，导致一旦web沦陷会获取到更高的权限的风险)

**安全的Java存储过程示例**:

下面的代码示例，Java使用存储过程的接口`CallableStatement`来执行相同的数据库查询。`sp_getAccountBalance`存储过程必须在数据库中预定义，以便实现与预期定义的查询达到相同的功能。

```java
// This should REALLY be validated
String custname = request.getParameter("customerName");
try {
  CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
  cs.setString(1, custname);
  ResultSet results = cs.executeQuery();
  // … result set handling
} catch (SQLException se) {
  // … logging and error handling
}
```

**安全的VB .NET存储过程示例**:

下面的代码示例使用.NET实现的存储过程接口`SqlCommand`，执行相同的数据库查询。`sp_getAccountBalance`存储过程必须在数据库中预定义，以便实现与预期定义的查询达到相同的功能。 

```vbnet
 Try
   Dim command As SqlCommand = new SqlCommand("sp_getAccountBalance", connection)
   command.CommandType = CommandType.StoredProcedure
   command.Parameters.Add(new SqlParameter("@CustomerName", CustomerName.Text))
   Dim reader As SqlDataReader = command.ExecuteReader()
   '...
 Catch se As SqlException
   'error handling
 End Try
```

### 防御选项 3: 白名单输入验证

SQL查询的各个部分都不是使用绑定变量的合法位置，例如表或列的名称，以及排序顺序指示符（ASC或DESC）。在这种情况下，输入验证或重新设计查询语句是最合适的防御措施。对于表或列的名称，理想情况下，这些值来自代码，而不是用户参数。


但是，如果用户参数值用于针对不同的表名和列名，那么参数值应该映射到合法/预期的表名或列名，以确保未经验证的用户输入不会出现在查询中。请注意，这是设计不佳的症状，如果时间允许，应考虑完全重写。


下面是一个表名验证的示例:

```text
String tableName;
switch(PARAM):
  case "Value1": tableName = "fooTable";
                 break;
  case "Value2": tableName = "barTable";
                 break;
  ...
  default      : throw new InputValidationException("unexpected value provided"
                                                  + " for table name");
```

 `tableName`可以直接附加到SQL查询中，因为现在已知它是该查询中表名的合法值和期望值之一。请记住，通用表验证函数可能会导致数据丢失，因为在不需要表名的查询中使用了表名。 ([D] 可以理解为，假如全部的输入都不经思索的套上通用的表验证函数，那么预期插入的值，可能被映射成了一个表名，导致预期的数据丢失)

对于排序顺序这样的简单操作，最好将用户提供的输入转换为布尔值，然后使用该布尔值选择要附加到查询的安全值。这是动态查询创建中非常标准的需求。 

例如:

```java
public String someMethod(boolean sortOrder) {
 String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");`
 ...
```

任何时候，用户输入都可以转换为非字符串，如日期、数字、布尔值、枚举类型等。在将其附加到查询或用于选择要附加到查询的值之前，这确保了这样做的安全性。

在所有情况下，输入验证都建议作为次要防御，即使在使用绑定变量时也是如此，本文稍后将对此进行讨论。有关如何实现强输入验证的更多技术，请参见[输入验证](./Input_Validation_Cheat_Sheet.md)。

### 防御选项 4: 转义用户所有的输入

只有在上述任何一项都不可行的情况下，这种技术才应作为最后手段使用。输入验证可能是一个更好的选择，因为与其他防御措施相比，这种方法很脆弱，我们不能保证它在所有情况下都会阻止所有SQL注入。

这种技术是在将用户输入放入查询之前对其进行转义。它的实现非常特定于数据库。通常，只有在实现输入验证不划算时，才建议改进遗留代码。从头开始构建的应用程序，或者需要低风险容忍度的应用程序，应该使用参数化查询、存储过程或为您构建对象关系映射器（ORM）来重构你的查询语句。

这种技术是这样工作的。每个DBMS 对于特定的查询语句类型 都支持一个或多个 字符转义方案 。使用正确的数据库转义方案转义所有用户提供的输入，DBMS将不会将该输入与开发人员编写的SQL代码混淆，从而避免任何可能的SQL注入漏洞。([D] 计算机没法区分内存上的数据是代码或是数据，需要一个边界来控制)


OWASP企业安全API（ESAPI）是一个免费、开源的web应用程序安全控制库，使程序员更容易编写低风险的应用程序。ESAPI库的设计目的是让程序员更容易在现有应用程序中改进安全性。ESAPI库也为新的发展奠定了坚实的基础：

- 有关细节 [ESAPI are available here on OWASP](https://owasp.org/www-project-enterprise-security-api/).
- javadoc: [ESAPI 2.x (Legacy) is available](http://www.javadoc.io/doc/org.owasp.esapi/esapi/2.1.0). 该代码于2014年11月迁移到GitHub。
- 当Javadoc似乎不够用时，[The legacy ESAPI for Java at GitHub](https://github.com/ESAPI/esapi-java-legacy)  帮助理解它的现有用途。
- [An attempt at another ESAPI for Java GitHub](https://github.com/ESAPI/esapi-java) 有其他方法，没有测试具体的编解码器。

要查找专门用于数据库编码器的javadoc，请单击左侧的`Codec`类,其实现了很多编解码器。两种特定于数据库的编解码器是`OracleCodec`和`MySQLCodec`。

只需在Codec页面顶部的`All Known Implementing Classes`中单击它们的名称。


目前，ESAPI拥有以下数据库编码器：

- Oracle
- MySQL (支持ANSI和原生方法)

数据库编码器即将推出：

- SQL Server
- PostgreSQL

如果您的数据库编码器丢失，请告知我们。

#### 特定于数据库的转义细节

如果您想构建自己的转义例程，以下是我们为每个数据库开发的ESAPI编码器的转义细节：

- Oracle
- SQL Server
- DB2

##### Oracle 转义

信息基于 [Oracle Escape character information](http://www.orafaq.com/wiki/SQL_FAQ#How_does_one_escape_special_characters_when_writing_SQL_queries.3F).

###### 转义动态查询

使用ESAPI数据库编解码器非常简单。Oracle的示例如下所示：

```java
ESAPI.encoder().encodeForSQL( new OracleCodec(), queryparam );
```

因此，如果您的代码中生成了一个现有的动态查询，该查询将发送到Oracle，如下所示：

```java
String query = "SELECT user_id FROM user_data WHERE user_name = '"
              + req.getParameter("userID")
              + "' and user_password = '" + req.getParameter("pwd") +"'";
try {
    Statement statement = connection.createStatement( … );
    ResultSet results = statement.executeQuery( query );
}
```

你可以重写第一行，如下所示：

```java
Codec ORACLE_CODEC = new OracleCodec();
String query = "SELECT user_id FROM user_data WHERE user_name = '"
+ ESAPI.encoder().encodeForSQL( ORACLE_CODEC, req.getParameter("userID"))
+ "' and user_password = '"
+ ESAPI.encoder().encodeForSQL( ORACLE_CODEC, req.getParameter("pwd")) +"'";
```

现在，无论提供什么输入，它都不会受到SQL注入的影响。为了获得最大的代码可读性，您还可以构建自己的`OracleEncoder`：

```java
Encoder oe = new OracleEncoder();
String query = "SELECT user_id FROM user_data WHERE user_name = '"
+ oe.encode( req.getParameter("userID")) + "' and user_password = '"
+ oe.encode( req.getParameter("pwd")) +"'";
```

使用这种类型的解决方案，只需将每个用户提供的参数封装到一个`ESAPI.encoder().encodeForOracle( )`调用或任何你命名的调用，你就会完成。

###### 关闭字符替换

使用`SET DEFINE OFF`或`SET SCAN OFF`确保自动字符替换已关闭。如果启用此字符替换，&字符将被视为SQLPlus变量前缀，攻击者可以通过该前缀检索私人数据。

参见[此处](https://docs.oracle.com/cd/B19306_01/server.102/b14357/ch12040.htm#i2698854)还有[这里](https://stackoverflow.com/a/410490)更多信息

###### 在Like子句中转义通配符

`LIKE`关键字允许进行文本扫描搜索。在Oracle中，下划线`_`字符只匹配一个字符，而符号`%`用于匹配任何字符的零次或多次出现。这些字符([D] 即_和%)必须在LIKE子句条件中转义。

例如:

```sql
SELECT name FROM emp WHERE id LIKE '%/_%' ESCAPE '/';

SELECT name FROM emp WHERE id LIKE '%\%%' ESCAPE '\';
```

###### Oracle 10g 转义

Oracle 10g及更高版本的另一种选择是在字符串周围放置`{`和`}`以转义整个字符串。但是，您必须注意字符串中没有`}`字符。您必须搜索这些，如果有，则必须将其替换为`}}`。否则，该字符将导致提前结束转义，并可能引入漏洞。 

##### MySQL 转义

Mysql支持两种转义方式:

1. `ANSI_QUOTES` SSQL模式，以及一个关闭的模式，我们称之为
2. `MySQL` 模式.

`ANSI SQL` 模式: 只是简单的将所有的`'`（单引号）字符编码为`''`（两个单引号）([D] 危险)

`MySQL` 模式, 做如下动作:

```text
NUL (0x00) --> \0  [This is a zero, not the letter O]
BS  (0x08) --> \b
TAB (0x09) --> \t
LF  (0x0a) --> \n
CR  (0x0d) --> \r
SUB (0x1a) --> \Z
"   (0x22) --> \"
%   (0x25) --> \%
'   (0x27) --> \'
\   (0x5c) --> \\
_   (0x5f) --> \_
all other non-alphanumeric characters with ASCII values
less than 256  --> \c where 'c' is the original non-alphanumeric character.
```

此信息基于 [MySQL Escape character information](https://dev.mysql.com/doc/refman/5.7/en/string-literals.html).

##### SQL Server 转义

我们还没有实现SQL Server转义例程，但下面有一些很好的链接，指向描述如何防止SQL Server上的SQL注入攻击的文章，请参见[此处](https://aka.ms/sql-injection). 

##### DB2 转义

此信息基于 [DB2 WebQuery special characters](https://www.ibm.com/support/pages/web-query-special-characters) 以及来自 [Oracle's JDBC DB2 driver](http://docs.oracle.com/cd/E12840_01/wls/docs103/jdbc_drivers/sqlescape.html).

关于几个 [DB2 Universal drivers](https://www.ibm.com/support/pages/db2-jdbc-driver-versions-and-downloads) 之间差异的信息

#### Hex编码所有输入

转义的一种特殊情况是对从用户处收到的整个字符串进行十六进制编码（这可以看作是对每个字符进行转义）。在将用户输入包含在SQL语句中之前，web应用程序应该对其进行十六进制编码。SQL语句应该考虑到这一事实，并相应地比较数据。


例如，如果我们必须查找与sessionID匹配的记录，并且用户传输字符串abc123作为会话ID，select语句将是：

```sql
SELECT ... FROM session WHERE hex_encode(sessionID) = '616263313233'
```

`hex_encode`  应替换为所用数据库的特定功能。字符串606162313233是从用户接收的字符串的十六进制编码版本（它是用户数据的ASCII/UTF-8代码的十六进制值序列）。 

如果攻击者在试图注入SQL代码后传输一个包含单引号字符的字符串，则构造的SQL语句只会如下所示： 

```sql
... WHERE hex_encode ( ... ) = '2720 ... '
```

`27`是单引号的ASCII码（十六进制），与字符串中的任何其他字符一样，它是简单的十六进制编码。生成的SQL只能包含数字和字母`a`到`f`，而不能包含任何可以造成SQL注入的特殊字符。([D] 补充一个利用到hex的mysql注入姿势: https://www.cnblogs.com/Mrsm1th/p/6842300.html)

#### 在PHP转义SQLi

使用预编译和参数化查询。这些SQL语句与任何参数分开发送到数据库服务器并由数据库服务器解析。这样，攻击者就不可能注入恶意SQL。 

你基本上有两个选择来实现这一点： 

1. 使用 [PDO](https://www.php.net/manual/en/book.pdo.php) (适用于任何受支持的数据库驱动程序):

```php
$stmt = $pdo->prepare('SELECT * FROM employees WHERE name = :name');
$stmt->execute(array('name' => $name));
foreach ($stmt as $row) {
    // do something with $row
}
```

2. 使用[MySQLi](https://www.php.net/manual/en/book.mysqli.php) (适用于MySql):

```php
$stmt = $dbConnection->prepare('SELECT * FROM employees WHERE name = ?');
$stmt->bind_param('s', $name);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    // do something with $row
}
```

PDO是通用选项。如果要连接到MySQL以外的数据库，可以参考特定于驱动程序的第二个选项（例如，PostgreSQL的pg_prepare()和pg_execute())。

## 补充防御

 除了采用四种主要防御措施中的一种，我们还建议采用所有这些额外防御措施，以便提供纵深防御。这些额外的防御措施包括： 

- **最小特权**
- **白名单输入验证**

### 最小特权

为了将成功的SQL注入攻击的潜在危害降至最低，您应该将分配给环境中每个数据库帐户的权限降至最低。不要为应用程序帐户分配DBA或管理员类型的访问权限。我们知道这很容易，当你这样做的时候，一切都会“起作用”，但这是非常危险的。


从头开始，确定你的应用程序帐户需要什么访问权限，而不是试图弄清楚你需要取消什么访问权限。确保只需要读取权限的帐户只被授予对其需要访问的表的读取权限。


如果帐户只需要访问表的某些部分，请考虑创建一个视图，该视图限制对该部分数据的访问，指定帐户访问权限到视图而不是对表。很少（如果有的话）授予对数据库帐户的创建或删除访问权限。


如果您采用的策略是在任何地方都使用存储过程，并且不允许应用程序帐户直接执行自己的查询，那么请将这些帐户限制为只能执行所需的存储过程。不要直接授予他们数据库中表的任何权限。


SQL注入并不是对数据库数据的唯一威胁。攻击者只需将参数值从其提供的合法值之一更改为未经授权的值，但应用程序本身可能有权访问。因此，最小化授予应用程序的权限将降低此类未经授权的访问尝试的可能性，即使攻击者没有试图将SQL注入作为其攻击的一部分。

当您使用它时，您应该最小化DBMS运行时所使用的操作系统帐户的权限。不要以root或system身份运行DBMS！大多数DBMS都有一个非常强大的系统帐户。例如，默认情况下，MySQL在Windows上作为系统运行！使用受限权限将DBMS的操作系统帐户更改为更合适的帐户。

#### 多个数据库用户

web应用程序的设计者应该避免在web应用程序中使用相同的owner/admin帐户来连接数据库。不同的DB用户应用于不同的web应用程序。 

通常，每个需要访问数据库的独立web应用程序都可以有一个指定的数据库用户帐户，web应用程序将使用该帐户连接到数据库。这样，应用程序的设计者可以在访问控制中拥有良好的粒度，从而尽可能减少权限。然后，每个数据库用户将有权选择只访问其需要的内容，并根据需要进行写访问。 

例如，登录页面需要对表的用户名和密码字段进行读取访问，但不需要任何形式的写入访问（不需要插入、更新或删除）。然而，注册页面当然需要该表的插入权限；只有当这些web应用使用不同的DB用户连接到数据库时，才能实施此限制。 

#### 视图

您可以使用SQL视图，通过将读取权限限制为表的特定字段或表的联接，进一步提高访问粒度。它可能还有其他好处：例如，假设系统需要（可能是由于某些特定的法律要求）存储用户的密码，而不是加盐的哈希密码。


设计师可以使用视图来弥补这一限制；撤销对表的所有访问（除了owner/admin之外的所有DB用户），并创建一个输出密码字段哈希而不是字段本身的视图。任何成功窃取数据库信息的SQL注入攻击都将被限制为窃取密码的散列（甚至可能是密钥散列），因为任何web应用程序的数据库用户都无权访问表本身。

### 白名单输入验证

在无法使用其他主要防御（例如，当绑定变量不合法时），输入验证还可以作为次要防御，用于在未经授权的输入被传递到SQL查询之前检测它。有关更多信息，请参阅[输入验证](./Input_Validation_Cheat_Sheet.md)。在这里要小心。通过字符串构建将验证数据插入SQL查询并不一定安全。

## 相关文章

**SQL Injection Attack Cheat Sheets**:

以下文章介绍了如何利用本文帮助您,避免各种平台上不同类型的SQL注入漏洞：

- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
- Bypassing WAF's with SQLi - [SQL Injection Bypassing WAF](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)

**SQL注入漏洞描述**:

- OWASP article on [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) Vulnerabilities
- OWASP article on [Blind_SQL_Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection) Vulnerabilities

**如何避免SQL注入漏洞**:

- [OWASP Developers Guide](https://github.com/OWASP/DevGuide) article on how to avoid SQL injection vulnerabilities
- OWASP Cheat Sheet that provides [numerous language specific examples of parameterized queries using both Prepared Statements and Stored Procedures](Query_Parameterization_Cheat_Sheet.md)
- [The Bobby Tables site (inspired by the XKCD webcomic) has numerous examples in different languages of parameterized Prepared Statements and Stored Procedures](http://bobby-tables.com/)

**如何检查SQL注入漏洞的代码**:

- [OWASP Code Review Guide](https://wiki.owasp.org/index.php/Category:OWASP_Code_Review_Project) article on how to [Review Code for SQL Injection](https://wiki.owasp.org/index.php/Reviewing_Code_for_SQL_Injection) Vulnerabilities

**如何测试SQL注入漏洞**:

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide) article on how to [Test for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html) Vulnerabilities