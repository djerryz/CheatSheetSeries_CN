# 反序列化

## 介绍

 本文的重点是 为安全地反序列化应用程序中不受信任的数据 提供清晰、可操作的指导。

## 什么是反序列化

**序列化** 是将某个对象转换为数据格式的过程，以后可以恢复。人们经常序列化对象，以便将其保存到存储器中，或作为通信的一部分发送。

**反序列化** 与此相反，从某种格式获取结构化数据，并将其重建为对象。如今，序列化数据最流行的数据格式是JSON。在此之前，它是XML。

然而，许多编程语言提供了序列化对象的原生机制。这些原生格式通常比JSON或XML提供更多功能，包括序列化过程的可定制性。

不幸的是，在对不受信任的数据进行操作时，这些原生反序列化机制的功能可能会被重用于实现恶意功能。已发现针对反序列化程序的攻击允许拒绝服务、访问控制和远程代码执行（RCE）攻击。

## 关于安全地反序列化对象的指导

以下特定于语言的指南试图列举用于反序列化不可信数据的安全方法。

### PHP

#### 白盒审计

审计unserialize()的使用情况，并检查是如何接受外部参数的。如果需要将序列化数据传递给用户，请使用安全的标准数据交换格式，如JSON（通过`json_decode()`和`json_encode()`）。

### Python

#### 黑盒审计

如果数据流量的最后包含符号点`.`，数据很可能是以序列化的方式发送的。

#### 白盒审计

Python中的以下API易受序列化攻击，按照如下模板检索代码：

1. `pickle/c_pickle/_pickle` 配合`load/loads`使用:

```python
import pickle
data = """ cos.system(S'dir')tR. """
pickle.loads(data)
```

2. `PyYAML` 配合`load`使用:

```python
import yaml
document = "!!python/object/apply:os.system ['ipconfig']"
print(yaml.load(document))
```

3. `jsonpickle` 配合`encode` 或`store` 方法使用.

### Java

以下技术都有助于防止针对[Java序列化格式](https://docs.oracle.com/javase/7/docs/api/java/io/Serializable.html)的反序列化攻击。

实施建议：

- 在代码中，重写`ObjectInputStream#resolveClass()`方法以防止反序列化任意类。这种安全行为可以封装在像[SerialKiller](https://github.com/ikkisoft/SerialKiller)这样的库中.
- 使用安全函数替换通用的`readObject()`方法的使用。请注意，通过检查输入长度和反序列化对象的数量来解决"[billion laughs](https://en.wikipedia.org/wiki/Billion_laughs_attack)" 类型的攻击。

#### 白盒审计

请注意以下Java API存在潜在的序列化漏洞。

1. `XMLdecoder` 使用外部用户定义的参数

2. `XStream` 配合`fromXML` 方法(xstream version <= v1.46 易受序列化问题的影响)

3. `ObjectInputStream` 配合`readObject`

4. 使用`readObject`, `readObjectNodData`, `readResolve` 或`readExternal`

5. `ObjectInputStream.readUnshared`

6. `Serializable`

#### 黑盒审计

如果捕获的流量数据包括以下模式，则可能表明数据是在Java序列化流中发送的

- Hex包含`AC ED 00 05`
- Base64编码包含`rO0` 
- HTTP响应头的`Content-type` 为 `application/x-java-serialized-object`

#### 防止数据泄漏及受信任的字段破坏

如果某个对象的数据成员在反序列化过程中不应由最终用户控制，或在序列化过程中不应向用户公开，则应将其声明为[`transient`关键字](https://docs.oracle.com/javase/7/docs/platform/serialization/spec/serial-arch.html#7231)（*保护敏感信息*章节）。

对于定义为可序列化的类，敏感信息变量应声明为`private transient`。

例如，myAccount类、变量`profit`和`margin`被声明为transient，以避免序列化：

```java
public class myAccount implements Serializable
{
    private transient double profit; // declared transient

    private transient double margin; // declared transient
    ....
```

#### 防止domain对象的反序列化

由于层次结构的原因，一些应用程序对象可能会被迫实现可序列化。为了保证应用程序对象不能被反序列化，应该声明一个`readObject()`方法（带有`final`修饰符），该方法可以抛出异常：

```java
private final void readObject(ObjectInputStream in) throws java.io.IOException {
    throw new java.io.IOException("Cannot be deserialized");
}
```

#### 强化自己的java.io.ObjectInputStream

`java.io.ObjectInputStream` 类用于反序列化对象，通过将其子类化，可以强化其行为。这是最好的解决方案，如果：

* 您可以更改执行反序列化的代码

* 你知道你希望反序列化什么类

一般的想法是重写 [`ObjectInputStream.html#resolveClass()`](http://docs.oracle.com/javase/7/docs/api/java/io/ObjectInputStream.html#resolveClass(java.io.ObjectStreamClass))， 以便限制允许反序列化的类。

由于此调用发生在调用`readObject()`之前，因此可以确保不会发生反序列化活动，除非该类型是您希望允许的类型。

这里展示了一个简单的例子，`LookAheadObjectInputStream`类保证不会反序列化除`Bicycle`类之外的任何其他类型：

```java
public class LookAheadObjectInputStream extends ObjectInputStream {

    public LookAheadObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /**
    * Only deserialize instances of our expected Bicycle class
    */
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!desc.getName().equals(Bicycle.class.getName())) {
            throw new InvalidClassException("Unauthorized deserialization attempt", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

各种社区成员已经提出了这种方法的更完整实施方案：

- [NibbleSec](https://github.com/ikkisoft/SerialKiller) - 创建允许反序列化的类列表的库
- [IBM](https://www.ibm.com/developerworks/library/se-lookahead/) - 在设想最具破坏性的场景之前的几年，写下的种子保护 ([D] 不好理解)
- [Apache Commons IO classes](https://commons.apache.org/proper/commons-io/javadocs/api-2.5/org/apache/commons/io/serialization/ValidatingObjectInputStream.html)

#### 使用 Agent 强化全部 java.io.ObjectInputStream 

如前所述， `java.io.ObjectInputStream`类用于反序列化对象。通过将其子类化，可以强化其行为。

然而，如果你没有代码或者等不来补丁更新，可以使用一个agent将其嵌入到 `java.io.ObjectInputStream` 是最好的解决方案。

全局更改`ObjectInputStream`只在防御已知恶意类型是安全的([D] 黑名单方式)，因为不可能知道所有应用程序预期反序列化的类是什么。

幸运的是，如今，黑名单列表中仅需少量的类即可抵御大量已知的攻击向量。

不可避免地，会发现更多可能被滥用的“gadget”类。然而，如今有大量易受攻击的软件暴露出来，需要修复。在某些情况下，“修复”漏洞可能涉及重新设计消息传递系统，并在开发人员不接受序列化对象时破坏向后兼容性。


要启用这些代理，只需添加一个新的JVM参数：

```text
-javaagent:name-of-agent.jar
```

各种社区成员已经发布了采用这种方法的agent:

- [rO0 by Contrast Security](https://github.com/Contrast-Security-OSS/contrast-rO0)

一种类似但可扩展性较差的方法是手动修补和引导JVM的ObjectInputStream。有关这种方法的指导意见[此处](https://github.com/wsargent/paranoid-java-serialization).

### .Net CSharp

#### 白盒审计

在源代码中搜索以下术语：

1. `TypeNameHandling`
2. `JavaScriptTypeResolver`

查找由用户控制变量进行类型设置的任何序列化函数。

#### 黑盒审计

搜索以下以开头的base64编码内容：

```text
AAEAAAD/////
```

搜索包含以下文本的内容：

1. `TypeObject`
2. `$type:`

#### 一般预防措施

微软已经声明，`BinaryFormatter`类型是危险的，无法保护。因此，不应使用它。详细信息请参见[BinaryFormatter安全指南](https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide). ([D] 在逆向某客户端时遇到该场景，并实现了RCE，后续有机会分享)

对象类型的流被用于反序列化则不允许通过数据流定义。如果可能的话，可以通过使用`DataContractSerializer`或`XmlSerializer`来防止这种情况。

当使用`JSON.Net`时需要确保`TypeNameHandling`仅被设置为`None`.

```csharp
TypeNameHandling = TypeNameHandling.None
```

如果要使用`JavaScriptSerializer`，则不要将其与`JavaScriptTypeResolver`一起使用。

如果必须反序列化定义其自身类型的数据流，则限制允许反序列化的类型。人们应该意识到，和许多.Net类型原生函数本身具有潜在危险一样, 这仍然存在风险。例如

```csharp
System.IO.FileInfo
```

在反序列化时，引用服务器上实际文件的`FileInfo` 对象可能会更改这些文件的属性，例如更改为只读，从而造成潜在的拒绝服务攻击。

即使您限制了可以反序列化的类型，也要记住，某些类型的属性有风险. 例如，`System.ComponentModel.DataAnnotations.ValidationException`， 若其属性"Value"的类型为"Object"，如果此类型是允许反序列化的类型，则攻击者可以将“Value”属性设置为他们可控的任何对象类型。

应防止攻击者操纵将被实例化的类型。即使是`DataContractSerializer` 或`XmlSerializer`也可能被滥用，例如：

```csharp
// Action below is dangerous if the attacker can change the data in the database
var typename = GetTransactionTypeFromDatabase();

var serializer = new DataContractJsonSerializer(Type.GetType(typename));

var obj = serializer.ReadObject(ms);
```

恶意执行可以发生在某些.Net类型的反序列化期间。创建如下所示的控件是无效的。

```csharp
var suspectObject = myBinaryFormatter.Deserialize(untrustedData);

//Check below is too late! Execution may have already occurred.
if (suspectObject is SomeDangerousObjectType)
{
    //generate warnings and dispose of suspectObject
}
```

对于 `JSON.Net` 可以使用自定义的`SerializationBinder`创建更安全的白名单列表形式。

尽量了解最新已知的关于.NET不安全的反序列化gadgets相关信息，并特别注意反序列化进程可以创建此类类型的代码。**反序列化程序只能实例化它知道的类型**。

尝试将可能创建潜在gadgets的代码与任何具有互联网连接的代码分开。例如，在WPF应用程序中使用的`System.Windows.Data.ObjectDataProvider` 是一个允许任意方法调用的已知gadgets。在对不可信数据进行反序列化的REST服务项目中，引用上述程序集是有风险的。 

#### 已知 .NET RCE Gadgets

- `System.Configuration.Install.AssemblyInstaller`
- `System.Activities.Presentation.WorkflowDesigner`
- `System.Windows.ResourceDictionary`
- `System.Windows.Data.ObjectDataProvider`
- `System.Windows.Forms.BindingSource`
- `Microsoft.Exchange.Management.SystemManager.WinForms.ExchangeSettingsProvider`
- `System.Data.DataViewManager, System.Xml.XmlDocument/XmlDataDocument`
- `System.Management.Automation.PSObject`



## 安全使用反序列化-无关语言的通用方法

### 使用替代数据格式

通过避免使用原生的（反）序列化格式，可以大大降低风险。通过切换到JSON或XML等纯数据格式，可以减少自定义反序列化逻辑被重新用于恶意目的的可能性。

许多应用程序依赖于[数据传输对象模式](https://en.wikipedia.org/wiki/Data_transfer_object)，这涉及待为显式数据传输目的创建一个单独的对象域。当然，在解析纯数据对象后，应用程序仍有可能犯安全错误。

### 仅对签名数据进行反序列化

如果应用程序在反序列化之前知道需要处理哪些消息，则可以在序列化过程中对其进行签名。然后，应用程序可以选择不反序列化任何没有经过身份验证的签名的消息。



## 缓解工具/库

- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [SWAT](https://github.com/cschneider4711/SWAT) (Serial Whitelist Application Trainer)
- [NotSoSerial](https://github.com/kantega/notsoserial)

## 检测工具

- [Java deserialization cheat sheet aimed at pen testers](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.](https://github.com/frohoff/ysoserial)
- [Java De-serialization toolkits](https://github.com/brianwrf/hackUtils)
- [Java de-serialization tool](https://github.com/frohoff/ysoserial)
- [.Net payload generator](https://github.com/pwntester/ysoserial.net)
- [Burp Suite extension](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer is a static bytecode analyzer for deserialization](https://github.com/mbechler/serianalyzer)
- [Payload generator](https://github.com/mbechler/marshalsec)
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda)
- Burp Suite Extension
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)

## 引用

- [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [Deserialization of untrusted data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [Java Deserialization Attacks - German OWASP Day 2016](../assets/Deserialization_Cheat_Sheet_GOD16Deserialization.pdf)
- [AppSecCali 2015 - Marshalling Pickles](http://www.slideshare.net/frohoff1/appseccali-2015-marshalling-pickles)
- [FoxGlove Security - Vulnerability Announcement](http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere)
- [Java deserialization cheat sheet aimed at pen testers](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.](https://github.com/frohoff/ysoserial)
- [Java De-serialization toolkits](https://github.com/brianwrf/hackUtils)
- [Java de-serialization tool](https://github.com/frohoff/ysoserial)
- [Burp Suite extension](https://github.com/federicodotta/Java-Deserialization-Scanner/releases)
- [Java secure deserialization library](https://github.com/ikkisoft/SerialKiller)
- [Serianalyzer is a static bytecode analyzer for deserialization](https://github.com/mbechler/serianalyzer)
- [Payload generator](https://github.com/mbechler/marshalsec)
- [Android Java Deserialization Vulnerability Tester](https://github.com/modzero/modjoda)
- Burp Suite Extension
    - [JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller)
    - [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)
    - [Burp-ysoserial](https://github.com/summitt/burp-ysoserial)
    - [SuperSerial](https://github.com/DirectDefense/SuperSerial)
    - [SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active)
- .Net
    - [Alvaro Muñoz: .NET Serialization: Detecting and defending vulnerable endpoints](https://www.youtube.com/watch?v=qDoBlLwREYk)
    - [James Forshaw - Black Hat USA 2012 - Are You My Type? Breaking .net Sandboxes Through Serialization](https://www.youtube.com/watch?v=Xfbu-pQ1tIc)
    - [Jonathan Birch BlueHat v17 - Dangerous Contents - Securing .Net Deserialization](https://www.youtube.com/watch?v=oxlD8VWWHE8)
    - [Alvaro Muñoz & Oleksandr Mirosh - Friday the 13th: Attacking JSON - AppSecUSA 2017](https://www.youtube.com/watch?v=NqHsaVhlxAQ)