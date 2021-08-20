# 防范不安全的直接对象引用(IDOR)

## 介绍

不安全的直接对象引用 (此处称**IDOR**) , 发生于应用程序对内部实现的对象进行引用时。 使用这种方式，它将展现存储于后端中元素的实际标识符和使用的格式/模式。最常见的例子（尽管不限于此）是存储系统（数据库、文件系统等）中的记录标识符。

在2013年版OWASP前10名中[A4](https://wiki.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References)中引用并阐述IDOR。

## 背景

IDOR不会带来直接的安全问题，因为它本身只展示了用于对象标识符的格式/模式。IDOR根据对应的格式/模式，使攻击者拥有对其枚举攻击的能力，以便尝试探测对关联对象的访问。 

枚举攻击可以这样描述：攻击者通过发现的格式/模式，进而构建出有效标识符的集合，并针对应用程序进行测试。

**案例:**

假设一个HR应用程序接受服务的员工ID为参数，并以此返回员工信息，员工ID的格式/模式如下：

```text
EMP-00000
EMP-00001
EMP-00002
...
```

基于此，攻击者可以构建从*EMP-00000*到*EMP-99999*的有效ID集合。

要被利用，IDOR问题必须与[访问控制](./cheatsheets/Access_Control_Cheat_Sheet.md)问题相结合，因为攻击者通过枚举攻击猜出标识符, 并正是访问控制问题“允许”其可以访问标识符所对应的对象。

## 补充说明

**Jeff Williams**:

直接对象引用基本上是一个访问控制问题。我们将其拆分，以强调URL访问控制和数据层访问控制之间的区别。对于数据层使用URL进行访问控制的问题，您无能为力。它们也不是真正的输入验证问题。但我们一直看到DOR。如果我们只列出“从一开始就乱七八糟的访问控制”，那么人们可能只会在URL上添加SiteMinder或来JEE声明性访问控制，并就此结束。我们试图避免这样的情况。

> 注: DOR 直接对象引用

**Eric Sheridan**:

对象引用"映射"首先使用临时存储在会话中的授权值列表填充。用户请求一个字段（ex:color=654321）时，应用程序会从会话的"映射"中进行查找，以确定适当的列名。如果此受限的"映射"中不存在该值，则用户未被授权。引用"映射"不应是全局的（即包括所有可能的值），它们是临时"映射"/字典，仅使用授权值填充。

当开发人员将对内部实现对象（如文件、目录、数据库记录或密钥）的引用作为URL或表单参数展示(传递)时，会发生直接对象引用。

我对文件、目录等使用DOR感到“失望”，但对所有数据库的主键却不是这样。就像你说的那样，这太疯狂了。我认为，只要数据库主键被公开(展现)，就需要访问控制规则。在真正的企业或后企业系统中，几乎无法避免DOR数据库主键。

但是，假设用户有一个帐户列表，比如数据库ID23456是其支票帐户。我一下子就能DOR(指访问其银行账户)。你需要谨慎对待这件事。 

## 目标

本文提出了一种想法，以一种简单、可移植和无状态的方式防止直接展示和暴露真实标识符，该建议需要处理会话和无会话应用程序的拓扑。

## 建议

建议使用哈希(散列)替换直接标识符。为了支持应用程序以多实例模式部署的拓扑（用于生产），根据应用程序级别所定义的值进行哈希加"盐"。

哈希应有以下属性

- 不需要在用户会话或应用程序级的缓存中去维护映射表（真实ID与前端ID）。
- 使创建枚举集合变得更加困难，因为即使攻击者可以从ID长度猜测哈希算法，它也无法再现该值，因为"盐"不依赖于隐藏值。

为前端生成用于对照映射的标识符-JAVA utility class实例:

``` java
import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Handle the creation of ID that will be send to front end side
 * in order to prevent IDOR
 */

public class IDORUtil {
    /**
     * SALT used for the generation of the HASH of the real item identifier
     * in order to prevent to forge it on front end side.
     */
    private static final String SALT = "[READ_IT_FROM_APP_CONFIGURATION]";

    /**
     * Compute a identifier that will be send to the front end and be used as item
     * unique identifier on client side.
     *
     * @param realItemBackendIdentifier Identifier of the item on the backend storage
     *                                  (real identifier)
     * @return A string representing the identifier to use
     * @throws UnsupportedEncodingException If string's byte cannot be obtained
     * @throws NoSuchAlgorithmException If the hashing algorithm used is not
     *                                  supported is not available
     */
    public static String computeFrontEndIdentifier(String realItemBackendIdentifier)
     throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String frontEndId = null;
        if (realItemBackendIdentifier != null && !realItemBackendIdentifier.trim().isEmpty()) {
            //Prefix the value with the SALT
            String tmp = SALT + realItemBackendIdentifier;
            //Get and configure message digester
            //We use SHA1 here for the following reason even if SHA1 have now potential collision:
            //1. We do not store sensitive information, just technical ID
            //2. We want that the ID stay short but not guessable
            //3. We want that a maximum of backend storage support the algorithm used in order to compute it in selection query/request
            //If your backend storage supports SHA256 so use it instead of SHA1
            MessageDigest digester = MessageDigest.getInstance("sha1");
            //Compute the hash
            byte[] hash = digester.digest(tmp.getBytes("utf-8"));
            //Encode is in HEX
            frontEndId = DatatypeConverter.printHexBinary(hash);
        }
        return frontEndId;
    }
}
```

前端使用标识符的服务示例：

``` java
/**
 * Service to list all available movies
 *
 * @return The collection of movies ID and name as JSON response
 */
@RequestMapping(value = "/movies", method = GET, produces = {MediaType.APPLICATION_JSON_VALUE})
public Map<String, String> listAllMovies() {
    Map<String, String> result = new HashMap<>();

    try {
        this.movies.forEach(m -> {
            try {
                //Compute the front end ID for the current element
                String frontEndId = IDORUtil.computeFrontEndIdentifier(m.getBackendIdentifier());
                //Add the computed ID and the associated item name to the result map
                result.put(frontEndId, m.getName());
            } catch (Exception e) {
                LOGGER.error("Error during ID generation for real ID {}: {}", m.getBackendIdentifier(),
                             e.getMessage());
            }
        });
    } catch (Exception e) {
        //Ensure that in case of error no item is returned
        result.clear();
        LOGGER.error("Error during processing", e);
    }

    return result;
}

/**
 * Service to obtain the information on a specific movie
 *
 * @param id Movie identifier from a front end point of view
 * @return The movie object as JSON response
 */
@RequestMapping(value = "/movies/{id}", method = GET, produces = {MediaType.APPLICATION_JSON_VALUE})
public Movie obtainMovieName(@PathVariable("id") String id) {

    //Search for the wanted movie information using Front End Identifier
    Optional<Movie> movie = this.movies.stream().filter(m -> {
        boolean match;
        try {
            //Compute the front end ID for the current element
            String frontEndId = IDORUtil.computeFrontEndIdentifier(m.getBackendIdentifier());
            //Check if the computed ID match the one provided
            match = frontEndId.equals(id);
        } catch (Exception e) {
            //Ensure that in case of error no item is returned
            match = false;
            LOGGER.error("Error during processing", e);
        }
        return match;
    }).findFirst();

    //We have marked the Backend Identifier class field as excluded
    //from the serialization
    //So we can send the object to front end through the serializer
    return movie.get();
}
```

使用value object：

``` java
public class Movie {
    /**
     * We indicate to serializer that this field must never be serialized
     *
     * @see "https://fasterxml.github.io/jackson-annotations/javadoc/2.5/com/fasterxml/
     *       jackson/annotation/JsonIgnore.html"
     */
    @JsonIgnore
    private String backendIdentifier;
...
}
```

## 原型案例

[GitHub repository](https://github.com/righettod/poc-idor).