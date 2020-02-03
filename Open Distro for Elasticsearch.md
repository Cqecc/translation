<h1>Open Distro for Elasticsearch</h1>
本文是[Open Distro for Elasticsearch](https://opendistro.github.io/for-elasticsearch/)的技术文档。Open Distro for Elasticsearch是一个社区驱动，100%开源的Elasticsearch发行版本，它实现了高级安全、警报、深度性能分析等其它功能。

---

内容目录

[TOC]

***

# 关于

## 为什么使用Open Distro for Elasticsearch？

Open Distro for Elasticsearch适用于下列场景：

- 日志分析

- 实时应用监控

- 点击流（Clickstream）分析

- 搜索后端

相比较于Elasticsearch的发行版，Open Distro for Elasticsearch提供下面几个额外的特性：

| 内容                                                         | 目的                           |
| ------------------------------------------------------------ | ------------------------------ |
| Elasticsearch                                                | 数据存储和搜索引擎             |
| Kibana                                                       | 搜索前端和可视化               |
| [Security](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/) | 集群的身份认证和访问控制       |
| [Alerting](https://opendistro.github.io/for-elasticsearch-docs/docs/alerting/) | 数据内容触发一定条件时发送提醒 |
| [SQL](https://opendistro.github.io/for-elasticsearch-docs/docs/sql/) | 使用SQL查询你的数据            |
| [Performance Analyzer](https://opendistro.github.io/for-elasticsearch-docs/docs/pa/) | 监控和优化你的集群             |

***

## 开始

<font color="green">DOCKER</font>

1. 安装并启动[Docker Desktop](https://www.docker.com/products/docker-desktop)。

2. 运行下列命令：

   ```sh
   docker pull amazon/opendistro-for-elasticsearch:1.2.0
   docker run -p 9200:9200 -p 9600:9600 -e "discovery.type=single-node" amazon/opendistro-for-elasticsearch:1.2.0
   ```
   
3. 打开一个新终端会话，执行：

   ```sh
   curl -XGET --insecure https://localhost:9200 -u admin:admin 
   ```

想了解更多，见[安装](https://opendistro.github.io/for-elasticsearch-docs/docs/install/)。
***
## 构建

如果想修改Open Distro for Elasticsearch代码并从自己的源构建，指令在[opendistro-build](https://github.com/opendistro-for-elasticsearch/opendistro-build)仓库的`elasticsearch/README.md`和`kibana/README.md`文件中。同样的，你能在各种插件自己的仓库中找到这些指令。如果你的修改也有益于其它人，请考虑提交一个pull request。

***

## 关于Open Distro for Elasticsearch

[Open Distro for Elasticsearch](https://opendistro.github.io/for-elasticsearch/)由Amazon Web Service支持。所有组件都支持[GitHub](https://github.com/opendistro-for-elasticsearch/)上的[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)协议。

本项目欢迎提供GitHub issue、bug修改、特性、插件、文档等任何东西。想参与进来吗，见Open Distro for Elasticsearch网站上的[Contribute](https://opendistro.github.io/for-elasticsearch/contribute.html)。

***

# 版本历史

| Open Distro for Elasticsearch 版本 | 发布信息                                                     | 发布时间      | Elasticsearch version |
| :--------------------------------- | :----------------------------------------------------------- | :------------ | :-------------------- |
| 1.2.0                              | 升级Elasticsearch版本                                        | 2019-9-19     | 7.2.0                 |
| 1.1.0                              | 升级Elasticsearch版本                                        | 2019-7-30     | 7.1.1                 |
| 1.0.2                              | 修复Security plugin中的一个权限组bug                         | 2019-7-23     | 7.0.1                 |
| 1.0.1                              | 修复Security plugin中的一个后端角色bug                       | 2019-7-12     | 7.0.1                 |
| 1.0.0                              | 给添加警报插件添加操作限制，升级Elasticsearch到新主要版本。见[升级到1.x.x](https://opendistro.github.io/for-elasticsearch-docs/docs/upgrade/1-0-0/)小节中的重要更新。 | 28 June 2019  | 7.0.1                 |
| 0.10.0                             | 添加对Elasticsearch旧版本的支持                              | 7 August 2019 | 6.8.1                 |
| 0.9.0                              | 升级Elasticsearch版本                                        | 1 May 2019    | 6.7.1                 |
| 0.8.0                              | 升级Elasticsearch版本                                        | 5 April 2019  | 6.6.2                 |
| 0.7.1                              | 修复Kibana多租户功能                                         | 29 March 2019 | 6.5.4                 |
| 0.7.0                              | 发布版本                                                     | 11 March 2019 | 6.5.4                 |

想了解详细发布信息吗，到下列GitHub仓库中查看吧：

- [Security](https://github.com/opendistro-for-elasticsearch/security/releases)
- [Alerting](https://github.com/opendistro-for-elasticsearch/alerting/releases)
- [SQL](https://github.com/opendistro-for-elasticsearch/sql/releases)
- [Performance Analyzer](https://github.com/opendistro-for-elasticsearch/performance-analyzer/releases)

***

# 安装与配置

Open Distro for Elasticsearch有以下几种下载选项：Docker镜像、RPM包、Debian包和压缩包。

## Docker

你可以像其它镜像一样拉取Open Distro for Elasticsearch的Docker镜像：

```sh
docker pull amazon/opendistro-for-elasticsearch:1.2.0
docker pull amazon/opendistro-for-elasticsearch-kibana:1.2.0
```

上[Docker Hub](https://hub.docker.com/r/amazon/opendistro-for-elasticsearch/tags)获取更多可用的版本。

Open Distro for Elasticsearch镜像使用`centos:7`作为基本镜像。如果你在本地运行Docker，我们推荐在**Preferences** > **Advanced**中设置至少4GB大小的内存。

### 运行镜像

运行本地开发环境的镜像：

```sh
docker run -p 9200:9200 -p 9600:9600 -e "discovery.type=single-node" amazon/opendistro-for-elasticsearch:1.2.0
```

然后请求到服务器来校验Elasticsearch是否启动运行：

```sh
curl -XGET https://localhost:9200 -u admin:admin --insecure
curl -XGET https://localhost:9200/_cat/nodes?v -u admin:admin --insecure
curl -XGET https://localhost:9200/_cat/plugins?v -u admin:admin --insecure
```

查找容器ID：

```sh
docker ps
```

然后可以停止正在使用的容器：

```sh
docker stop <container-id>
```

### 开启集群

部署跨多个节点的镜像以适应产品级工作量，创建一个适合你环境的`docker-compose.yml`文件，然后运行：

```sh
docker-compose up
```

要停止集群，运行：

```sh
docker-compose down
```

要停止集群并且删除所有的数据卷，运行：

```sh
docker-compose down -v
```

#### DOCKER COMPOSE示例文件

该示例文件开启了两个数据节点和Kibana。

```yaml
version: '3'
services:
  odfe-node1:
    image: amazon/opendistro-for-elasticsearch:1.2.0
    container_name: odfe-node1
    environment:
      - cluster.name=odfe-cluster
      - node.name=odfe-node1
      - discovery.seed_hosts=odfe-node1,odfe-node2
      - cluster.initial_master_nodes=odfe-node1,odfe-node2
      - bootstrap.memory_lock=true # along with the memlock settings below, disables swapping
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m" # minimum and maximum Java heap size, recommend setting both to 50% of system RAM
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536 # maximum number of open files for the Elasticsearch user, set to at least 65536 on modern systems
        hard: 65536
    volumes:
      - odfe-data1:/usr/share/elasticsearch/data
    ports:
      - 9200:9200
      - 9600:9600 # required for Performance Analyzer
    networks:
      - odfe-net
  odfe-node2:
    image: amazon/opendistro-for-elasticsearch:1.2.0
    container_name: odfe-node2
    environment:
      - cluster.name=odfe-cluster
      - node.name=odfe-node2
      - discovery.seed_hosts=odfe-node1,odfe-node2
      - cluster.initial_master_nodes=odfe-node1,odfe-node2
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - odfe-data2:/usr/share/elasticsearch/data
    networks:
      - odfe-net
  kibana:
    image: amazon/opendistro-for-elasticsearch-kibana:1.2.0
    container_name: odfe-kibana
    ports:
      - 5601:5601
    expose:
      - "5601"
    environment:
      ELASTICSEARCH_URL: https://odfe-node1:9200
      ELASTICSEARCH_HOSTS: https://odfe-node1:9200
    networks:
      - odfe-net

volumes:
  odfe-data1:
  odfe-data2:

networks:
  odfe-net:
```

如果你要使用环境变量重写了`kibana.yml`配置，如上所示，将配置的各字母大写，并用下划线隔开。例如：`elasticsearch.url`，将写作`ELASTICSEARCH_URL`。

### 配置Elasticsearch

你可以导入一个自定义的`elasticsearch.yml`文件到Docker容器中，使用`docker run`的[`-v` flag](https://docs.docker.com/engine/reference/commandline/run/#mount-volume--v---read-only) 功能：

```sh
docker run \
-p 9200:9200 -p 9600:9600 \
-e "discovery.type=single-node" \
-v /<full-path-to>/custom-elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml \
amazon/opendistro-for-elasticsearch:1.2.0
```

你可以在`docker-compose.yml` 文件中使用相对路径达到相同的效果：

```yaml
services:
  odfe-node1:
    volumes:
      - odfe-data1:/usr/share/elasticsearch/data
      - ./custom-elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
  odfe-node2:
    volumes:
      - odfe-data2:/usr/share/elasticsearch/data
      - ./custom-elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
  kibana:
    volumes:
      - ./custom-kibana.yml:/usr/share/kibana/config/kibana.yml
```

你可以使用相同的方法来[导入自己的证书](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker-security/)来使用Open Disctro的安全插件。

### 使用Bash访问容器

要在容器中创建一个交互的Bash会话，运行`docker ps` 找到容器ID。然后运行：

```sh
docker exec -it <container-id> /bin/bash
```

### 重要配置

为适应产品环境工作量，确保[Linux配置](https://www.kernel.org/doc/Documentation/sysctl/vm.txt)`vm.max_map_count`的值至少设置为262144。在Open Distro for Elasticsearch Docker镜像中，这是一个默认设置。可在容器中运行一个Bash会话运行如下命令查看：

```sh
cat /proc/sys/vm/max_map_count
```

要增加这个值，你需要修改Docker镜像。使用RPM安装时，你可以在主机的`/etc/sysctl.conf`文件中添加这个设置，使用如下命令：

```
vm.max_map_count=262144
```

然后运行`sudo sysctl -p`重载配置。

上面提到的`docker-compose.yml`文件也包含了几个关键配置：`bootstrap.memory_lock=true`，`ES_JAVA_OPTS=-Xms512m -Xmx512m`，`nofile 65536`和`port 9600`。这些配置分别是禁止内存交换（同`memlock`），设置Java堆内存大小（我们推荐系统RAM的一半），设置Elasticsearch用户的打开文件数限制为65536，最后让你在9600端口访问性能分析工具。

### 自定义插件

要在运行镜像时加上一个自定义插件，首先创建一个[`Dockerfile`](https://docs.docker.com/engine/reference/builder/)：

```dockerfile
FROM amazon/opendistro-for-elasticsearch:1.2.0
RUN /usr/share/elasticsearch/bin/elasticsearch-plugin install --batch <plugin-name-or-url>
```

然后运行下列命令：

```sh
docker build --tag=odfe-custom-plugin .
docker run -p 9200:9200 -p 9600:9600 -v /usr/share/elasticsearch/data odfe-custom-plugin
```

为使用安全插件，你也可以导入你自己的证书，同 [配置Elasticsearch](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#configure-elasticsearch)时使用的`-v`参数相似：

```dockerfile
FROM amazon/opendistro-for-elasticsearch:1.2.0
COPY --chown=elasticsearch:elasticsearch elasticsearch.yml /usr/share/elasticsearch/config/
COPY --chown=elasticsearch:elasticsearch my-key-file.pem /usr/share/elasticsearch/config/
COPY --chown=elasticsearch:elasticsearch my-certificate-chain.pem /usr/share/elasticsearch/config/
COPY --chown=elasticsearch:elasticsearch my-root-cas.pem /usr/share/elasticsearch/config/
```

## RPM

## Debian包

## Docker安全配置

## 压缩包

压缩包安装在Linux操作系统中可行，并且提供了一个带有运行Open Distro for Elasticsearch所有所需要的东西的独立目录，包括一个完整的Java开发套件（JDK）。压缩包在测试时是一个不错的选择，但在产品环境中，我们推荐Docker或者包管理器部署。

压缩包支持CentOS 7，Amazon Linux 2，Ubuntu 18.04和其它著名的Linux发行版本。如果你有自己的Java安装包，并在终端中设置了`JAVA_HOME`，在macOS中也能运行。

1. 下载压缩包：

   ```sh
   curl https://d3g5vo6xdbdb9a.cloudfront.net/tarball/opendistro-elasticsearch/opendistroforelasticsearch-1.2.0.tar.gz -o opendistroforelasticsearch-1.2.0.tar.gz
   ```

2. 下载checksum：

   ```sh
   curl https://d3g5vo6xdbdb9a.cloudfront.net/tarball/opendistro-elasticsearch/opendistroforelasticsearch-1.2.0.tar.gz.sha512 -o opendistroforelasticsearch-1.2.0.tar.gz.sha512
   ```

3. 核实压缩包的checksum:

   ```sh
   shasum -a 512 -c opendistroforelasticsearch-1.2.0.tar.gz.sha512
   ```

   在CentOS操作系统中，你可能没有`shasum`。安装这个工具：

   ```shell
   sudo yum install perl-Digest-SHA
   ```

4. 解压TAR文件到一个目录中，然后进入到该目录：

   ```shell
   tar -zxf opendistroforelasticsearch-1.2.0.tar.gz
   cd opendistroforelasticsearch-1.2.0
   ```

5. 运行Open Distro for Elasticsearch：

   ```shell
   ./opendistro-tar-install.sh
   ```

6. 打开第二个终端会话，发送请求到服务来核实Open Distro for Elasticsearch是否已启动运行：

   ```shell
   curl -XGET https://localhost:9200 -u admin:admin --insecure
   curl -XGET https://localhost:9200/_cat/plugins?v -u admin:admin --insecure
   ```

### 配置

你可以修改`config/elasticsearch.yml`或者在`-E`参数中添加环境变量:

```shell
./opendistro-tar-install.sh -Ecluster.name=odfe-cluster -Enode.name=odfe-node1 -Ehttp.host=0.0.0.0 -Ediscovery.type=single-node
```

在[重要配置](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#important-settings)中查看其它设置。

## 单独的Elasticsearch插件安装

## 其它组件

## Rest加密

# 升级

# Elasticsearch

# Kibana

# 安全-配置

Open Distro for Elasticsearch引入了一个安全插件来进行身份认证和访问控制。这个插件提供了几个特性来协助你保护你的集群。

| 特性                                               | 描述                                                         |
| :------------------------------------------------- | :----------------------------------------------------------- |
| 节点间通信加密                                     | 加密Es集群中各节点间的流量                                   |
| 基于HTTP的身份认证                                 | 在Http请求的基础上添加了一个简单的使用用户名和密码的身份认证。 |
| 支持活动目录、LDAP、Kerberos、SAML和OpenID Connect | 使用现存的工业级架构来认证用户，或者在内置用户数据库中创建新用户 |
| 基于角色的访问控制                                 | 角色定义了用户有哪些操作：哪些数据可以看，哪些集群的配置可以改，哪些索引可以写等等。角色与用户是多对多的关系。 |
| 索引，文档及字段级别的安全                         | 严格控制所有索引，索引中具体的文档，或者文档中某些字段的访问。 |
| 日志审计                                           | 审计日志让你能查看对Elasticsearch集群的访问踪迹，用于保持对es的合规和安全的使用。 |
| 跨集群搜索                                         | 使用协调集群提交搜索请求到远程集群。                         |
| Kibana多租户                                       | 创建一个共享（或者私有）的空间用于索引模式、可视化、仪表板和其它kibana对。 |

## 开始

插件包含了一个演示证书，所以你可以快速上手和运行，但在产品环境中使用之前，你需要手动配置：

1. [替换演示证书](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker-security/)
2. [重新在`elasticsearch.yml`配置你自己的证书](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
3. [重新在`config.yml`配置你自己的后端认证](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/) (如果你不打算使用内置用户数据库)
4. [修改YAML文件中的配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/yaml/)
5. [使用securityadmin.sh应用修改](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/security-admin/)
6. [添加用户、角色、角色映射和租户](https://opendistro.github.io/for-elasticsearch-docs/docs/security-access-control/)

如果你不想使用该插件，见[禁止安全](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/disable/).

***

## 身份认证流

理解身份认证流是上手配置Open Distro for Elasticsearch的安全插件的最好方法。

1. 要确定一个想访问集群的用户，安全插件需要用户的认证信息。

   这些认证信息的差别取决于你怎样配置这插件。例如，如果你使用基础认证，认证信息就是用户名和密码。如果你使用JSON网络令牌，认证信息就保存在令牌里面。如果你使用TLS证书，认证信息就是证书的可识别名（DN）。

2. 安全插件使用后台程序认证用户的认证信息：内置用户数据库、轻量目录访问协议（LDAP）、活动目录、Kerberos或者JSON网络令牌。

   插件支持链状后台程序。如果配置了多个后台程序，插件会在所有的后台程序中依次对用户进行身份校验，直到有一个成功。一个常用的使用场景是结合安全插件的内置用户数据库和LDAP/活动目录。

3. （可选的）在认证器核实完用户的认证信息后，插件收集所有的后台程序角色。在大多数情况下，后台程序是LDAP/活动目录。

4. 在用户被认证且后台程序角色都获取到后，安全插件使用角色映射来查找用户的安全角色（或者后台程序角色）。

   如果角色映射没有包括用户（或者用户的后台程序角色），用户成功登录但没有权限。

5. 用户现在可以进行对应安全角色定义的操作了。例如，一个用户可能配置了`kibana_user`角色，因此有权限访问Kibana。

***

## 后台程序配置

使用安全插件的第一步就是决定一个在上一节的第2、3点提到的后台身份认证程序。插件有一个内置用户数据库，但多数人更喜欢已有的后台身份认证程序，如LDAP服务，或者两者结合使用。

身份认证和权限管理的后台程序的主要配置文件是`plugins/opendistro_security/securityconfig/config.yml`。它定义了安全插件怎样检索用户的认证信息，怎样核验这些认证信息，以及额外的用户角色是怎么从后台程序中获取的（可选的）。

`config.yml`主要有三部分：

```yaml
opendistro_security:
  dynamic:
    http:
      ...
    authc:
      ...
    authz:
      ...
```

想了解完整示例，到[sample file on GitHub](https://github.com/opendistro-for-elasticsearch/security/blob/master/securityconfig/config.yml)上查看。

### HTTP

`http`部分的格式如下：

```yaml
anonymous_auth_enabled: <true|false>
xff: # optional section
  enabled: <true|false>
  internalProxies: <string> # Regex pattern
  remoteIpHeader: <string> # Name of the header in which to look. Typically: x-forwarded-for
  proxiesHeader: <string>
  trustedProxies: <string> # Regex pattern
```

如果你禁止了匿名认证，且一个`authc`都没有提供的话，安全插件不会初始化。

### 身份认证

`auth`部分的格式如下：

```yaml
<name>:
  http_enabled: <true|false>
  transport_enabled: <true|false>
  order: <integer>
    http_authenticator:
      ...
    authentication_backend:
      ...
```

`authc`的每一项称作*认证域*。它指定了去哪儿获取用户的认证信息以及使用哪个后台程序认证用户。

你可以使用多个认证域。每个认证域都有一个名称（如，`basic_auth_internal`），`enabled`标志和`order`属性。顺序保证了多个认证域以链式相连。安全插件根据你提供的顺序使用它们。如果在一个域用户成功认证了，安全插件会跳过剩余的域。

`http_authenticator`指定了你想在HTTP级别使用哪种认证方法。

下面是在HTTP级别定义一个认证器的语法：

```yaml
http_authenticator:
  type: <type>
  challenge: <true|false>
  config:
    ...
```

`type`可配置的值有：

- `basic`：HTTP基础认证。不需要额外的配置。
- `kerberos`：Kerberos认证。需要额外配置[Kerberos-specific配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#kerberos)。
- `jwt`：JSON网络令牌。需要额外配置[JWT-specific配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#json-web-token)。
- `clientcert`：通过客户端TLS证书认证。证书必须被你节点的truststore中的根证书信任。

配置了HTTP认证器后，你必须指定一个你想用来认证用户的后台程序：

```yaml
authentication_backend:
  type: <type>
  config:
    ...
```

`type`可配置的值有：

- `noop`：后台程序系统不会做进一步的认证。当HTTP认证器已经对用户完全认证时，如JWT、Kerberos或客户端证书身份验证，使用`noop`。
- `internal`：使用`internal_users.yml`中定义的用于身份认证的用户和角色。
- `ldap`：通过LDAP服务对用户进行身份认证。该设置需要搭配[LDAP特殊配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/ldap/)使用。

### 权限管理

在用户被认证后，安全插件可以选择性的收集来自于后台程序系统的附加用户角色。权限配置的格式如下：

```yaml
authz:
  <name>:
    http_enabled: <true|false>
    transport_enabled: <true|false>
    authorization_backend:
      type: <type>
      config:
        ...
```

同身份认证的配置类似，你可以在这里面配置多项内容。这时候执行顺序就没什么关系了，也就没有了`order`字段。

`type`可能的值有：

- `noop`：整个跳过这一步。
- `ldap`：从LDAP服务中获取附加角色。该设置需要搭配[LDAP特殊配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/ldap/)使用。

### 示例

Open Distro for Elasticsearch默认带有`plugins/opendistro_security/securityconfig/config.yml`文件，里面包含了许多示例配置。把这些示例当作起点，并可以按你的需求自行配置。

### HTTP基础

想要设置HTTP基础身份认证，你必需在配置中的`http_authenticator`一节里面开启它：

```yaml
http_authenticator:
  type: basic
  challenge: true
```

大多数情况下，你设置`challenge`标识为`true`。如果HTTP头中`Authorization`属性没有被设置，该标识决定了安全插件的行为。

如果`challenge`设定为`true`，安全插件返回一个带有`UNAUTHORIZED`(401)状态的响应给客户端。如果客户端使用器访问集群，这会触发一个身份认证弹窗，提示用户输入用户名和密码。

如果`challenge`设为`false`，且没有设置`Authorization`请求头，安全插件不会返回`www-Authenticate`响应给客户端，认证失败。如果你已经在认证域中配置了另外一个`http_authenticator`，这种设置就可以用。还有一种场景是结合基础认证和Kerveros使用。

### Kerberos

基于Kerberos的性质，你必须配置`elasticsearch.yml`和`config.yml`两个文件。

在`elasticsearch.yml`中，定义以下内容：

```yaml
opendistro_security.kerberos.krb5_filepath: '/etc/krb5.conf'
opendistro_security.kerberos.acceptor_keytab_filepath: 'eskeytab.tab'
```

`opendistro_security.kerberos.krb5_filepath`表示你的Kerberos的配置文件路径。这文件包含了Kerberos安装相关的各种配置，例如，realm名称、主机名、Kerberos密钥分发中心（KDC）的端口。

`opendistro_security.kerberos.acceptor_keytab_filepath`表明了keytab文件的路径，这文件包含了安全插件发送请求到Kerberos的主体。

`opendistro_security.kerberos.acceptor_principal: 'HTTP/localhost'`定义了安全插件发送请求到Kerberos的主体。这个值必需在keytab文件中存在。

> 由于安全限制，keytab文件必需存放在`config`目录或者其子目录中，`elasticsearch.yml`中配置的路径也必需是相对路径，而不是绝对路径。

#### 动态配置

在`config.yml`中，一个典型的Kerberos认证域配置如下：

```yaml
authc:
  kerberos_auth_domain:
    enabled: true
    order: 1
    http_authenticator:
      type: kerberos
      challenge: true
      config:
        krb_debug: false
        strip_realm_from_principal: true
    authentication_backend:
      type: noop
```

通过浏览器在HTTP级别完成Kerberos认证需使用SPNEGO。Kerberos/SPNEGO实现方式的不同，取决于你的浏览器和操作系统。这非常重要，当决定`challenge`标识设置为`true`还是`false`时。

与[HTTP Basic Authentication](#http-基础)搭配时，当在HTTP请求头中没有找到`Authorization`属性或者属性值不等于`negotiate`时，标识决定了安全插件该怎样反应。

如果设置为`true`，安全插件返回一个状态响应码是401及响应头`www-Authenticate`属性设置为`negotiate`的响应。这会告诉客户端（浏览器）重新发送一个带有`Authorization`头的请求。如果设置为`false`，安全插件不会解压请求中的认证信息，也就是说，认证失败。设置`challenge`为`false`只有在Kerberos认证信息全放到初始请求中发送了才有意义。

和名字表示的意义一样，设置`krb_debu`为`true`将把Kerberos相关调试信息输出到`stdout`中。在集成Kerberos遇到问题时可使用这个设置。

如果把`strip_realm_from_principal`设为`true`，安全插件会从用户名中去掉realm名。

#### 后台认证

由于Kerberos/SPNEGO在HTTP级别认证用户，也就不需要`authentication_backend`。设置这个值为`noop`。

### JSON网络令牌

JSON网络令牌（JWTs）是基于JSON的包含一个或多个声明的访问令牌。它们通常用于实现单点登录（SSO）解决方案中，属于基于令牌一类的认证系统：

1. 用户提供认证信息（如用户名和密码）登录一个身份认证服务。
2. 身份认证服务校验认证信息。
3. 身份认证服务创建一个访问令牌，并签名。
4. 身份认证服务返回令牌给用户。
5. 用户保存访问令牌。
6. 用户每次发送到他想用的服务的请求都要带上访问令牌。
7. 服务核实令牌并决定是否通过。

一个JSON网络令牌从某种意义上说是自包含的，因为它携带了所有核实一个它内部用户所需要的信息。令牌都是base64编码的、被签名的JSON对象。

JSON网络令牌由三部分组成：

1. Header
2. Payload
3. Signature

#### Header

Header包含用到的关于签名机制的信息，格式如下：

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

在这个例子中，header记录了信息使用HMAC-SHA256签名。

#### Payload

JSON网络令牌包含的payload也被称作[JWT Claims](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#RegisteredClaimName)，一个claim可以是已被创建该令牌的应用核实的用户相关的任何信息。

规范定义了一些有着保留的名称（"registered claims"）的标准claim，包括如令牌签发人、过期时间或者创建时间等。

公开的claim，在另一方面，可以被令牌签发人自由创建，可以包含任何信息，比如用户名和用户的角色。

示例：

```json
{
  "iss": "example.com",
  "exp": 1300819380,
  "name": "John Doe",
  "roles": "admin, devops"
}
```

#### Signature

令牌的签发人通过对base64编码头和payload应用加密hash算法计算出令牌的signature。一个完整的JSON网络令牌是这三部分通过英文句号串联起来的：

```java
encoded = base64UrlEncode(header) + "." + base64UrlEncode(payload)
signature = HMACSHA256(encoded, 'secretkey');
jwt = encoded + "." + base64UrlEncode(signature)
```

示例：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbkFzIjoiYWRtaW4iLCJpYXQiOjE0MjI3Nzk2Mzh9.gzSraSYS8EXBxLN_oWnFSRgCzcmJmMjLiuyu5CSpyHI
```

#### 配置JSON网络令牌

> 如果JSON网络令牌是你用来认证的唯一方式，使用设置`opendistro_security.cache.ttl_minutes: 0`来禁止用户缓存。

设置一个认证域，选择`jwt`作为HTTP认证类型。因为令牌已经包含去核实请求所有需要的信息，`challenge`必须设为`false`，`authentication_backend`设为`noop`。

示例：

```yaml
jwt_auth_domain:
  enabled: true
  order: 0
  http_authenticator:
    type: jwt
    challenge: false
    config:
      signing_key: "base64 encoded key"
      jwt_header: "Authorization"
      jwt_url_parameter: null
      subject_key: null
      roles_key: null
  authentication_backend:
    type: noop
```

下列表格展示了配置参数。

| 名称                | 说明                                                         |
| ------------------- | ------------------------------------------------------------ |
| `signing_key`       | 核实令牌时使用签名密钥。如果你使用一个对称密钥算法，则分享的秘密是base64编码的。如果你使用一个非对称算法，它包含了一个公钥。 |
| `jwt_header`        | 在HTTP头里面传递令牌。典型用法是`Authorization`头设为`Bearer`模式：`Authorization: Bearer <token>`。默认是`Authorization`。 |
| `jwt_url_parameter` | 如果令牌不通过HTTP头传递，而使用URL参数，在这儿定义参数名。  |
| `subject_key`       | JSON payload里的保存用户名的key。如果没有设置，使用[subject registered claim](https://tools.ietf.org/html/rfc7519#section-4.1.2)。 |
| `roles_key`         | JSON payload里的保存用户角色的key。key的值必需是以英文逗号隔开的角色集合。 |

因为JSON网络令牌是自包含的，且用户在HTTP级别上认证的，不需要额外的`authentication_backend`配置。设置它的值为`noop`。

#### 对称密钥算法：HMAC

以hash为基础的消息认证代码（HMACs）是一组算法，算法提供的方法是通过分享密钥的方式对消息签名。密钥在身份认证服务和安全插件之间分享。它必须以base64编码值配置到`signing_key`中：

```yaml
jwt_auth_domain:
  ...
    config:
      signing_key: "a3M5MjEwamRqOTAxOTJqZDE="
      ...
```

#### 非对称密钥算法：RSA and ECDSA

RSA和ECDSA都是非对称加密的、数字签名算法，使用公/私密钥对来签名和验证令牌。这意味着它们使用私钥签名令牌，然后安全插件需要知道公钥并用来核实它。

因为你不能使用公钥签发一个新令牌，而且由于你能伪造一个有效的假令牌创建器，RSA和ECDSA被认为是比HMAC更安全。

要使用RS256，你只需要在JWT配置配置中设置（非base64编码的）RSA公钥作为`signing_key`：

```yaml
jwt_auth_domain:
  ...
    config:
      signing_key: |-
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQK...
        -----END PUBLIC KEY-----
      ...
```

安全插件自动检测使用的算法（RSA/ECDSA），而且如果你想的话，可以把密钥写成多行。

#### HTTP请求的持票人认证

最常用的在HTTP请求中传送一个JSON网络令牌的方式是添加一个带有持票人认证模式的HTTP头：

```
Authorization: Bearer <JWT>
```

默认头的名称是`Authorization`。如果你的身份认证服务或者代理商需要，你也可以通过使用`jwt_header`配置的关键字来使用不同的HTTP头名称。

正如HTTP基础认证一样，当在HTTP请求中传递JSON网络令牌时，你需要使用HTTPS代替HTTP。

#### HTTP请求的URL参数

尽管最常用的在HTTP请求中传递JWT的方式是使用一个请求头字段，安全插件还是支持参数方式。使用如下关键字设置`GET`请求的参数名：

```yaml
    config:
      signing_key: ...
      jwt_url_parameter: "parameter_name"
      subject_key: ...
      roles_key: ...
```

正如HTTP基础认证一样，你应当使用HTTPS代替HTTP。

#### 有效的registered claims

下列registered claims都是自动有效的：

- “iat” (Issued At) Claim
- “nbf” (Not Before) Claim
- “exp” (Expiration Time) Claim

#### 支持的格式和算法

安全插件支持使用下列标准算法进行数字签名、压缩JSON网络令牌：

```
HS256: HMAC using SHA-256
HS384: HMAC using SHA-384
HS512: HMAC using SHA-512
RS256: RSASSA-PKCS-v1_5 using SHA-256
RS384: RSASSA-PKCS-v1_5 using SHA-384
RS512: RSASSA-PKCS-v1_5 using SHA-512
PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
ES256: ECDSA using P-256 and SHA-256
ES384: ECDSA using P-384 and SHA-384
ES512: ECDSA using P-521 and SHA-512
```

## YAML文件

在运行`securityadmin.sh`命令加载配置到`.opendistro_security`索引中前，配置在`plugins/opendistro_security/securityconfig`里的YAML文件。你可能会备份这些文件，这样可以在其它集群中重新使用它们。

使用这些YAML文件最好的方式是配置[保留且隐藏的资源](https://opendistro.github.io/for-elasticsearch-docs/docs/security-access-control/api/#reserved-and-hidden-resources)，例如`admin`和`kibanaserver`用户。你可能会发现使用Kibana和REST API添加其它用户、角色、映射、操作组和租户更方便一些。

### internal_users.yml

该文件包含了任何你想要添加到安全插件的内置用户数据库中的初始用户。

该文件格式要求经过hash处理的密码。运行`plugins/opendistro_security/tools/hash.sh -p <new-password>`生成一个。如果你决定保留这些演示用户的任何一个，*修改它们的密码*。

```yaml
# This is the internal user database
# The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

_meta:
  type: "internalusers"
  config_version: 2

# Define your internal users here
new-user:
  hash: "$2y$12$88IFVl6IfIwCFh5aQYfOmuXVL9j2hz/GusQb35o.4sdTDAEMTOD.K"
  reserved: false
  hidden: false
  backend_roles:
  - "some-backend-role"
  attributes:
    attribute1: "value1"
  static: false

## Demo users

admin:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

kibanaserver:
  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
  reserved: true
  description: "Demo kibanaserver user"

kibanaro:
  hash: "$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC"
  reserved: false
  backend_roles:
  - "kibanauser"
  - "readall"
  attributes:
    attribute1: "value1"
    attribute2: "value2"
    attribute3: "value3"
  description: "Demo kibanaro user"

logstash:
  hash: "$2a$12$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2"
  reserved: false
  backend_roles:
  - "logstash"
  description: "Demo logstash user"

readall:
  hash: "$2a$12$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2"
  reserved: false
  backend_roles:
  - "readall"
  description: "Demo readall user"

snapshotrestore:
  hash: "$2y$12$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W"
  reserved: false
  backend_roles:
  - "snapshotrestore"
  description: "Demo snapshotrestore user"
```

### roles.yml

该文件包含任何你想添加到安全插件中的初始角色。除了一些元数据以外，默认文件内容是空的，因为安全插件有一些静态角色会自动加上。

```yaml
complex-role:
  reserved: false
  hidden: false
  cluster_permissions:
  - "read"
  - "cluster:monitor/nodes/stats"
  - "cluster:monitor/task/get"
  index_permissions:
  - index_patterns:
    - "kibana_sample_data_*"
    dls: "{\"match\": {\"FlightDelay\": true}}"
    fls:
    - "~FlightNum"
    masked_fields:
    - "Carrier"
    allowed_actions:
    - "read"
  tenant_permissions:
  - tenant_patterns:
    - "analyst_*"
    allowed_actions:
    - "kibana_all_write"
  static: false
_meta:
  type: "roles"
  config_version: 2
```

### roles_mapping.yml

```yaml
manage_snapshots:
  reserved: true
  hidden: false
  backend_roles:
  - "snapshotrestore"
  hosts: []
  users: []
  and_backend_roles: []
logstash:
  reserved: false
  hidden: false
  backend_roles:
  - "logstash"
  hosts: []
  users: []
  and_backend_roles: []
own_index:
  reserved: false
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "*"
  and_backend_roles: []
  description: "Allow full access to an index named like the username"
kibana_user:
  reserved: false
  hidden: false
  backend_roles:
  - "kibanauser"
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps kibanauser to kibana_user"
complex-role:
  reserved: false
  hidden: false
  backend_roles:
  - "ldap-analyst"
  hosts: []
  users:
  - "new-user"
  and_backend_roles: []
_meta:
  type: "rolesmapping"
  config_version: 2
all_access:
  reserved: true
  hidden: false
  backend_roles:
  - "admin"
  hosts: []
  users: []
  and_backend_roles: []
  description: "Maps admin to all_access"
readall:
  reserved: true
  hidden: false
  backend_roles:
  - "readall"
  hosts: []
  users: []
  and_backend_roles: []
kibana_server:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
  - "kibanaserver"
  and_backend_roles: []
```

### action_groups.yml

该文件包含任何你想添加到安全插件中的初始操作。除了一些元数据外，默认文件内容是空的，因为安全插件有几个静态操作组会自动添加上。这些静态操作组覆盖了大范围的使用场景，是开始使用插件的一种好途径。

```yaml
my-action-group:
  reserved: false
  hidden: false
  allowed_actions:
  - "indices:data/write/index*"
  - "indices:data/write/update*"
  - "indices:admin/mapping/put"
  - "indices:data/write/bulk*"
  - "read"
  - "write"
  static: false
_meta:
  type: "actiongroups"
  config_version: 2
```

### tenants.yml

```yaml
_meta:
  type: "tenants"
  config_version: 2
admin_tenant:
  reserved: false
  description: "Demo tenant for admin user"
```

## TLS证书

TLS配置在`elasticsearch.yml`中。主要有两个配置模块：传输层和HTTP层。TLS对于REST层是可选的，但在传输层是强制的。

> 你能在[GitHub](https://www.github.com/opendistro-for-elasticsearch/security-ssl/blob/master/opendistrosecurity-ssl-config-template.yml)上找到带有所有选项的示例配置模板。

### X.509 PEM证书和PKCS #8密钥

下列两表内容展示了你能用于配置PEM证书位置和秘钥的设置。

#### 传输层TLS

| 名称                                                       | 说明                                                         |
| :--------------------------------------------------------- | :----------------------------------------------------------- |
| `opendistro_security.ssl.transport.pemkey_filepath`        | 证书密钥文件（PKCS #8）存放的位置，必需在`config`目录下，使用相对路径。必填项。 |
| `opendistro_security.ssl.transport.pemkey_password`        | 密钥密码。密钥没密码时可省略。非必填项。                     |
| `opendistro_security.ssl.transport.pemcert_filepath`       | X.509节点证书链（PEM格式）的路径，必需在`config`目录下，使用相对路径。必填项。 |
| `opendistro_security.ssl.transport.pemtrustedcas_filepath` | 根证书的位置（PEM格式），必需在`config`目录下，使用相对路径。必填项。 |

# 安全-访问控制

# 安全-日志审计

# 警报

# SQL

# 索引状态管理

# 异常侦测

# 性能分析

# 疑难解答

# 其它资源

