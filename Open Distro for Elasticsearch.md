# Open Distro for Elasticsearch

本文是[Open Distro for Elasticsearch](https://opendistro.github.io/for-elasticsearch/)的技术文档。Open Distro for Elasticsearch是一个社区驱动，100%开源的Elasticsearch发行版本，它实现了高级安全、警报、深度性能分析等其它功能。

***

## 关于

内容目录

1. 为什么使用Open Distro for Elasticsearch？

2. 开始

3. 构建

4. 关于Open Distro for Elasticsearch

***

### 为什么使用Open Distro for Elasticsearch？

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

### 开始

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
### 构建

如果想修改Open Distro for Elasticsearch代码并从自己的源构建，指令在[opendistro-build](https://github.com/opendistro-for-elasticsearch/opendistro-build)仓库的`elasticsearch/README.md`和`kibana/README.md`文件中。同样的，你能在各种插件自己的仓库中找到这些指令。如果你的修改也有益于其它人，请考虑提交一个pull request。

***

### 关于Open Distro for Elasticsearch

[Open Distro for Elasticsearch](https://opendistro.github.io/for-elasticsearch/)由Amazon Web Service支持。所有组件都支持[GitHub](https://github.com/opendistro-for-elasticsearch/)上的[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)协议。

本项目欢迎提供GitHub issue、bug修改、特性、插件、文档等任何东西。想参与进来吗，见Open Distro for Elasticsearch网站上的[Contribute](https://opendistro.github.io/for-elasticsearch/contribute.html)。

***

## 版本历史

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

## 安装与配置

Open Distro for Elasticsearch有以下几种下载选项：Docker镜像、RPM包、Debian包和压缩包。

***

内容目录

- [Docker](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/)
- [RPM](https://opendistro.github.io/for-elasticsearch-docs/docs/install/rpm/)
- [Debian包](https://opendistro.github.io/for-elasticsearch-docs/docs/install/deb/)
- [Docker安全配置](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker-security/)
- [压缩包](https://opendistro.github.io/for-elasticsearch-docs/docs/install/tar/)
- [单独的Elasticsearch插件安装](https://opendistro.github.io/for-elasticsearch-docs/docs/install/plugins/)
- [其它组件](https://opendistro.github.io/for-elasticsearch-docs/docs/install/other-components/)
- [Rest加密](https://opendistro.github.io/for-elasticsearch-docs/docs/install/encryption-at-rest/)

***

### Docker

你可以像其它镜像一样拉取Open Distro for Elasticsearch的Docker镜像：

```sh
docker pull amazon/opendistro-for-elasticsearch:1.2.0
docker pull amazon/opendistro-for-elasticsearch-kibana:1.2.0
```

上[Docker Hub](https://hub.docker.com/r/amazon/opendistro-for-elasticsearch/tags)获取更多可用的版本。

Open Distro for Elasticsearch镜像使用`centos:7`作为基本镜像。如果你在本地运行Docker，我们推荐在**Preferences** > **Advanced**中设置至少4GB大小的内存。

***

内容目录：

1. [运行镜像](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#run-the-image)
2. [开启集群](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#start-a-cluster)
3. [配置Elasticsearch](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#configure-elasticsearch)
4. [使用Bash访问容器](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#bash-access-to-containers)
5. [重要配置](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#important-settings)
6. [自定义插件](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#run-with-custom-plugins)

***

#### 运行镜像

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

#### 开启集群

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

##### DOCKER COMPOSE示例文件

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

#### 配置Elasticsearch

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

#### 使用Bash访问容器

要在容器中创建一个交互的Bash会话，运行`docker ps` 找到容器ID。然后运行：

```sh
docker exec -it <container-id> /bin/bash
```

#### 重要配置

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

#### 自定义插件

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

### RPM

### Debian包

### Docker安全配置

### 压缩包

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

#### 配置

你可以修改`config/elasticsearch.yml`或者在`-E`参数中添加环境变量:

```shell
./opendistro-tar-install.sh -Ecluster.name=odfe-cluster -Enode.name=odfe-node1 -Ehttp.host=0.0.0.0 -Ediscovery.type=single-node
```

在[重要配置](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker/#important-settings)中查看其它设置。

### 单独的Elasticsearch插件安装

### 其它组件

### Rest加密

## 升级

## Elasticsearch

## Kibana

## 安全-配置

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

### 开始

插件包含了一个演示证书，所以你可以快速上手和运行，但在产品环境中使用之前，你需要手动配置：

1. [替换演示证书](https://opendistro.github.io/for-elasticsearch-docs/docs/install/docker-security/)
2. [重新在`elasticsearch.yml`配置你自己的证书](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
3. [重新在`config.yml`配置你自己的后端认证](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/) (如果你不打算使用内置用户数据库)
4. [修改YAML文件中的配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/yaml/)
5. [使用securityadmin.sh应用修改](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/security-admin/)
6. [添加用户、角色、角色映射和租户](https://opendistro.github.io/for-elasticsearch-docs/docs/security-access-control/)

如果你不想使用该插件，见[禁止安全](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/disable/).

***

### 身份认证流

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

### 后台程序配置

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

***

内容目录

1. [HTTP](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#http)

2. [身份认证](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#authentication)

3. [权限管理](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#authorization)

4. [示例](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#examples)

5. [HTTP基础](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#http-basic)

6. Kerberos

      a. [动态配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#dynamic-configuration)

      b. [后台认证](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#authentication-backend)

7. JSON web token

      a. [请求头](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#header)

      b. [Payload](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#payload)

      c. [Signature](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#signature)

      d. [Configure JSON web tokens](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#configure-json-web-tokens)
   e. [Symmetric key algorithms: HMAC](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#symmetric-key-algorithms-hmac)
   f. [Asymmetric key algorithms: RSA and ECDSA](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#asymmetric-key-algorithms-rsa-and-ecdsa)
   g. [Bearer authentication for HTTP requests](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#bearer-authentication-for-http-requests)
   h. [URL parameters for HTTP requests](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#url-parameters-for-http-requests)
   i. [Validated registered claims](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#validated-registered-claims)
   j. [Supported formats and algorithms](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/configuration/#supported-formats-and-algorithms)

#### HTTP

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

#### 身份认证

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

`http_authenticator`指定了你想在HTTP层使用哪种认证方法。

下面是在HTTP层定义一个认证器的语法：

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
- `ldap`：通过LDAP服务对用户进行身份认证。该设置需要额外配置[LDAP-specific配置](https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/ldap/)。

#### 权限管理



## 安全-访问控制

## 安全-日志审计

## 警报

## SQL

## 索引状态管理

## 异常侦测

## 性能分析

## 疑难解答

## 其它资源

