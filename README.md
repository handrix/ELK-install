ELK日志监控系统安装手册
=====
撰写背景
---
由于某些需求，需要构建一套日志管理系统，所以老大就让我们搭一套ELK，此文档记录了搭建时的一些坑。

整体架构
---

该日志收集系统分两大块，即服务端与客户端：

- 服务端：即接受日志的服务器，日志在这里建立索引并在kibana呈现。
- 客户端：日志生产者

ELK整套系统在centOS上的安装分一下几个步骤：

- java
- Logstash
- Elasticsearch
- Kibana
- Filebeat
- Nginx

下面对其安装方式进行依次讲解

java
--
亲测java7存在不可描述的问题，所以请安装java8。

```
cd ~
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
# 之后别忘删除源文件
rm ~/jdk-8u*-linux-x64.rpm
```

Elasticsearch
---
#### 安装：
```
sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch

# 下面到 | sudo tee /etc/yum.repos.d/elasticsearch.repo为止是一条命令
echo '[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/elasticsearch.repo

sudo yum -y install elasticsearch
```
#### 配置：
```
sudo vi /etc/elasticsearch/elasticsearch.yml
```
在vi的命令模式下输入`：/network.host`找到对应代码
取消network.host的注释，并将其改为：
```
network.host: localhost
```
#### 启动服务：
```
# 启动
sudo systemctl start elasticsearch
# 开机自启动
sudo systemctl enable elasticsearch
```
注：最好检查一下运行状态，如果没能成功启动请看下面的步骤，如果成功请跳至下条：
```
sudo systemctl status elasticsearch
```
#### 如果失败：
极有可能是多版本遗留文件冲突所至，所以全都干掉再重装就好啦：
```
find -name "elasticsearch" | args sudo rm -rf
# 之后再重复安装的步骤。。。
```

Kibana
---
整个流程中最顺畅的步骤，目前没发现坑：
#### 安装
```
sudo vi /etc/yum.repos.d/kibana.repo
# 写入以下内容：
[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
# 安装
sudo yum -y install kibana
```
#### 配置
```
sudo vi /opt/kibana/config/kibana.yml
```
找到`server.host`并将其改为
```
server.host: "localhost"
```
#### 启动服务
```
sudo systemctl start kibana
sudo chkconfig kibana on
```

Nginx
---
因为我们的kibana监听了localhost，所以需要nginx作为反向代理，允许外部访问
注：安装前请启用SSL / TLS
#### 安装
```
sudo yum -y install epel-release
sudo yum -y install nginx httpd-tools
```
#### 配置
建立用户：
```
# 其中XXX为用户名，请自行更改，在键入一下命令后会提示设置密码
sudo htpasswd -c /etc/nginx/htpasswd.users XXX
```
更改配置：
打开配置文件
```
sudo vi /etc/nginx/nginx.conf
```
找到其中的`server {`配置块，将其内容删除并添加如下一行：
```
include /etc/nginx/conf.d/*.conf;
```
打开kibana配置文档
```
sudo vi /etc/nginx/conf.d/kibana.conf
```
输入如下内容，记得改`server_name`本机ip即可
```
server {
    listen 80;

    server_name example.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;        
    }
}
```
#### 启用服务
```
sudo systemctl start nginx
sudo systemctl enable nginx
```
此外建议禁用SELinux
```
sudo setsebool -P httpd_can_network_connect 0
```

Logstash
---

#### 安装
```
sudo vi /etc/yum.repos.d/logstash.repo
# 写入
[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
# 安装
sudo yum -y install logstash
```

#### 配置
在阅读这部分文档之前建议先阅读SSL证书相关的内容，以下步骤皆为`vi`打开文档然后输入内容，故不再做文字描述：
```
###
sudo vi /etc/logstash/conf.d/02-beats-input.conf
###
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
###
sudo vi /etc/logstash/conf.d/10-syslog-filter.conf
###
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
###
sudo vi /etc/logstash/conf.d/30-elasticsearch-output.conf
###
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
```
对以上内容做一个简单的解释，logstash分三个步骤。
- input：即输入，本文档采用filebeats的方式收录log，故需要ssl密钥地址
- filter：即过滤规则，本文档采用grok（基于正则表达式）作为过滤规则
- output： 即输出端，本文当中日志输出给elasticsearch
用一下命令检查配置中是否有错误
```
sudo service logstash configtest
```
如显示`Configuration OK`则表示通过
#### 启用服务
```
sudo systemctl restart logstash
sudo chkconfig logstash on
```

SSL证书
--
ssl作为`filebeats`连接服务端的密钥，在搭建环节中是必不可少的：
打开ssl配置文档
```
sudo vi /etc/pki/tls/openssl.cnf
```
找到`[ v3_ca ]`部分
其中`ELK_server_private_ip`为服务端机器ip地址
```
subjectAltName = IP: ELK_server_private_ip
```
生成密钥：
```
cd /etc/pki/tls
sudo openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
```
生产环境中需要把该密钥发送到服务端机器，此文档中省略在后续`fabfile`中补充

kibana相关配置
---
#### 加载仪表盘
```
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
# 如已安装unzip可略过
sudo yum -y install unzip
# 提取内容
unzip beats-dashboards-*.zip
# 运行脚本
cd beats-dashboards-* && ./load.sh
```
#### 在Elasticsearch中加载Filebeat索引模板

```
cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json
```
如果操作正确会得到如下输出:
```
{
  "acknowledged" : true
}
```

Filebeat
----

#### 安装
```
sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
# 打开beats配置文档
sudo vi /etc/yum.repos.d/elastic-beats.repo
# 写入
[beats]
name=Elastic Beats Repository
baseurl=https://packages.elastic.co/beats/yum/el/$basearch
enabled=1
gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
gpgcheck=1
# 安装
sudo yum -y install filebeat
```

#### 配置

创建配置文档
```
sudo vi /etc/filebeat/filebeat.yml
```
搜索`prospectors`并找到`path:`,注销掉`- /var/log/*.log`，并输入：
```
      paths:
        - /var/log/secure
        - /var/log/messages
#        - /var/log/*.log
```
搜索`document_type`
```
document_type: syslog
```
搜索`output`并找到`elasticsearch`,注销掉其全部内容，我们不做filebeats与elasticsearch的关联,
同样是`output`处，搜索`### Logstash as output`并将其改为如下模样：
```
  ### Logstash as output
  logstash:
    # The Logstash hosts
    hosts: ["ELK_server_private_IP:5044"]
```
设置`bulk_max_size: 1024`
最后来到`tls`部分，配置我们的密钥地址：
```
...
    tls:
      # List of root certificates for HTTPS server verifications
      certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]
```
#### 启动服务
```
sudo systemctl start filebeat
sudo systemctl enable filebeat
```

测试安装
---

```
curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty'
```
如果见到类似于如下的输出则配置正确，如若不是请查找上述步骤是否有遗漏
```
...
{
      "_index" : "filebeat-2016.01.29",
      "_type" : "log",
      "_id" : "AVKO98yuaHvsHQLa53HE",
      "_score" : 1.0,
      "_source":{"message":"Feb  3 14:34:00 rails sshd[963]: Server listening on :: port 22.","@version":"1","@timestamp":"2016-01-29T19:59:09.145Z","beat":{"hostname":"topbeat-u-03","name":"topbeat-u-03"},"count":1,"fields":null,"input_type":"log","offset":70,"source":"/var/log/auth.log","type":"log","host":"topbeat-u-03"}
    }
```

在kibana中查看归档日志
---
打开kibana界面（之前nginx映射的地址）
![配置默认索引模式](https://www.howtoing.com/wp-content/uploads/articles/elk/1-filebeat-index.gif)
![查看结果](https://www.howtoing.com/wp-content/uploads/articles/elk/2-filebeat-discover.png)
安装完成！

参考文献
---
主要基于[这篇](https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7)文章来完成本文档的撰写
