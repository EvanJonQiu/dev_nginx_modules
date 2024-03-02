# 部署和编译环境

需要在Linux环境下编译和部署。

## 相关约束和依赖

1. Linux环境中需要安装gcc，perl
2. 尽量使用非root用户进行编译

### 源代码

1. [nginx-release-1.25.3](https://nginx.org/en/download.html)
2. [openssl-3.2.0](https://www.openssl.org/)
3. [pcre-8.45](https://sourceforge.net/projects/pcre/)
4. [zlib-1.3](https://www.zlib.net/)
5. [jansson-2.14](https://github.com/akheron/jansson)
6. [libjwt-1.17.0](https://github.com/benmcollins/libjwt)

## 安装依赖包
### 安装openssl
1. 将openssl-3.2.0.tar.gz进行解压
2. 执行如下命令
```shell
./Configure
```
3. 编译
```shell
make
```
4. 安装(非root用户)
```shell
sudo make install
```
5. 默认的安装路径为: /usr/local

### 安装jansson
1. 将jansson进行解压
2. 执行如下命令
```shell
./configure
```
3. 编译
```shell
make
```
4. 安装(非root用户)
```shell
sudo make install
```
5. 默认的安装路径为: /usr/local

### 安装libjwt
1. 将libjwt进行解压
2. 执行如下命令
```shell
./configure
```
3. 编译
```shell
make
```
4. 安装(非root用户)
```shell
sudo make install
```
5. 默认的安装路径为: /usr/local

## 配置当前用户的profile
1. 打开当前用户的.bash_profile，写入如下配置项
```bash
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$/usr/local/lib/pkgconfig

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```
2. 配置完成后，为了使其生效，可以在已经打开的terminal中执行
```shell
source ~/.bash_profile
```

## 编译nginx

1. 将nginx源码包进行解压

```shell
tar xvzf nginx-release-1.25.3.tar.gz
```
2. 在nginx目录中创建objs/lib

```shell
mkdir -p objs/lib
```
3. 将openssl,pcre,zlib都解压到objs/lib中
4. 创建html, logs, temp目录
5. 将工程里的html目录下的文件拷贝到新建的html目录下
6. 在nginx目录下执行如下命令：
```shell
./auto/configure \
    --with-cc=gcc \
    --with-debug \
	--builddir=build \
    --prefix= \
    --conf-path=conf/nginx.conf \
    --pid-path=logs/nginx.pid \
    --http-log-path=logs/access.log \
    --error-log-path=logs/error.log \
    --sbin-path=nginx \
    --http-client-body-temp-path=temp/client_body_temp \
    --http-proxy-temp-path=temp/proxy_temp \
    --http-fastcgi-temp-path=temp/fastcgi_temp \
    --http-scgi-temp-path=temp/scgi_temp \
    --http-uwsgi-temp-path=temp/uwsgi_temp \
    --with-cc-opt=-DFD_SETSIZE=1024 \
    --with-pcre=objs/lib/pcre-8.45 \
    --with-zlib=objs/lib/zlib-1.3 \
	--with-openssl=objs/lib/openssl-3.2.0 \
    --with-openssl-opt=no-asm \
    --with-http_ssl_module \
	--with-http_auth_request_module
```
7. 执行如下命令进行编译:
```shell
make -j 10
```
8. 运行,然后通过浏览器访问nginx，以检查nginx是否可以正常运行
```shell
./build/nginx
```
9. 停止
```shell
./build/nginx -s stop
```

### 带ngx_http_study_module编译

10. 在nginx目录下创建modules目录
11. 将ngx_http_sutdy_module拷贝到module目录下
12. 执行configure命令：
```shell
./auto/configure \
    --with-cc=gcc \
    --with-debug \
	--builddir=build \
    --prefix= \
    --conf-path=conf/nginx.conf \
    --pid-path=logs/nginx.pid \
    --http-log-path=logs/access.log \
    --error-log-path=logs/error.log \
    --sbin-path=nginx \
    --http-client-body-temp-path=temp/client_body_temp \
    --http-proxy-temp-path=temp/proxy_temp \
    --http-fastcgi-temp-path=temp/fastcgi_temp \
    --http-scgi-temp-path=temp/scgi_temp \
    --http-uwsgi-temp-path=temp/uwsgi_temp \
    --with-cc-opt=-DFD_SETSIZE=1024 \
    --with-pcre=objs/lib/pcre-8.45 \
    --with-zlib=objs/lib/zlib-1.3 \
	--with-openssl=objs/lib/openssl-3.2.0 \
    --with-openssl-opt=no-asm \
    --with-http_ssl_module \
	--with-http_auth_request_module \
	--add-module=modules/ngx_http_study_module
```
13. 编译
```shell
make
```

### 修改nginx配置文件
可以参考example_config/example_nginx_config.conf进行修改。

14. 打开nginx.conf文件继续编辑
15. 如果是debug版本，则通过如下配置来打开调试日志进行调试（第8行）
```
error_log  logs/error.log  debug;
```
16. 配置日志输出格式，该日志将会以json格式输出到相关日志文件中。（第26-47行）
```
log_format main     escape=json '{'
                                          '"timestamp": "$time_local", '
                                         '"remote_addr": "$remote_addr", '
                                         '"remote_user": "$remote_user", '
                                         '"study_username": "$study_username", '
                                         '"study_service_uri": "$study_service_uri", '
                                         '"request_method": "$request_method", '
                                         '"request_uri": "$request_uri", '
                                         '"request_protocol": "$server_protocol", '
                                         '"request_length": "$request_length", '
                                         '"request_time": "$request_time", '
                                         '"response_status": "$status", '
                                         '"body_bytes_sent": "$body_bytes_sent", '
                                         '"bytes_sent": "$bytes_sent", '
                                         '"http_referer": "$http_referer", '
                                         '"http_user_agent": "$http_user_agent", '
                                         '"http_x_forwarded_for": "$http_x_forwarded_for", '
                                         '"http_host": "$http_host", '
                                         '"server_name": "$server_name", '
                                         '"upstream_addr": "$upstream_addr", '
                                         '"upstream_status": "$upstream_status"'
                                         '}';
```
17. 修改nginx的access日志格式
```
access_log  logs/access.log  main;
```

18. 修改监听地址和端口
```
        listen       8081;
        server_name  192.168.56.106;
```

19. 配置地图服务代理
```
    location /xxx/ {
            access_log  logs/xxx_access.log  main;

            study_root xxx;
            study_rex_str ^/geo/(.*)/(MapServer|FeatureServer|ImageServer|SeceneServer);
            study_jwt_key <your security key>

            rewrite ^/gis/(.*)$ /$1 break;

            proxy_set_header Authorization "";

            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Server $host;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

            proxy_pass https://map.geoq.cn/;
        }
```

