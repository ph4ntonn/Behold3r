# Behold3r
Behold3r是一个子域名收集工具，因为受到了sublert的启发，就想着写点小玩意自娱自乐hhh

# 环境需求
Redis

Python3

# 文件描述
Behold3r.py为主程序

config.py为配置文件，redis相关配置、线程数配置及未来功能的配置都存放在此文件

其中包括邮箱设置：

sender：发件人邮箱

authcode：发件人授权码（在邮箱设置中可以找到）

receiver：收件人邮箱

Email.py 为邮件发送代码

# 参数设置
-u --url:设置要查找的域名，形如:python -u http//:www.example.com

-s --search:设置要查找的域名但不执行收集的操作，仅仅只是从redis数据库中查找保存的对应域名的子域名的历史数据,形如:python -s http//:www.example.com

-c --confirm:设置是否要对查找出来的子域名进行查活操作，形如:python -u http//:www.example.com -c

-r --redis:设置是否需要将查找出来的子域名用redis进行保存，默认不保存。形如:python -u http//:www.example.com -r

           (注意，当-r参数与-c参数连用时，只保存存活的子域名)
-t --timeout:设置查活操作线程的超时时间，默认为5s

-e --email:设置接受监控信息的邮箱（现仅支持qq以及163邮箱），具体参数：-e 163(使用163邮箱)  -e qq（使用qq邮箱）注意，此选项必须与-d选项联用

-d --domain:设置需要监控的域名，形如:-d http://www.4399.com

如果-e的


# Todo:
加入定时查询的功能，监控子域名变化并发送邮件通知用户

加入更多好用的子域名查询来源

。。。。。。。。
