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

-d --domain:设置需要监控的域名，形如:-d http://www.4399.com  注意，此选项必须与-e选项联用

如果-e与-d选项联用，形如：python Beholder.py -d http://www.4399.com  -e 163(即监控http://www.4399.com ,监控邮件发送至163邮箱，具体邮箱地址及授权码配置请至config.py文件中配置)

# 注意事项
若使用了域名监控功能，请手动使用crontab -e 命令将其变为定时任务(不知道这是啥的请自行百度。。。)：

添加的内容类似如下：

\* * * * cd ~/code/Beholder && python Beholder.py -x

(前面四个 * 号表示每过一分钟执行，不知道使用方法者请自行百度。之后的cd语句只需改成你代码所在的目录即可）

如上设置，即可在邮箱中每分钟收到一次子域名变化信息

# Todo:

加入更多好用的子域名查询来源

。。。。。。。。
