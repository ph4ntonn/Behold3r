# Behold3r
Behold3r是一个子域名收集工具，因为受到了sublert的启发，就想着写点小玩意自娱自乐hhh

# 环境需求
Redis

Python3

# 参数设置
-u --url:设置要查找的域名，形如:python -u http//:www.example.com

-s --search:设置要查找的域名但不执行收集的操作，仅仅只是从redis数据库中查找保存的对应域名的子域名的历史数据,形如:python -s http//:www.example.com

-c --confirm:设置是否要对查找出来的子域名进行查活操作，形如:python -u http//:www.example.com -c

-r --redis:设置是否需要将查找出来的子域名用redis进行保存，默认不保存。形如:python -u http//:www.example.com -r

           (注意，当-r参数与-c参数连用时，只保存存活的子域名)
-t --timeout:设置查活操作线程的超时时间，默认为5s

# Todo:
加入定时的
