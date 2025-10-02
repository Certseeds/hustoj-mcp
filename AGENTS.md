## hustoj-mcp

## for-agnet

1. 使用zh-CN思考, 输出
2. 尽量长的思考

## 实现方式

使用uv管理python3的依赖, 使用框架 `mcp[cli]`

## 目标

目标是为hustOJ开发一个本地单人使用的mcp, 具有以下的功能.

0. 配置, 设置域名, 账户名, 密码三个变量, 并保存到本地一个 dotfile 中
  + [x] set
  + [x] delete
  + [x] show
1. 登录, 将登陆后的token/key等变量存储到本地保存
  + [x] 对应页面 `https://{domain}/onlinejudge/loginpage.php`
2. 获取 `https://{domain}/onlinejudge/problem.php?id={number}` 下的全部描述
  + [x] 已完成
3. 获取 `https://{domain}/onlinejudge/contest.php?cid={number}` 下的题目及其序号
  + 返回格式 List[{"Order": "1470", "Problem": "A"},]
  + [x] 已完成
4. 在 `https://{domain}/onlinejudge/submitpage.php?id={number}`中为指定语言, c, cpp, java提交代码
  + [x] 已完成
  + 结果获取不了
5. 在 `https://{domain}/onlinejudge/problem.php?cid={number}&pid={number}`中为指定语言, c, cpp, java提交代码
  + [x] 已完成
  + 本地没有能提交的contest, 无法测试, 理论上可以执行.

## 参考资料

1. 本地的指定 "hustoj" 目录, 内部存储了最新的hustoj源代码, 可以从中参考具体实现.
