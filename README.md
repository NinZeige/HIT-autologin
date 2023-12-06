# 哈工大校园网自动登录脚本

🚧 WIP

- [x] 运行一次可以成功登录
- [ ] 监控并自动登录
- [x] 校本部
- [ ] 深圳校区
- [ ] 没有认识的威海同学, 欢迎PR 

## 如何使用

修改`username`, `password`, 然后运行

```py
if __name__ == "__main__":
    username = "输入学号加创新学分"
    password = "won't tell you :)"
    # uncomment to trace
    # basicConfig(level=INFO)
    ctx = get_challenge(username, password)
    url = meet_challenge(ctx)
    login(url)
```

如果对登录结果不自信, 可解注释`basicConfig(level=INFO)`查看网络请求的结果

## 初步打算

目前仅仅实现了运行后能完成登录的功能

初步计划实现后台检测连接校园网, 当连接上HIT-WLAN且不能连接的时候自动执行登录的过程

## 动机

- 聪明的NetworkManager认证窗口不能记住密码
- 动手练习编程寄巧
- 考完计网比较闲
- 对自己动手能力过分自信

# 故事线

2023年12月, 当nzg在某个下午再次因为不想输网络认证密码时, 他决定不再忍气吞声, 他成功说服了自己的电脑和GPT同他一起踏上开发自动登录脚本的道路, 他持非常乐观的态度向它们描绘最多半个小时就可以解决这个问题的美好前景, 随后花了一个晚上

对于试图实现类似功能的人也可以作为参考

认证过程大致如下

- 客户端发起`get_challenge`请求, 请求服务器提供`token`
- 客户端根据服务器提供的`token`, 计算密码的HMAC-MD5值, 计算整个请求的`checksum`, 以及一个`info`签名
- 客户端组装一个包含上面字段的查询, 服务器收到后验证正确性并准予使用网络

## 发起的请求

两次

- `get_challenge` 请求
- `callback` 请求

## 坑

### 神秘的`info()`

个人水平所限, 没有看出`xEncode`, `s`, `l`都是什么算法, 所以只能试图用python重新实现了这些函数, 而原代码精妙地利用了JS语法特性做了很多trick, 导致实现的时候颇有坎坷

> 一个有意思的点, `s()`和`l()`是互逆的

### `base64` 编码问题

**tldr**: 认证端使用的base64编码有问题, 用现成的库算不出它需要的编码

> 1. 有人上来非常自信地调了库, 并相信这肯定是没有问题的
> 2. 随后发现原网页中base64还偷偷改了字母表, 做了二次映射, 于是写了个mapping验证了一下, 在网页控制台和python反复比对, 再次确认没有问题
> 3. 然后调试的时候就发现`info`的值计算出来始终不对, 而每个函数看起来结果都一样, 就是组装起来结果不对

网页端里面的base64编码:

```js
for (i = 0; i < imax; i += 3) {
    b10 = (getbyte(s, i) << 16) | (getbyte(s, i + 1) << 8) | getbyte(s, i + 2);
    x.push(ALPHA.charAt(b10 >> 18));
    x.push(ALPHA.charAt((b10 >> 12) & 63));
    x.push(ALPHA.charAt((b10 >> 6) & 63));
    x.push(ALPHA.charAt(b10 & 63));
}
```

这个base64编码当且仅当单字节编码的时候是对的

所以需要手动实现这个错误的base64编码 \:\)


