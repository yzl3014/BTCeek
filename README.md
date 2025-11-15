# BTCeek

一个用于解决Bitcoin Puzzle的比特币私钥扫描器。

## 配置说明

在 `main()` 函数中修改以下参数：
```rust
// 私钥范围（十六进制）
let start_hex = "1000000";    // 十六进制起始
let end_hex = "1ffffff";      // 十六进制结束
// 目标比特币地址
let target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP";
// 线程数量（自动设置为CPU核心数）
let num_threads = num_cpus::get();
```

上述信息可以在 [BTC Puzzle](https://btcpuzzle.info/zh/puzzle) 网站找到。

构建项目：
```bash
cargo build --release
```

运行：
```bash
cargo run --release
```

## 输出示例

图示程序运行在一台2015年的老旧笔记本电脑上，搭载了`Intel Core i7-4510U`。

<img width="1290" height="440" alt="image" src="https://github.com/user-attachments/assets/27bd0ae4-aef5-4078-93c7-f7eacaf82f93" />

## 许可证

[MIT](LICENSE)
