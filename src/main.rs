use bitcoin::{
    PrivateKey,
    Address, Network, PublicKey,
};
use hex;
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
    fs::{File, OpenOptions},
    io::{Write, BufWriter},
};

// 彩色输出工具
mod color {
    pub const RESET: &str = "\x1b[0m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BOLD: &str = "\x1b[1m";
}

struct Scanner {
    start: u128,
    end: u128,
    target_address: String,
    found_key: Arc<Mutex<Option<(String, String)>>>,
    processed: Arc<Mutex<u128>>,
    start_time: Arc<Instant>,
    log_file: Arc<Mutex<BufWriter<File>>>,
    last_log_flush: Arc<Mutex<Instant>>,
}

impl Scanner {
    fn new(start_hex: &str, end_hex: &str, target_address: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let start = u128::from_str_radix(start_hex, 16)?;
        let end = u128::from_str_radix(end_hex, 16)?;
        
        // 创建日志文件
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("bitcoin_scanner.log")?;
        let log_writer = BufWriter::new(log_file);
        
        Ok(Scanner {
            start,
            end,
            target_address: target_address.to_string(),
            found_key: Arc::new(Mutex::new(None)),
            processed: Arc::new(Mutex::new(0)),
            start_time: Arc::new(Instant::now()),
            log_file: Arc::new(Mutex::new(log_writer)),
            last_log_flush: Arc::new(Mutex::new(Instant::now())),
        })
    }

    fn format_duration(seconds: f64) -> String {
        if seconds < 60.0 {
            format!("{:.1} 秒", seconds)
        } else if seconds < 3600.0 {
            format!("{:.1} 分钟", seconds / 60.0)
        } else if seconds < 86400.0 {
            format!("{:.1} 小时", seconds / 3600.0)
        } else if seconds < 2592000.0 {
            format!("{:.1} 天", seconds / 86400.0)
        } else if seconds < 31536000.0 {
            format!("{:.1} 月", seconds / 2592000.0)
        } else {
            format!("{:.1} 年", seconds / 31536000.0)
        }
    }

    fn log_message(&self, message: &str, force_flush: bool) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let console_message = format!("[{}] {}", timestamp, message);
        let log_message = format!("[{}] {}", timestamp, Self::strip_colors(message));
        
        // 输出到控制台（带颜色）
        println!("{}", console_message);
        
        // 写入日志文件（无颜色）- 使用超时避免死锁
        self.try_log_to_file(&log_message, force_flush);
    }

    fn log_multiline(&self, title: &str, lines: &[&str], force_flush: bool) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        
        // 输出到控制台（带颜色）
        println!("[{}] {}", timestamp, title);
        for line in lines {
            println!("[{}]   {}", timestamp, line);
        }
        
        // 写入日志文件（无颜色）- 使用超时避免死锁
        let full_message = format!(
            "[{}] {}\n{}",
            timestamp,
            Self::strip_colors(title),
            lines.iter()
                .map(|line| format!("[{}]   {}", timestamp, Self::strip_colors(line)))
                .collect::<Vec<String>>()
                .join("\n")
        );
        
        self.try_log_to_file(&full_message, force_flush);
    }

    fn log_progress(&self, message: &str) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let console_message = format!("[{}] {}", timestamp, message);
        let log_message = format!("[{}] {}", timestamp, Self::strip_colors(message));
        
        // 输出到控制台（带颜色，不换行）
        print!("\r{}", console_message);
        let _ = std::io::stdout().flush();
        
        // 写入日志文件（无颜色，带换行）- 使用超时避免死锁
        self.try_log_to_file(&log_message, false);
    }

    // 尝试写入日志文件，带超时机制
    fn try_log_to_file(&self, message: &str, force_flush: bool) {
        // 尝试获取锁，最多等待100毫秒
        let log_file_lock = match self.log_file.try_lock() {
            Ok(lock) => lock,
            Err(_) => {
                // 如果获取锁失败，只输出到控制台
                return;
            }
        };
        
        let mut file = log_file_lock;
        
        if let Err(e) = writeln!(file, "{}", message) {
            eprintln!("写入日志失败: {}", e);
            return;
        }
        
        // 检查是否需要刷新到磁盘
        let should_flush = force_flush || {
            if let Ok(last_flush) = self.last_log_flush.lock() {
                last_flush.elapsed() > Duration::from_secs(30)
            } else {
                false
            }
        };
        
        if should_flush {
            if let Err(e) = file.flush() {
                eprintln!("刷新日志失败: {}", e);
            }
            if let Ok(mut last_flush) = self.last_log_flush.lock() {
                *last_flush = Instant::now();
            }
        }
    }

    // 移除ANSI颜色代码
    fn strip_colors(text: &str) -> String {
        text.replace("\x1b[0m", "")
            .replace("\x1b[31m", "")
            .replace("\x1b[32m", "")
            .replace("\x1b[33m", "")
            .replace("\x1b[34m", "")
            .replace("\x1b[35m", "")
            .replace("\x1b[36m", "")
            .replace("\x1b[1m", "")
    }

    fn private_key_to_address(&self, private_key_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
        // 将十六进制私钥转换为字节
        let private_key_bytes = hex::decode(private_key_hex)?;
        
        // 创建比特币私钥对象
        let secret_key = PrivateKey::from_slice(&private_key_bytes, Network::Bitcoin)?;
        
        // 生成公钥
        let public_key = PublicKey::from_private_key(&secp256k1::Secp256k1::new(), &secret_key);
        
        // 生成P2PKH地址
        let address = Address::p2pkh(&public_key, Network::Bitcoin);
        
        Ok(address.to_string())
    }

    fn scan_range_forward(&self, start: u128, end: u128, thread_id: usize) {
        let mut current = start;
        let batch_size = 10000;
        
        while current <= end {
            // 检查是否已找到私钥
            if self.found_key.lock().unwrap().is_some() {
                return;
            }
            
            let batch_end = std::cmp::min(current + batch_size as u128 - 1, end);
            
            for i in current..=batch_end {
                // 将十进制转换为十六进制私钥（64个字符，填充前导零）
                let private_key_hex = format!("{:064x}", i);
                
                match self.private_key_to_address(&private_key_hex) {
                    Ok(address) => {
                        if address == self.target_address {
                            let success_message = format!(
                                "{}正向线程 {} 找到匹配的私钥!{}",
                                color::GREEN, thread_id, color::RESET
                            );
                            self.log_message(&success_message, true); // 强制刷新日志
                            
                            // 先设置找到的私钥，确保其他线程知道已找到
                            {
                                let mut found = self.found_key.lock().unwrap();
                                *found = Some((private_key_hex.clone(), address.clone()));
                            }
                            
                            // 然后记录详情
                            let line1 = format!("{}私钥 (HEX): {}{}", color::CYAN, private_key_hex, color::RESET);
                            let line2 = format!("{}私钥 (DEC): {}{}", color::CYAN, i, color::RESET);
                            let line3 = format!("{}比特币地址: {}{}", color::CYAN, address, color::RESET);
                            
                            let details = [
                                line1.as_str(),
                                line2.as_str(),
                                line3.as_str(),
                            ];
                            
                            self.log_multiline("发现私钥详情:", &details, true); // 强制刷新日志
                            return;
                        }
                    }
                    Err(_) => {
                        // 静默处理错误
                    }
                }
            }
            
            // 更新进度
            {
                let mut processed = self.processed.lock().unwrap();
                *processed += (batch_end - current + 1) as u128;
            }
            
            current = batch_end + 1;
        }
    }

    fn scan_range_backward(&self, start: u128, end: u128, thread_id: usize) {
        let mut current = end;
        let batch_size = 10000;
        
        while current >= start {
            // 检查是否已找到私钥
            if self.found_key.lock().unwrap().is_some() {
                return;
            }
            
            let batch_start = if current >= batch_size as u128 {
                current - batch_size as u128 + 1
            } else {
                start
            };
            
            for i in (batch_start..=current).rev() {
                // 将十进制转换为十六进制私钥（64个字符，填充前导零）
                let private_key_hex = format!("{:064x}", i);
                
                match self.private_key_to_address(&private_key_hex) {
                    Ok(address) => {
                        if address == self.target_address {
                            let success_message = format!(
                                "{}反向线程 {} 找到匹配的私钥!{}",
                                color::GREEN, thread_id, color::RESET
                            );
                            self.log_message(&success_message, true); // 强制刷新日志
                            
                            // 先设置找到的私钥，确保其他线程知道已找到
                            {
                                let mut found = self.found_key.lock().unwrap();
                                *found = Some((private_key_hex.clone(), address.clone()));
                            }
                            
                            // 然后记录详情
                            let line1 = format!("{}私钥 (HEX): {}{}", color::CYAN, private_key_hex, color::RESET);
                            let line2 = format!("{}私钥 (DEC): {}{}", color::CYAN, i, color::RESET);
                            let line3 = format!("{}比特币地址: {}{}", color::CYAN, address, color::RESET);
                            
                            let details = [
                                line1.as_str(),
                                line2.as_str(),
                                line3.as_str(),
                            ];
                            
                            self.log_multiline("发现私钥详情:", &details, true); // 强制刷新日志
                            return;
                        }
                    }
                    Err(_) => {
                        // 静默处理错误
                    }
                }
            }
            
            // 更新进度
            {
                let mut processed = self.processed.lock().unwrap();
                *processed += (current - batch_start + 1) as u128;
            }
            
            if batch_start == start {
                break;
            }
            current = batch_start - 1;
        }
    }

    fn start_scan(&self, num_threads: usize) {
        let start_message = format!(
            "{}BTCeek 1.0 [GitHub.com/yzl3014/btceek] {}",
            color::MAGENTA, color::RESET
        );

        self.log_message(&start_message, false);
        
        let start_message = format!(
            "{}开始比特币地址扫描 {}",
            color::BOLD, color::RESET
        );
        self.log_message(&start_message, false);
        
        self.log_message(&format!("目标地址: {}", self.target_address), false);
        self.log_message(&format!(
            "私钥范围: {:x} 到 {:x}", 
            self.start, self.end
        ), false);
        self.log_message(&format!(
            "使用 {} 个线程 ({} 正向 + {} 反向)", 
            num_threads, num_threads/2, num_threads/2
        ), false);
        self.log_message(&format!("日志文件: bitcoin_scanner.log (每30秒刷新)"), false);
        self.log_message("============================================================", false);
        
        let range_size = (self.end - self.start + 1) / (num_threads / 2) as u128;
        let mut handles = vec![];
        
        // 启动正向搜索线程
        for i in 0..num_threads/2 {
            let thread_start = self.start + (i as u128) * range_size;
            let thread_end = if i == num_threads/2 - 1 {
                self.end
            } else {
                thread_start + range_size - 1
            };
            
            self.log_message(&format!(
                "{}正向线程 {} 扫描范围: {:x} 到 {:x}{}",
                color::YELLOW, i, thread_start, thread_end, color::RESET
            ), false);
            
            let scanner = Scanner {
                start: self.start,
                end: self.end,
                target_address: self.target_address.clone(),
                found_key: Arc::clone(&self.found_key),
                processed: Arc::clone(&self.processed),
                start_time: Arc::clone(&self.start_time),
                log_file: Arc::clone(&self.log_file),
                last_log_flush: Arc::clone(&self.last_log_flush),
            };
            
            let handle = thread::spawn(move || {
                scanner.scan_range_forward(thread_start, thread_end, i);
            });
            
            handles.push(handle);
        }
        
        // 启动反向搜索线程
        for i in 0..num_threads/2 {
            let thread_start = self.start + (i as u128) * range_size;
            let thread_end = if i == num_threads/2 - 1 {
                self.end
            } else {
                thread_start + range_size - 1
            };
            
            self.log_message(&format!(
                "{}反向线程 {} 扫描范围: {:x} 到 {:x}{}",
                color::YELLOW, i, thread_end, thread_start, color::RESET
            ), false);
            
            let scanner = Scanner {
                start: self.start,
                end: self.end,
                target_address: self.target_address.clone(),
                found_key: Arc::clone(&self.found_key),
                processed: Arc::clone(&self.processed),
                start_time: Arc::clone(&self.start_time),
                log_file: Arc::clone(&self.log_file),
                last_log_flush: Arc::clone(&self.last_log_flush),
            };
            
            let handle = thread::spawn(move || {
                scanner.scan_range_backward(thread_start, thread_end, i + num_threads/2);
            });
            
            handles.push(handle);
        }
        
        // 主线程负责进度报告
        let mut last_processed = 0;
        let mut last_report_time = Instant::now();
        let total_keys = (self.end - self.start + 1) * 2; // 因为双向搜索，理论上可能扫描两倍密钥
        
        loop {
            thread::sleep(Duration::from_millis(100));
            
            // 检查是否已找到私钥
            if self.found_key.lock().unwrap().is_some() {
                break;
            }
            
            let processed = *self.processed.lock().unwrap();
            
            // 每2秒报告一次进度，或者当进度有显著变化时
            if last_report_time.elapsed() > Duration::from_secs(2) || processed - last_processed > total_keys / 100 {
                let percentage = (processed as f64 / total_keys as f64) * 100.0;
                let elapsed = self.start_time.elapsed().as_secs_f64();
                let keys_per_sec = processed as f64 / elapsed;
                let remaining = total_keys - processed;
                let eta_seconds = if keys_per_sec > 0.0 { remaining as f64 / keys_per_sec } else { 0.0 };
                
                let progress_message = format!(
                    "{}进度: {}/{} ({:.5}%) | 速度: {:.0} 密钥/秒 | ETA: {}{}",
                    color::BLUE, processed, total_keys, percentage, keys_per_sec, 
                    Self::format_duration(eta_seconds), color::RESET
                );
                
                self.log_progress(&progress_message);
                
                last_processed = processed;
                last_report_time = Instant::now();
            }
            
            // 如果所有线程都完成，退出循环
            if processed >= total_keys {
                break;
            }
        }
        
        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }
        
        let elapsed = self.start_time.elapsed();
        self.log_message(&format!(
            "{}扫描完成，耗时: {:.2} 秒{}",
            color::BOLD, elapsed.as_secs_f64(), color::RESET
        ), true); // 强制刷新日志
        
        if let Some(found) = self.found_key.lock().unwrap().as_ref() {
            let success_message = format!(
                "{}成功找到私钥!{}",
                color::GREEN, color::RESET
            );
            self.log_message(&success_message, true); // 强制刷新日志
            self.log_message(&format!("私钥 HEX: {}", found.0), true); // 强制刷新日志
            self.log_message(&format!("对应地址: {}", found.1), true); // 强制刷新日志
        } else {
            let failure_message = format!(
                "{}在指定范围内未找到匹配的私钥{}",
                color::RED, color::RESET
            );
            self.log_message(&failure_message, true); // 强制刷新日志
        }
        
        // 确保所有日志都已写入文件
        if let Ok(mut file) = self.log_file.lock() {
            let _ = file.flush();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 配置扫描参数
    let start_hex = "1000000";    // 十六进制起始
    let end_hex = "1ffffff";      // 十六进制结束
    let target_address = "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP";
    let num_threads = num_cpus::get(); // 使用CPU核心数作为线程数
    
    // 确保线程数为偶数，以便平分给正向和反向搜索
    let num_threads = if num_threads % 2 == 0 { num_threads } else { num_threads - 1 };
    let num_threads = std::cmp::max(2, num_threads); // 至少2个线程
    
    let scanner = Scanner::new(start_hex, end_hex, target_address)?;
    scanner.start_scan(num_threads);
    
    Ok(())
}