---
name: "zip-password-recovery"
description: "Recovers forgotten passwords of ZipCrypto-encrypted zips via encryption-type inspection, cross-file verification, and multi-threaded brute-force/dictionary attacks. Invoke when a user forgot a zip password and needs to crack or extract it."
---

# Zip 压缩包密码破解（ZipCrypto）

## 适用场景（何时使用本 Skill）

- 用户忘记 zip 压缩包密码、源文件已删除，需要找回密码并解压。
- 压缩包使用**传统 ZipCrypto 加密**时可快速暴力破解。
- 若压缩包使用 **AES 加密**，暴力破解基本不可行，只能做字典攻击，需提前告知用户预期。

> ⚠️ 仅用于用户自己的文件或已获授权的安全测试，不要用于未授权内容。

---

## 核心方法论（按顺序执行，正确性优先于速度）

```
侦察加密类型 → 理解加密算法 → 设计可靠校验(防假阳性) → 选执行方案(先Python后Java) → 搜索空间排序 → 验证并解压
```

---

## 第 1 步：侦察——判断加密类型（可行性评估）

这一步决定"能不能破解、能多快破解"，**必须先做**。

- ZipCrypto 传统加密：`flag_bits` 含 `0x1`，且额外字段里**没有** `0x9901`（AES 标记）。
- AES 加密：存在 `0x9901` extra field。

```python
# inspect_zip.py
import zipfile

z = zipfile.ZipFile(ZIP_PATH)
for i in z.infolist():
    enc = bool(i.flag_bits & 0x1)
    aes = any(i.extra[k] == 0x99 and i.extra[k+1] == 0x01 for k in range(len(i.extra)-1))
    print(repr(i.filename), "encrypted=", enc, "AES=", aes, "flag_bits=", hex(i.flag_bits))
```

---

## 第 2 步：理解 ZipCrypto 算法（用于自己写轻量校验）

读 Python 标准库 `zipfile.py` 的 `_ZipDecrypter`，要点：

1. 三个 32 位密钥初始化：`k0=0x12345678`、`k1=0x23456789`、`k2=0x34567890`。
2. 逐字节喂入密码做 CRC 混合更新（见下方 `pw_keys`）。
3. 加密文件头 12 字节，最后一个字节解密后必须等于文件 CRC 高 8 位（`check_byte`）。
4. **单个文件校验只有 1/256 误判率** —— 这是假阳性的根源。

---

## 第 3 步：可靠校验——多文件交叉验证（防假阳性）

**关键教训**：只用少量文件校验 + "命中即提前退出" 会产生假阳性（如密码 `4435324` 通过了 3 个文件校验但真实解压失败）。

正确做法是**两阶段过滤 + 不提前退出**：

- **阶段一**：只对 1 个文件校验（成本低，1/256 误判，快速筛掉约 99.6% 错误密码）。
- **阶段二**：对剩余 7 个文件校验（仅少数候选走到这，误判率趋近 0）。
- 最终必须用 `zipfile.open(pwd=...)` 真实解压确认才算命中。

```python
# 校验字节计算（脱离 zipfile，用于高速穷举）
def _gen_crc_table():
    t = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        t.append(c)
    return t

CRC = _gen_crc_table()

def pw_keys(pw):
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
    for b in pw:
        k0 = (k0 >> 8) ^ CRC[(k0 ^ b) & 0xff]
        k1 = (k1 + (k0 & 0xff)) & 0xffffffff
        k1 = (k1 * 134775813 + 1) & 0xffffffff
        k2 = (k2 >> 8) ^ CRC[(k2 ^ (k1 >> 24)) & 0xff]
    return k0, k1, k2

def header_last(k0, k1, k2, header):
    c = 0
    for i in range(12):
        k = k2 | 2
        c = header[i] ^ (((k * (k ^ 1)) >> 8) & 0xff)
        k0 = (k0 >> 8) ^ CRC[(k0 ^ c) & 0xff]
        k1 = (k1 + (k0 & 0xff)) & 0xffffffff
        k1 = (k1 * 134775813 + 1) & 0xffffffff
        k2 = (k2 >> 8) ^ CRC[(k2 ^ (k1 >> 24)) & 0xff]
    return c

def check_password(pw):
    k0, k1, k2 = pw_keys(pw)
    if header_last(k0, k1, k2, T0_HEADER) != T0_CB:   # 阶段一：1 个文件快速过滤
        return False
    for header, cb in REST:                             # 阶段二：其余 7 个文件确认
        if header_last(k0, k1, k2, header) != cb:
            return False
    return True
```

> 用 Python 标准库 `_ZipDecrypter(tp)(header)[11]` 对已知密码做 **self-test**，确认自己的校验函数与标准库完全一致再开始穷举。

---

## 第 4 步：执行方案——先 Python 后 Java（性能跃迁）

- **Python**：开发最快，适合侦察、写校验、小规模验证；但纯循环 ZipCrypto 仅约 30 万次/秒，不足以大规模穷举。
- **Java**：JIT 编译接近原生速度，多线程成熟，实测约 4000~5000 万次/秒，**快百倍**。

暴力破解是"尴尬并行"（每个密码独立校验、互不依赖），直接按 CPU 核数切片并行。

```java
// Crack.java 核心片段（用 long 存 32 位密钥避免符号问题；--release 8 编译兼容旧 JVM）
static int headerLast(long k0, long k1, long k2, byte[] header) {
    int c = 0;
    for (int i = 0; i < 12; i++) {
        long k = k2 | 2L;
        c = (header[i] & 0xff) ^ (int)(((k * (k ^ 1)) >>> 8) & 0xff);
        k0 = (k0 >>> 8) ^ CRC[(int)((k0 ^ c) & 0xff)];
        k1 = (k1 + (k0 & 0xff)) & 0xffffffffL;
        k1 = (k1 * 134775813L + 1) & 0xffffffffL;
        k2 = (k2 >>> 8) ^ CRC[(int)((k2 ^ (k1 >>> 24)) & 0xff)];
    }
    return c;
}

// 主循环：每线程负责一段 [start, end)，用 volatile FOUND 做全局命中标记
static void worker(byte[] cs, int len, int base, long start, long end, AtomicLong checked) {
    byte[] pw = new byte[len];
    for (long idx = start; idx < end; idx++) {
        if (FOUND != null) return;
        long x = idx;
        for (int j = len - 1; j >= 0; j--) { pw[j] = cs[(int)(x % base)]; x /= base; }
        if (checkPassword(pw)) { synchronized (LOCK) { if (FOUND == null) FOUND = new String(pw, US_ASCII); } return; }
    }
}
```

---

## 第 5 步：搜索空间排序（按命中概率 × 成本）

不要乱搜，按以下顺序：

1. **字典**：常见密码 + 从文件名/文件夹名提取的日期规律（如 `2024`、`240903`、`290` 等）。
2. 纯数字 1~10 位。
3. 小写字母 1~6 位。
4. 小写字母 + 数字 1~6 位。
5. 大小写字母 + 数字、可打印字符（兜底）。

---

## 第 6 步：验证并解压

找到候选密码后，用真实解压做最终确认，再全量解压：

```python
# extract.py
z = zipfile.ZipFile(ZIP_PATH)
info = next(i for i in z.infolist() if not i.is_dir() and (i.flag_bits & 0x1))
with z.open(info.filename, pwd=PWD) as f:      # 最终确认
    assert f.read(16)
for info in z.infolist():
    pwd = PWD if (info.flag_bits & 0x1) and not info.is_dir() else None
    z.extract(info, OUT_DIR, pwd=pwd)
```

---

## 常见坑（务必注意）

| 坑 | 表现 | 对策 |
|---|---|---|
| 假阳性 | 密码通过少量文件校验但解压失败 | 多文件交叉验证 + 真实解压确认 + 不提前退出 |
| Python 太慢 | 纯循环穷举以分钟计 | 换成 Java + 多线程 |
| `java`/`javac` 版本不匹配 | 编译成功但运行报错 | 用 `javac --release 8` 编译 |
| 终端中文乱码 | 路径/文件名含中文导致输出乱码 | 把输出重定向到文件再读文件 |
| AES 加密 | 无法快速破解 | 只做字典攻击，提前告知用户预期 |
