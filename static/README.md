# 微信小程序静态分析 (static/)

对【任意】已缓存的微信小程序做离线静态逆向分析:**解密 → 解包 → 签名/加密定位 → 接口抽取 → 复现代码生成**。一条命令出报告。

与本仓库另一条线(动态调试 / `src/` MCP director)互补:**静态先行**,大多数无混淆小程序读源码即可复现接口;只有参数被运行时加密/JSVMP 混淆时才需要动态抓包。

> ⚠️ 仅用于对【自有 / 已授权】小程序的安全分析与接口对接。解包产物含第三方源码,`static/out/` 已在 `.gitignore` 中,不提交。

## 用法

```bash
# 分析当前在微信里打开的小程序(自动检测)
node static/mp-analyze.mjs --active

# 分析指定 appid(取最新版本)
node static/mp-analyze.mjs <appid>

# 批量分析全部缓存小程序
node static/mp-analyze.mjs --all

# 仅列出缓存里有哪些小程序
node static/mp-analyze.mjs --list

# 指定版本
node static/mp-analyze.mjs <appid> --version 2
```

缓存目录(macOS 微信):
`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/Applet/packages`

## 产物 (`static/out/<appid>/`)

| 文件 | 内容 |
|---|---|
| `app/` | 主包 + 全部命名分包合并后的源码树 |
| `plugins/<key>/` | 插件包(`__PLUGINCODE__`)源码,单独隔离 |
| `report.json` | 结构化分析结果(解包统计 / 签名定位 / API 清单) |
| `REPORT.md` | 人类可读报告 |
| `repro.node.mjs` | Node 接口复现代码(node ≥18,内置 fetch) |
| `repro.python.py` | Python 接口复现代码(requests) |

## 三类判定

工具不只找"签名函数",更靠**签名/加密信号**(拦截器/封装层/安全SDK/响应解密)判定 —— 因为现代小程序的签名几乎都在请求拦截器或安全 SDK 里,不在 `wx.request` 调用点的字面量上。报告给出三类:

- **✅ 无签名**(多数):复现代码可直接填 token/参数运行。
- **🔐 有签名**:定位签名函数/签名信号(`useSign`/`x_ca_sign`/`signWithSiua`/RC4/MD5...),能抽到函数则移植进 Node 复现代码并标注闭包变量与 `npm i` 依赖。
- **🔒 有加解密(疑无业务签名)**:检出响应解密/请求体加密但无明确业务签名挂载,提示人工核对(可能是第三方 SDK/OAuth 自用)。

> 这套信号检测是**对抗式验证**(多个真实 app 读源码核对)后加的 —— 此前纯靠函数名锚点,对重度签名 app 会**误报无签名**(危险假阴性),且 API 严重漏抽(真实上百只抽到个位数)。改用拦截器/安全 SDK/签名头/响应解密多信号联合判定后,分类与人工核对一致,API 召回大幅提升。

## 架构 (`static/lib/`)

```
mp-analyze.mjs            统一 CLI,编排下面四个模块 + 出报告
└─ lib/
   ├─ batch-unpack.mjs    解密(V1MMWX)+解包(0xBE),主包/命名分包/插件包 → 源码树
   ├─ crypto-locate.mjs   签名/加密定位:函数定义锚点+括号配平切片+算法分类+签名串抽取
   ├─ sign-adapter.mjs    把 crypto-locate 的签名函数适配成 codegen 的 signInfo(含闭包变量检测)
   └─ codegen.mjs         wx.request 抽取 + Node/Python 复现代码生成
```

### 关键技术点

- **V1MMWX 解密**:`PBKDF2(appid,"saltiest",1000,32,sha1)` 派生 AES-256-CBC 密钥,解前 1024 字节取前 1023,**XOR key = appid 倒数第二个字符**,对 enc[1024..] 逐字节 XOR。解密 appid 一律取缓存目录名(主包/分包/插件包同此 key)。
- **命名分包零配置合并**:分包内部文件路径自带 app-root 前缀(`/packages/dish/...`),全部解进同一根目录即天然合并,不需 wxappUnpacker 的 `-s`。
- **插件包隔离**:`__PLUGINCODE__` 内部路径相对插件自身根,单独解到 `plugins/<key>/`。
- **压缩代码静态分析**:webpack 压缩成单行,用括号配平切片(string/escape 感知)从函数定义锚点切出函数体;按【调用形式】(`CryptoJS.MD5(`、`HmacSHA256(`)而非裸标识符判定算法,避免 crypto-js 库内定义的全部算法被误报。
- **内容哈希去重**:微信发 `app-service.js` / `appservice.app.js` 孪生文件,按 sha1 去重避免重复计数。

## 已知边界

- base URL 经跨模块配置引用的 webpack app,`extractApis` 给 `{BASE_URL}` 占位待用户填。
- 签名应用在拦截器/封装层而非 `wx.request` 字面量内时,需 `crypto-locate` 显式传 signInfo。
- JSVMP/字符串数组混淆的签名函数:能定位并移植函数体,但引用大量混淆闭包变量,需手动接线(note 会列出)。
- 动态构造的 `data: e` 整体表达式:记为 `{_raw}` 并在生成代码里留 TODO。
