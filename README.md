# Clash Convert Script (Mihomo/Clash )

这是一个基于 JavaScript 的 Clash/Mihomo 配置文件处理脚本，专为 **Clash**、**FlClash** 等支持 JS 脚本的客户端设计。它提供了一套极简、高性能且自动化的配置方案。

## 🚀 核心特性

-   **⚡ 高性能精简**：默认采用“直连为主”的逻辑（适合台湾或国际网络环境优化），大幅减少规则条数，提升分流速度。
-   **🤖 智能区域分组**：
    -   自动识别节点名称中的地区信息（美国、日本、香港、台湾、新加坡等）。
    -   **动态显示**：仅当某地区节点数量 **大于 3 个** 时才创建独立的延迟选优分组。
    -   **互斥逻辑**：节点分配具有唯一性，未被分配的节点将自动进入“其他”分组并隐藏。
-   **分流服务定向加速**：
    -   内置专用的分流分组：**AI** (ChatGPT/HuggingFace)、**Google**、**GitHub**、**Telegram**。
    -   各服务分组均支持：节点选择、手动选择、延迟选优及全局直连。
-   **📦 现代规则集**：
    -   集成 [MetaCubeX](https://github.com/MetaCubeX/meta-rules-dat) 的 `.mrs` 格式规则集。
    -   引入 [DustinWin](https://github.com/DustinWin/ruleset_geodata) 的 AI 专用规则。
-   **🛠️ 内核深度优化**：
    -   启用 `tcp-concurrent` (TCP 并发连接) 以加速握手。
    -   启用 `unified-delay` (统一延迟计算)。
    -   持久化存储选中节点 (`store-selected`)。
    -   浏览器指纹伪装 (`chrome`)。

## 🛠️ 如何使用

1.  **获取脚本**：下载 `convert.js` (源码版) 或 `convert.min.js` (转码版)。
2.  **配置客户端**：
    -   **Clash Verge Rev**：在“脚本”菜单中添加该脚本。
    -   **FlClash**：在设置中导入 JS 脚本进行处理。
3.  **订阅配置**：将订阅链接指向该脚本处理后的配置。

## ⚙️ 自定义配置

你可以通过修改 `convert.js` 中的常量来自定义你的分流偏好：

### 添加自定义规则
在 `customRules` 数组中添加你的规则：
```javascript
const customRules = [
    "DOMAIN-SUFFIX,your-domain.com,手动选择", // 指定域名走特定分组
    "DOMAIN-KEYWORD,mykeyword,DIRECT",        // 指定关键字直连
];
```

### 启用/禁用脚本
```javascript
const enableScript = true; // 设置为 false 则直接返回原始配置
```

## 🔗 资源参考

-   **规则集来源**：`MetaCubeX/meta-rules-dat` (Geo 数据集)
-   **图标库**：`Koolson/Qure` 精美彩色图标

---

> [!TIP]
> 默认配置下，未匹配到特定服务或 GFW 列表的流量将通过 **全局直连** 访问。如果你在中国大陆使用且没有全天候开启代理的需求，请根据实际情况调整 `MATCH` 规则或 `customRules`。
