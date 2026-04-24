// ========================================
// Clash 覆写脚本
// 特点：
// 1. 默认直连
// 2. AI / Google 等走代理
// 3. 自动地区分组
// 4. 规则少、维护简单
// ========================================

const enableScript = true;

// ========== 自定义规则 ==========
const customRules = [
    "DOMAIN-SUFFIX,linux.do,手动选择",
    "DOMAIN-SUFFIX,huggingface.co,AI",
    "DOMAIN-KEYWORD,google,Google",
    "DOMAIN-KEYWORD,higress,DIRECT",
];

// ========== 常量 ==========
const RULE_BASE =
    "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo";

const ICON =
    "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color";

// ========== 分组名称 ==========
const GROUP = {
    SELECT: "节点选择",
    MANUAL: "手动选择",
    TEST: "延迟选优",
    DIRECT: "全局直连",
};

// ========== 通用参数 ==========
const ruleCommon = {
    type: "http",
    format: "mrs",
    interval: 86400,
};

const groupCommon = {
    interval: 600,
    timeout: 3000,
    lazy: true,
};

// ========== Rule Provider ==========
function rp(name, behavior = "domain") {
    const dir = behavior === "ipcidr" ? "geoip" : "geosite";
    return {
        ...ruleCommon,
        behavior,
        url: `${RULE_BASE}/${dir}/${name}.mrs`,
        path: `./ruleset/${name}.mrs`,
    };
}

const ruleProviders = {
    private: rp("private"),
    cn: rp("cn"),
    ipprivate: rp("private", "ipcidr"),
    ipcn: rp("cn", "ipcidr"),

    google: rp("google"),
    github: rp("github"),
    telegram: rp("telegram"),
    telegramcidr: rp("telegram", "ipcidr"),
    docker: rp("docker"),
    gfw: rp("gfw"),
    tld: rp("tld-!cn"),

    ai: {
        ...ruleCommon,
        behavior: "domain",
        url:
            "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ai.mrs",
        path: "./ruleset/ai.mrs",
    },
};

// ========== 规则 ==========
const rules = [
    ...customRules,

    "RULE-SET,ipprivate,全局直连,no-resolve",
    "RULE-SET,ipcn,全局直连,no-resolve",
    "RULE-SET,private,全局直连",
    "RULE-SET,cn,全局直连",

    "RULE-SET,ai,AI",
    "RULE-SET,google,Google",
    "RULE-SET,github,GitHub",
    "RULE-SET,telegram,Telegram",
    "RULE-SET,telegramcidr,Telegram",
    "RULE-SET,docker,Docker",

    "RULE-SET,gfw,节点选择",
    "RULE-SET,tld,节点选择",

    "MATCH,全局直连",
];

// ========== 创建代理组 ==========
function group(name, type, extra = {}) {
    return {
        ...groupCommon,
        name,
        type,
        ...extra,
    };
}

// ========== 地区 ==========
const regions = [
    { name: "🇺🇸 美国", matcher: "美国|🇺🇸|\\bUS\\b|United States|America", code: "us" },
    { name: "🇯🇵 日本", matcher: "日本|🇯🇵|\\bJP\\b|Japan", code: "jp" },
    { name: "🇰🇷 韩国", matcher: "韩|🇰🇷|\\bKR\\b|korea", code: "kr" },
    { name: "🇸🇬 新加坡", matcher: "新加坡|🇸🇬|\\bSG\\b|狮城|Singapore", code: "sg" },
    { name: "🇭🇰 香港", matcher: "香港|🇭🇰|\\bHK\\b|Hong Kong|HongKong", code: "hk" },
    { name: "🇨🇳 台湾", matcher: "台湾|🇹🇼|\\bTW\\b|taiwan|tai wan", code: "tw" },
    { name: "🇬🇧 英国", matcher: "英|🇬🇧|\\bUK\\b|united kingdom|great britain", code: "gb" },
    { name: "🇫🇷 法国", matcher: "法国|🇫🇷|\\bFR\\b|France", code: "fr" },
    { name: "🇩🇪 德国", matcher: "德国|🇩🇪|\\bDE\\b|germany", code: "de" },
    { name: "🇵🇱 波兰", matcher: "波兰|🇵🇱|Poland|\\bPL\\b", code: "pl" },
    { name: "🇳🇱 荷兰", matcher: "荷兰|🇳🇱|\\bNL\\b|Netherlands", code: "nl" },
    { name: "🇮🇪 爱尔兰", matcher: "爱尔兰|🇮🇪|\\bIE\\b|Ireland", code: "ie" },
    { name: "🇸🇪 瑞典", matcher: "瑞典|🇸🇪|\\bSE\\b|Sweden", code: "se" },
    { name: "🇷🇺 俄罗斯", matcher: "俄罗斯|🇷🇺|\\bRU\\b|Russia", code: "ru" },
    { name: "🇮🇹 意大利", matcher: "意大利|🇮🇹|\\bIT\\b|Italy", code: "it" },
    { name: "🇪🇸 西班牙", matcher: "西班牙|🇪🇸|\\bES\\b|Spain", code: "es" },
    { name: "🇵🇹 葡萄牙", matcher: "葡萄牙|🇵🇹|\\bPT\\b|Portugal", code: "pt" },
    { name: "🇹🇷 土耳其", matcher: "土耳其|🇹🇷|\\bTR\\b|Turkey", code: "tr" },
    { name: "🇦🇷 阿根廷", matcher: "阿根廷|🇦🇷|\\bAR\\b|Argentina", code: "ar" },
    { name: "🇨🇦 加拿大", matcher: "加拿大|🇨🇦|\\bCA\\b|Canada", code: "ca" },
    { name: "🇦🇺 澳大利亚", matcher: "澳大利亚|🇦🇺|\\bAU\\b|Australia", code: "au" },
    { name: "🇮🇷 伊朗", matcher: "伊朗|🇮🇷|\\bIR\\b|Iran", code: "ir" },
    { name: "🇮🇩 印尼", matcher: "印度尼西亚|印尼|🇮🇩|\\bID\\b|Indonesia", code: "id" },
    { name: "🇲🇾 马来西亚", matcher: "马来|🇲🇾|\\bMY\\b|Malaysia", code: "my" },
    { name: "🇵🇭 菲律宾", matcher: "菲律宾|🇵🇭|\\bPH\\b|Philippines", code: "ph" },
    { name: "🇮🇳 印度", matcher: "印度|🇮🇳|\\bIN\\b|India", code: "in" },
    { name: "🇻🇳 越南", matcher: "越南|🇻🇳|\\bVN\\b|Vietnam", code: "vn" },
    { name: "🇹🇭 泰国", matcher: "泰国|🇹🇭|\\bTH\\b|Thailand", code: "th" },
    { name: "🇨🇳 中国", matcher: "中国|🇨🇳|\\bCN\\b|china", code: "cn" },
    { name: "🌐 其他", code: "global", isOther: true },
];

// ========== 主代理组 ==========
const proxyGroups = [
    group(GROUP.SELECT, "select", {
        proxies: [GROUP.TEST, GROUP.MANUAL],
        icon: `${ICON}/Airport.png`,
    }),

    group(GROUP.MANUAL, "select", {
        "include-all": true,
        icon: `${ICON}/Proxy.png`,
    }),

    group(GROUP.TEST, "url-test", {
        "include-all": true,
        icon: `${ICON}/Speedtest.png`,
    }),

    group(GROUP.DIRECT, "select", {
        proxies: ["DIRECT", GROUP.SELECT],
        icon: `${ICON}/Direct.png`,
    }),

    group("AI", "select", {
        proxies: [
            GROUP.SELECT,
            GROUP.MANUAL,
            GROUP.TEST,
            GROUP.DIRECT,
        ],
        icon: `${ICON}/ChatGPT.png`,
    }),

    group("Google", "select", {
        proxies: [
            GROUP.SELECT,
            GROUP.MANUAL,
            GROUP.TEST,
            GROUP.DIRECT,
        ],
        icon: `${ICON}/Google_Search.png`,
    }),

    group("GitHub", "select", {
        proxies: [
            GROUP.SELECT,
            GROUP.MANUAL,
            GROUP.TEST,
            GROUP.DIRECT,
        ],
        icon: `${ICON}/GitHub.png`,
    }),

    group("Telegram", "select", {
        proxies: [
            GROUP.SELECT,
            GROUP.MANUAL,
            GROUP.TEST,
            GROUP.DIRECT,
        ],
        icon: `${ICON}/Telegram.png`,
    }),

    group("Docker", "select", {
        proxies: [
            GROUP.SELECT,
            GROUP.MANUAL,
            GROUP.TEST,
            GROUP.DIRECT,
        ],
        icon: `https://img.icons8.com/?size=100&id=22813&format=png&color=000000`,
    }),

];

// ========== 自动地区分组 ==========
function addRegions(config) {
    const names = config.proxies?.map((x) => x.name) || [];
    let remainingNames = [...names];

    const selectGroup = config["proxy-groups"].find((g) => g.name === GROUP.SELECT);
    const serviceGroups = config["proxy-groups"].filter((g) =>
        ["AI", "Google", "GitHub", "Telegram", "Docker"].includes(g.name)
    );

    const createdRegionNames = [];
    const otherNodes = [];

    // 1. 处理具体国家
    for (const region of regions) {
        if (region.isOther) continue;

        const reg = new RegExp(region.matcher, "i");
        // 关键修复：仅从剩余节点中筛选，实现互斥
        const matched = remainingNames.filter((n) => reg.test(n));

        if (matched.length > 3) {
            config["proxy-groups"].push(
                group(region.name, "url-test", {
                    proxies: matched,
                    icon: `${ICON}/Global.png`,
                })
            );
            createdRegionNames.push(region.name);
            if (selectGroup) selectGroup.proxies.push(region.name);

            // 从剩余池中移除已分配节点
            remainingNames = remainingNames.filter(n => !matched.includes(n));
        }
    }

    // 2. 剩余节点全部进入“其他”池
    otherNodes.push(...remainingNames);

    // 3. 创建“其他”分组（不加入节点选择，实现隐藏）
    if (otherNodes.length > 0) {
        const otherRegion = regions.find((r) => r.isOther);
        const otherName = otherRegion ? otherRegion.name : "🌐 其他";
        config["proxy-groups"].push(
            group(otherName, "url-test", {
                proxies: otherNodes,
                icon: `${ICON}/Global.png`,
            })
        );
        createdRegionNames.push(otherName);
    }

    // 4. 动态注入到服务分组
    for (const g of serviceGroups) {
        g.proxies.push(...createdRegionNames);
    }
}

// ========== 主函数 ==========
function main(config) {
    if (!enableScript) return config;

    if (!config.proxies?.length) {
        throw new Error("未检测到节点");
    }

    Object.assign(config, {
        profile: {
            "store-selected": true,
            "store-fake-ip": true,
        },
        "unified-delay": true,
        "tcp-concurrent": true,
        "global-client-fingerprint": "chrome",
        "geodata-loader": "standard",
    });

    config["rule-providers"] = ruleProviders;
    config["rules"] = rules;
    config["proxy-groups"] = proxyGroups;

    addRegions(config);

    return config;
}
