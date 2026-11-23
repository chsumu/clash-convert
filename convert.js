// ========================================
// Clash (Mihomo) 覆写脚本
// 特点：
// 1. 规则精简，主力采用 .mrs 二进制规则集，兼顾性能与可维护性
// 2. 自动地区分组（含城市/机场码/排除正则），少节点订阅自动扁平化兜底
// 3. 补全 Sniffer 域名嗅探与智能合并型 DNS，保留上游 DNS 分流策略
// 4. 兼容 Sub-Store $arguments 传参及本地覆写无参运行
// ========================================

const enableScript = true;

// ========== 默认参数（可通过 Sub-Store $arguments 覆盖） ==========
const DEFAULT_FLAGS = {
    threshold: 2,     // 地区节点数小于该值时不独立建组
    groupType: 0,     // 地区组类型：0=select, 1=url-test, 2=load-balance
    ipv6: false,      // 是否启用 IPv6
    quic: false,      // 是否允许 QUIC (UDP 443)，默认拦截以防断流
    fakeip: true,     // DNS 模式：true=fake-ip, false=redir-host
    adblock: false,   // 是否启用去广告规则 (AWAvenue .mrs)
    regex: false,     // 地区组是否使用 include-all + filter 正则过滤
    keepalive: false, // 是否启用 tcp-keep-alive
};

// ========== 自定义规则 ==========
const customRules = [
    "DOMAIN-SUFFIX,linux.do,节点选择",
    "DOMAIN-SUFFIX,huggingface.co,AI",
    "DOMAIN-KEYWORD,google,Google",
    "DOMAIN-KEYWORD,higress,DIRECT",
];

// ========== 常量 ==========
const RULE_BASE = "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo";
const CDN_BASE = "https://cdn.jsdelivr.net";
const ICON = `${CDN_BASE}/gh/Koolson/Qure@master/IconSet/Color`;
const TEST_URL = "https://cp.cloudflare.com";

const GROUP = {
    SELECT: "节点选择",
    MANUAL: "手动选择",
    TEST: "延迟选优",
    FALLBACK: "故障转移",
    DIRECT: "国内直连",
    FINAL: "漏网之鱼",
    STATIC: "静态资源",
    LOW_COST: "低倍率节点",
    ADBLOCK: "广告拦截",
    GLOBAL: "GLOBAL",
};

const TEST_COMMON = {
    url: TEST_URL,
    interval: 300,
    tolerance: 20,
    lazy: true,
};

// ========== 参数解析 ==========
function parseBool(val, fallback = false) {
    if (val === undefined || val === null) return fallback;
    if (typeof val === "boolean") return val;
    if (typeof val === "string") return val.toLowerCase() === "true" || val === "1";
    return fallback;
}

function parseIntSafe(val, fallback) {
    if (val === undefined || val === null) return fallback;
    const n = parseInt(String(val), 10);
    return Number.isNaN(n) ? fallback : n;
}

function readFlags() {
    let args = {};
    try {
        args = $arguments || {};
    } catch {
        args = {};
    }
    const gt = parseIntSafe(args.grouptype, DEFAULT_FLAGS.groupType);
    return {
        threshold: Math.max(1, parseIntSafe(args.threshold, DEFAULT_FLAGS.threshold)),
        groupType: [0, 1, 2].includes(gt) ? gt : DEFAULT_FLAGS.groupType,
        ipv6: parseBool(args.ipv6, DEFAULT_FLAGS.ipv6),
        quic: parseBool(args.quic, DEFAULT_FLAGS.quic),
        fakeip: parseBool(args.fakeip, DEFAULT_FLAGS.fakeip),
        adblock: parseBool(args.adblock, DEFAULT_FLAGS.adblock),
        regex: parseBool(args.regex, DEFAULT_FLAGS.regex),
        keepalive: parseBool(args.keepalive, DEFAULT_FLAGS.keepalive),
    };
}

// ========== Rule Providers ==========
function mrsProvider(name, behavior = "domain") {
    const dir = behavior === "ipcidr" ? "geoip" : "geosite";
    return {
        type: "http",
        format: "mrs",
        interval: 86400,
        behavior,
        url: `${RULE_BASE}/${dir}/${name}.mrs`,
        path: `./ruleset/${dir}_${name}.mrs`,
    };
}

function buildRuleProviders(flags) {
    const providers = {
        private: mrsProvider("private"),
        cn: mrsProvider("cn"),
        ipprivate: mrsProvider("private", "ipcidr"),
        ipcn: mrsProvider("cn", "ipcidr"),
        apple: mrsProvider("apple"),
        icloud: mrsProvider("icloud"),
        google: mrsProvider("google"),
        github: mrsProvider("github"),
        telegram: mrsProvider("telegram"),
        telegramcidr: mrsProvider("telegram", "ipcidr"),
        docker: mrsProvider("docker"),
        gfw: mrsProvider("gfw"),
        tld: mrsProvider("tld-!cn"),
        notcn: mrsProvider("geolocation-!cn"),
        ai: {
            type: "http",
            format: "mrs",
            behavior: "domain",
            interval: 86400,
            url: "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/ai.mrs",
            path: "./ruleset/ai.mrs",
        },
        StaticResources: {
            type: "http",
            behavior: "domain",
            format: "text",
            interval: 86400,
            url: "https://ruleset.skk.moe/Clash/domainset/cdn.txt",
            path: "./ruleset/StaticResources.txt",
        },
        CDNResources: {
            type: "http",
            behavior: "classical",
            format: "text",
            interval: 86400,
            url: "https://ruleset.skk.moe/Clash/non_ip/cdn.txt",
            path: "./ruleset/CDNResources.txt",
        },
        AdditionalCDNResources: {
            type: "http",
            behavior: "classical",
            format: "text",
            interval: 86400,
            url: `${CDN_BASE}/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list`,
            path: "./ruleset/AdditionalCDNResources.list",
        },
    };
    if (flags.adblock) {
        providers.adblock = {
            type: "http",
            behavior: "domain",
            format: "mrs",
            interval: 86400,
            url: `${CDN_BASE}/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-Clash.mrs`,
            path: "./ruleset/ADBlock.mrs",
        };
    }
    return providers;
}

function buildRules(flags) {
    return [
        ...customRules,
        flags.quic ? null : "AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
        `RULE-SET,ipprivate,${GROUP.DIRECT},no-resolve`,
        `RULE-SET,private,${GROUP.DIRECT}`,
        "RULE-SET,apple,Apple",
        "RULE-SET,icloud,Apple",
        `RULE-SET,cn,${GROUP.DIRECT}`,
        flags.adblock ? `RULE-SET,adblock,${GROUP.ADBLOCK}` : null,
        `RULE-SET,StaticResources,${GROUP.STATIC}`,
        `RULE-SET,CDNResources,${GROUP.STATIC}`,
        `RULE-SET,AdditionalCDNResources,${GROUP.STATIC}`,
        "RULE-SET,ai,AI",
        "RULE-SET,google,Google",
        "RULE-SET,github,GitHub",
        "RULE-SET,telegram,Telegram",
        "RULE-SET,telegramcidr,Telegram,no-resolve",
        "RULE-SET,docker,Docker",
        `RULE-SET,gfw,${GROUP.SELECT}`,
        `RULE-SET,tld,${GROUP.SELECT}`,
        `RULE-SET,notcn,${GROUP.SELECT}`,
        // 放在 MATCH 前且不加 no-resolve，让未命中域名规则的国内 IP 网站兜底直连
        `RULE-SET,ipcn,${GROUP.DIRECT}`,
        `MATCH,${GROUP.FINAL}`,
    ].filter(Boolean);
}

// ========== 地区字典（含权重、城市/机场码、排除正则与独立图标） ==========
const REGIONS = [
    { name: "🇭🇰 香港", weight: 10, icon: `${ICON}/Hong_Kong.png`, matcher: "香港|港|\\b(?:HK|hk)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Hong Kong|HongKong|深港|HKG|九龙|Kowloon|🇭🇰" },
    { name: "🇨🇳 台湾", weight: 20, icon: `${ICON}/Taiwan.png`, matcher: "台湾|台|新北|彰化|\\b(?:TW|tw)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Taiwan|TWN|TPE|ROC|🇹🇼" },
    { name: "🇸🇬 新加坡", weight: 30, icon: `${ICON}/Singapore.png`, matcher: "新加坡|坡|狮城|\\b(?:SG|sg)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Singapore|SIN|🇸🇬" },
    { name: "🇯🇵 日本", weight: 40, icon: `${ICON}/Japan.png`, matcher: "日本|东京|大阪|埼玉|关西|\\b(?:JP|jp)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Japan|JPN|NRT|HND|KIX|TYO|OSA|🇯🇵" },
    { name: "🇰🇷 韩国", weight: 45, icon: `${ICON}/Korea.png`, matcher: "韩国|韩|首尔|春川|\\b(?:KR|kr)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Korea|KOR|ICN|🇰🇷" },
    { name: "🇺🇸 美国", weight: 50, icon: `${ICON}/United_States.png`, matcher: "美国|美|波特兰|达拉斯|俄勒冈|凤凰城|硅谷|拉斯维加斯|洛杉矶|圣何塞|西雅图|芝加哥|纽约|亚特兰大|迈阿密|华盛顿|\\b(?:US|us)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|United States|USA|America|LAX|SFO|SEA|SJC|NYC|JFK|ORD|DFW|🇺🇸", exclude: "美属|亚美尼亚|圣多美|普林西比" },
    { name: "🇨🇦 加拿大", weight: 55, icon: `${ICON}/Canada.png`, matcher: "加拿大|温哥华|多伦多|蒙特利尔|\\b(?:CA|ca)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Canada|CAN|YVR|YYZ|YUL|🇨🇦" },
    { name: "🇬🇧 英国", weight: 60, icon: `${ICON}/United_Kingdom.png`, matcher: "英国|英|伦敦|曼彻斯特|\\b(?:UK|GB)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|United Kingdom|Great Britain|Britain|England|GBR|LHR|MAN|🇬🇧" },
    { name: "🇩🇪 德国", weight: 70, icon: `${ICON}/Germany.png`, matcher: "德国|德|柏林|法兰克福|慕尼黑|\\b(?:DE|de)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|Germany|DEU|FRA|MUC|🇩🇪", exclude: "瓜德罗普" },
    { name: "🇫🇷 法国", weight: 80, icon: `${ICON}/France.png`, matcher: "法国|法|巴黎|马赛|\\b(?:FR|fr)(?:[-_ ]?\\d+(?:[-_ ]?[A-Za-z]{2,})?)?\\b|France|CDG|MRS|🇫🇷", exclude: "法属|布基纳法索|法罗" },
    { name: "🇳🇱 荷兰", weight: 90, icon: `${ICON}/Netherlands.png`, matcher: "荷兰|阿姆斯特丹|\\bNL\\b|Netherlands|AMS|🇳🇱" },
    { name: "🇦🇺 澳大利亚", weight: 95, icon: `${ICON}/Australia.png`, matcher: "澳大利亚|澳洲|悉尼|墨尔本|\\bAU\\b|Australia|SYD|MEL|🇦🇺" },
    { name: "🇷🇺 俄罗斯", weight: 100, icon: `${ICON}/Russia.png`, matcher: "俄罗斯|俄|莫斯科|\\bRU\\b|Russia|🇷🇺", exclude: "埃塞俄比亚|白俄罗斯" },
    { name: "🇹🇷 土耳其", weight: 105, icon: `${ICON}/Turkey.png`, matcher: "土耳其|伊斯坦布尔|\\bTR\\b|Turkey|Türkiye|IST|🇹🇷" },
    { name: "🇮🇳 印度", weight: 110, icon: `${ICON}/India.png`, matcher: "印度|孟买|\\bIN\\b|India|🇮🇳", exclude: "印度洋|印度尼西亚" },
    { name: "🇮🇩 印尼", weight: 115, icon: `${ICON}/Indonesia.png`, matcher: "印度尼西亚|印尼|雅加达|\\bID\\b|Indonesia|🇮🇩" },
    { name: "🇲🇾 马来西亚", weight: 120, icon: `${ICON}/Malaysia.png`, matcher: "马来西亚|马来|吉隆坡|\\bMY\\b|Malaysia|🇲🇾" },
    { name: "🇹🇭 泰国", weight: 125, icon: `${ICON}/Thailand.png`, matcher: "泰国|曼谷|\\bTH\\b|Thailand|🇹🇭", exclude: "巴泰" },
    { name: "🇻🇳 越南", weight: 130, icon: `${ICON}/Vietnam.png`, matcher: "越南|胡志明|河内|\\bVN\\b|Vietnam|🇻🇳" },
    { name: "🇵🇭 菲律宾", weight: 135, icon: `${ICON}/Philippines.png`, matcher: "菲律宾|马尼拉|\\bPH\\b|Philippines|MNL|🇵🇭" },
    { name: "🇵🇱 波兰", weight: 140, icon: `${ICON}/Poland.png`, matcher: "波兰|华沙|\\bPL\\b|Poland|🇵🇱" },
    { name: "🇮🇹 意大利", weight: 145, icon: `${ICON}/Italy.png`, matcher: "意大利|米兰|罗马|\\bIT\\b|Italy|🇮🇹" },
    { name: "🇪🇸 西班牙", weight: 150, icon: `${ICON}/Spain.png`, matcher: "西班牙|马德里|\\bES\\b|Spain|🇪🇸" },
    { name: "🇵🇹 葡萄牙", weight: 155, icon: `${ICON}/Portugal.png`, matcher: "葡萄牙|里斯本|\\bPT\\b|Portugal|🇵🇹" },
    { name: "🇮🇪 爱尔兰", weight: 160, icon: `${ICON}/Ireland.png`, matcher: "爱尔兰|都柏林|\\bIE\\b|Ireland|🇮🇪" },
    { name: "🇸🇪 瑞典", weight: 165, icon: `${ICON}/Sweden.png`, matcher: "瑞典|斯德哥尔摩|\\bSE\\b|Sweden|🇸🇪" },
    { name: "🇦🇷 阿根廷", weight: 170, icon: `${ICON}/Argentina.png`, matcher: "阿根廷|布宜诺斯艾利斯|\\bAR\\b|Argentina|EZE|🇦🇷" },
    { name: "🇨🇳 中国", weight: 180, icon: `${ICON}/China.png`, matcher: "中国|\\bCN\\b|China|🇨🇳" },
];

const LOW_COST_PATTERN = "0\\.[0-5]|低倍率|省流|实验性";
const LOW_COST_REGEX = new RegExp(LOW_COST_PATTERN, "i");

// 过滤机场信息/广告/无效提示节点，避免污染分组及 include-all 测速
const USELESS_NODE_REGEX =
    /套餐到期|过期时间|到期时间|剩余流量|流量重置|重置时间|已用流量|可用流量|距离下次重置|官方客户端|官网|更新软件|请更新|订阅版本|订阅地址|续费|网址|发布页|最新地址|备用地址|防失联|交流群|电报群|TG群|客服|通知|公告|使用说明|教程|邀请|返利|充值|https?:\/\//i;

const SERVICE_GROUPS = [
    { name: GROUP.STATIC, icon: `${ICON}/Cloudflare.png`, preferLowCost: true },
    { name: "Apple", icon: `${ICON}/Apple_2.png`, defaultDirect: true },
    { name: "AI", icon: `${ICON}/ChatGPT.png` },
    { name: "Google", icon: `${ICON}/Google_Search.png` },
    { name: "GitHub", icon: `${ICON}/GitHub.png` },
    { name: "Telegram", icon: `${ICON}/Telegram.png` },
    { name: "Docker", icon: "https://img.icons8.com/?size=100&id=22813&format=png&color=000000" },
];

// ========== 节点分类与地区组构建 ==========
function classifyNodes(proxies, threshold) {
    const compiled = REGIONS.map((r) => ({
        ...r,
        reg: new RegExp(r.matcher, "i"),
        exReg: r.exclude ? new RegExp(r.exclude, "i") : null,
    }));
    const countryMap = new Map();
    const otherNames = [];
    const lowCostNames = [];
    const allNames = [];

    for (const node of proxies) {
        if (!node?.name) continue;
        allNames.push(node.name);
        if (LOW_COST_REGEX.test(node.name)) lowCostNames.push(node.name);

        let matched = false;
        for (const r of compiled) {
            if (r.reg.test(node.name) && !(r.exReg && r.exReg.test(node.name))) {
                if (!countryMap.has(r.name)) countryMap.set(r.name, []);
                countryMap.get(r.name).push(node.name);
                matched = true;
                break;
            }
        }
        if (!matched) otherNames.push(node.name);
    }

    const activeRegions = REGIONS
        .filter((r) => (countryMap.get(r.name)?.length || 0) >= threshold)
        .sort((a, b) => a.weight - b.weight);

    // 未达到建组阈值的地区节点并入“其他”，避免在地区分组中遗漏
    const activeSet = new Set(activeRegions.map((r) => r.name));
    for (const [name, list] of countryMap.entries()) {
        if (!activeSet.has(name)) otherNames.push(...list);
    }

    // 少于 2 个达标地区时降级为扁平模式，避免所有节点都落入“其他”
    const isGrouped = activeRegions.length >= 2;
    return { allNames, countryMap, activeRegions, otherNames, lowCostNames, isGrouped };
}

// 空代理组兜底，防止 Mihomo 内核因 proxies 为空报错
function ensureProxies(group) {
    if (!group["include-all"] && (!group.proxies || group.proxies.length === 0)) {
        return { ...group, proxies: ["DIRECT"] };
    }
    return group;
}

function createSelectGroup(name, icon, extra = {}) {
    return ensureProxies({ name, type: "select", icon, ...extra });
}

function createTypedGroup(name, icon, groupType, source) {
    if (groupType === 0) return createSelectGroup(name, icon, source);
    const type = groupType === 2 ? "load-balance" : "url-test";
    const extra = groupType === 2 ? { strategy: "sticky-sessions" } : {};
    return ensureProxies({ name, type, icon, ...TEST_COMMON, ...extra, ...source });
}

function buildRegionGroups(classified, flags) {
    const groups = [];
    if (classified.lowCostNames.length > 0) {
        const source = flags.regex
            ? { "include-all": true, filter: `(?i)${LOW_COST_PATTERN}` }
            : { proxies: classified.lowCostNames };
        groups.push(createTypedGroup(GROUP.LOW_COST, `${ICON}/Lab.png`, flags.groupType, source));
    }

    if (!classified.isGrouped) return groups;

    for (const r of classified.activeRegions) {
        const source = flags.regex
            ? {
                "include-all": true,
                filter: `(?i)${r.matcher}`,
                ...(r.exclude ? { "exclude-filter": `(?i)${r.exclude}` } : {}),
            }
            : { proxies: classified.countryMap.get(r.name) };
        groups.push(createTypedGroup(r.name, r.icon, flags.groupType, source));
    }

    if (classified.otherNames.length > 0) {
        groups.push(
            createTypedGroup("🌐 其他", `${ICON}/Global.png`, flags.groupType, {
                proxies: classified.otherNames,
            })
        );
    }
    return groups;
}

function buildProxyGroups(proxies, flags) {
    const classified = classifyNodes(proxies, flags.threshold);
    const regionGroups = buildRegionGroups(classified, flags);
    const regionNames = classified.isGrouped ? classified.activeRegions.map((r) => r.name) : [];
    if (classified.isGrouped && classified.otherNames.length > 0) {
        regionNames.push("🌐 其他");
    }
    const hasLowCost = classified.lowCostNames.length > 0;

    const selectProxies = classified.isGrouped
        ? [GROUP.TEST, GROUP.FALLBACK, GROUP.MANUAL, ...regionNames, ...(hasLowCost ? [GROUP.LOW_COST] : [])]
        : [GROUP.TEST, GROUP.FALLBACK, ...classified.allNames];

    const serviceChoices = classified.isGrouped
        ? [GROUP.SELECT, GROUP.MANUAL, GROUP.TEST, ...regionNames, ...(hasLowCost ? [GROUP.LOW_COST] : []), GROUP.DIRECT]
        : [GROUP.SELECT, GROUP.TEST, GROUP.DIRECT];

    const baseGroups = [
        createSelectGroup(GROUP.SELECT, `${ICON}/Airport.png`, { proxies: selectProxies }),
        classified.isGrouped ? createSelectGroup(GROUP.MANUAL, `${ICON}/Proxy.png`, { "include-all": true }) : null,
        ensureProxies({ name: GROUP.TEST, type: "url-test", icon: `${ICON}/Speedtest.png`, "include-all": true, ...TEST_COMMON }),
        ensureProxies({
            name: GROUP.FALLBACK,
            type: "fallback",
            icon: `${ICON}/Available_1.png`,
            ...TEST_COMMON,
            ...(classified.isGrouped ? { proxies: regionNames } : { "include-all": true }),
        }),
        createSelectGroup(GROUP.DIRECT, `${ICON}/Direct.png`, { proxies: ["DIRECT", GROUP.SELECT] }),
        createSelectGroup(GROUP.FINAL, `${ICON}/Global.png`, { proxies: [GROUP.SELECT, "DIRECT"] }),
        flags.adblock ? createSelectGroup(GROUP.ADBLOCK, `${ICON}/AdBlack.png`, { proxies: ["REJECT", "REJECT-DROP", "DIRECT"] }) : null,
    ].filter(Boolean);

    const serviceGroups = SERVICE_GROUPS.map((s) => {
        let list = serviceChoices;
        if (s.defaultDirect) {
            list = [GROUP.DIRECT, ...serviceChoices.filter((x) => x !== GROUP.DIRECT)];
        } else if (s.preferLowCost && hasLowCost) {
            list = [GROUP.LOW_COST, ...serviceChoices.filter((x) => x !== GROUP.LOW_COST)];
        }
        return createSelectGroup(s.name, s.icon, { proxies: list });
    });

    const allCreated = [...baseGroups, ...serviceGroups, ...regionGroups];
    const globalGroup = createSelectGroup(GROUP.GLOBAL, `${ICON}/Global.png`, {
        "include-all": true,
        proxies: allCreated.map((g) => g.name),
    });
    return [...allCreated, globalGroup];
}

// ========== Sniffer 与 DNS 智能合并 ==========
const SNIFFER_CONFIG = {
    enable: true,
    "force-dns-mapping": false,
    "override-destination": false,
    sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, 8080, 8880] },
        QUIC: { ports: [443, 8443] },
    },
    "skip-domain": ["Mijia Cloud", "dlg.io.mi.com", "+.push.apple.com"],
};

const FAKE_IP_FILTER = [
    "*.lan", "*.localdomain", "*.example", "*.invalid", "*.localhost", "*.test", "*.local", "*.home.arpa",
    "Mijia Cloud", "dlg.io.mi.com", "localhost.ptlogin2.qq.com", "*.icloud.com", "*.msftconnecttest.com",
    "*.msftncsi.com", "time.*.com", "time.*.gov", "time.*.edu.cn", "time.*.apple.com", "ntp.*.com",
    "+.pool.ntp.org", "*.stun.*.*", "*.stun.*.*.*", "stun.*.*", "stun.*.*.*",
    "music.163.com", "*.music.163.com", "*.126.net", "y.qq.com", "*.y.qq.com",
    "*.xboxlive.com", "*.*.xboxlive.com", "*.srv.nintendo.net", "*.*.stun.playstation.net",
];

function isPlainObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}

function mergeDnsConfig(flags, upstreamDns) {
    const base = {
        enable: true,
        ipv6: flags.ipv6,
        "prefer-h3": true,
        "enhanced-mode": flags.fakeip ? "fake-ip" : "redir-host",
        nameserver: ["system", "223.5.5.5", "119.29.29.29", "180.184.1.1"],
        fallback: ["https://dns.cloudflare.com/dns-query", "https://dns.sb/dns-query", "quic://dns0.eu"],
        ...(flags.fakeip ? { "fake-ip-filter": [...FAKE_IP_FILTER] } : {}),
    };
    if (!isPlainObject(upstreamDns)) return base;

    // 保留并合并上游订阅的策略与过滤列表，避免破坏原订阅分流
    for (const key of ["nameserver-policy", "proxy-server-nameserver-policy"]) {
        if (isPlainObject(upstreamDns[key])) {
            base[key] = { ...(base[key] || {}), ...upstreamDns[key] };
        }
    }
    for (const key of ["proxy-server-nameserver", "fake-ip-filter"]) {
        if (Array.isArray(upstreamDns[key])) {
            base[key] = [...new Set([...(base[key] || []), ...upstreamDns[key]])];
        }
    }
    return base;
}

// ========== 主函数 ==========
function main(config) {
    if (!enableScript) return config;
    if (!Array.isArray(config.proxies) || config.proxies.length === 0) {
        throw new Error("未检测到有效节点");
    }

    const validProxies = config.proxies.filter(
        (node) => node?.name && !USELESS_NODE_REGEX.test(node.name)
    );
    if (validProxies.length === 0) {
        throw new Error("过滤无用节点后未检测到可用节点");
    }
    config.proxies = validProxies;

    const flags = readFlags();

    Object.assign(config, {
        "unified-delay": true,
        "tcp-concurrent": true,
        "global-client-fingerprint": "chrome",
        "geodata-loader": "standard",
        "disable-keep-alive": !flags.keepalive,
        profile: {
            "store-selected": true,
            "store-fake-ip": flags.fakeip,
        },
        sniffer: SNIFFER_CONFIG,
        dns: mergeDnsConfig(flags, config.dns),
    });

    config["rule-providers"] = buildRuleProviders(flags);
    config["rules"] = buildRules(flags);
    config["proxy-groups"] = buildProxyGroups(config.proxies, flags);

    return config;
}
