/**
 * Cloudflare Worker Proxy
 * 功能：路径鉴权、隐私保护、跨域支持、资源透传、HTML重写
 */

const CONFIG = {
    // 访问密钥 (用于路径前缀鉴权)
    SECRET: 'password123',

    // 上游请求头过滤 (隐私保护)
    DROP_REQ_HEADERS: [
        'cf-connecting-ip', 'cf-worker', 'cf-ray', 'cf-visitor', 'cf-ipcountry', 'cf-ipcontinent',
        'x-forwarded-for', 'x-real-ip', 'x-client-ip', 'via'
    ],

    // 下游响应头过滤 (解除安全限制)
    DROP_RES_HEADERS: [
        'content-security-policy', 'content-security-policy-report-only',
        'clear-site-data', 'x-frame-options', 'strict-transport-security'
    ],

    // 跨域配置
    CORS: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': '*',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Credentials': 'true'
    }
};

const COOKIE_NAME = 'GW_Auth';

addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(req) {
    const url = new URL(req.url);

    // 静态资源处理
    if (url.pathname === '/favicon.ico') return new Response(null, { status: 204 });

    // 1. 权限校验模块
    // 方式 A: 路径前缀鉴权 (匹配 /密码/...)
    const prefix = '/' + CONFIG.SECRET;
    if (url.pathname.startsWith(prefix)) {
        // 移除密码前缀，获取真实路径
        const newPath = url.pathname.slice(prefix.length) || '/';
        
        // 建立会话并重定向到清洗后的地址
        return new Response(null, {
            status: 302,
            headers: {
                'Location': newPath + url.search,
                'Set-Cookie': `${COOKIE_NAME}=${CONFIG.SECRET}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax; Secure`
            }
        });
    }

    // 方式 B: 会话 Cookie 验证
    const cookie = req.headers.get('Cookie') || '';
    if (!cookie.includes(`${COOKIE_NAME}=${CONFIG.SECRET}`)) {
        // 未授权，返回登录界面
        return new Response(renderLogin(), { 
            status: 401, 
            headers: { 'Content-Type': 'text/html; charset=utf-8' } 
        });
    }

    // 2. 路由分发
    // 根路径仪表盘
    if (url.pathname === '/') {
        return new Response(renderDashboard(), { 
            headers: { 'Content-Type': 'text/html; charset=utf-8' } 
        });
    }

    // CORS 预检
    if (req.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: CONFIG.CORS });
    }

    // 3. 目标地址解析
    let targetPath = url.pathname.slice(1) + url.search;
    try {
        targetPath = decodeURIComponent(targetPath);
    } catch (e) {
        // 忽略解码错误
    }

    // 协议补全
    if (/^https?:\/[^/]/i.test(targetPath)) {
        targetPath = targetPath.replace(/^(https?):\/+/, '$1://');
    }
    if (!/^https?:\/\//i.test(targetPath)) {
        targetPath = 'https://' + targetPath;
    }

    try {
        const targetUrl = new URL(targetPath);
        const workerOrigin = url.origin;

        // 4. 构建代理请求
        const reqHeaders = new Headers(req.headers);
        CONFIG.DROP_REQ_HEADERS.forEach(k => reqHeaders.delete(k));
        reqHeaders.set('Host', targetUrl.host);
        reqHeaders.set('Origin', targetUrl.origin);
        reqHeaders.set('Referer', targetUrl.origin);
        reqHeaders.delete('Cookie'); // 移除鉴权 Cookie

        const res = await fetch(new Request(targetUrl, {
            method: req.method,
            headers: reqHeaders,
            body: req.body,
            redirect: 'manual'
        }));

        // 5. 构建响应头
        const resHeaders = new Headers(res.headers);
        CONFIG.DROP_RES_HEADERS.forEach(k => resHeaders.delete(k));
        Object.entries(CONFIG.CORS).forEach(([k, v]) => resHeaders.set(k, v));

        // 调整 Set-Cookie 作用域
        if (typeof res.headers.getSetCookie === 'function') {
            const cookies = res.headers.getSetCookie();
            resHeaders.delete('Set-Cookie');
            for (const c of cookies) {
                resHeaders.append('Set-Cookie', c.replace(/Domain=[^;]+;?/gi, ''));
            }
        }

        // 重写重定向路径
        if ([301, 302, 303, 307, 308].includes(res.status)) {
            const location = resHeaders.get('Location');
            if (location) {
                const newLoc = location.startsWith('http') ? location : new URL(location, targetUrl).href;
                resHeaders.set('Location', `${workerOrigin}/${newLoc}`);
            }
            return new Response(null, { status: res.status, headers: resHeaders });
        }

        // 6. 内容处理 (HTML 流式重写)
        const contentType = resHeaders.get('content-type');
        if (contentType && contentType.includes('text/html')) {
            return rewriteHtml(res, resHeaders, workerOrigin, targetUrl.origin);
        }

        return new Response(res.body, { status: res.status, headers: resHeaders });

    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500 });
    }
}

/**
 * HTML 内容重写处理器
 * 修正相对路径为代理路径，移除 SRI 校验
 */
function rewriteHtml(res, headers, workerBase, targetBase) {
    const handler = new AttributeHandler(workerBase, targetBase);
    const rewriter = new HTMLRewriter()
        .on('a', handler.attr('href'))
        .on('img', handler.attr('src'))
        .on('link', handler.attr('href'))
        .on('script', handler.attr('src'))
        .on('form', handler.attr('action'))
        .on('script', handler.remove(['integrity', 'nonce']))
        .on('link', handler.remove(['integrity', 'nonce']))
        .on('img', {
            element(e) {
                const val = e.getAttribute('srcset');
                if (val) {
                    e.setAttribute('srcset', val.replace(/(\s|^)\/(?!\/)/g, `$1${workerBase}/${targetBase}/`));
                }
            }
        });

    return rewriter.transform(new Response(res.body, { status: res.status, headers }));
}

class AttributeHandler {
    constructor(worker, target) {
        this.worker = worker;
        this.target = target;
    }

    attr(name) {
        return {
            element: (e) => {
                const val = e.getAttribute(name);
                if (!val) return;
                
                // 绝对路径
                if (val.startsWith('http')) {
                    e.setAttribute(name, `${this.worker}/${val}`);
                }
                // 协议相对路径
                else if (val.startsWith('//')) {
                    e.setAttribute(name, `${this.worker}/https:${val}`);
                }
                // 根相对路径
                else if (val.startsWith('/') && !val.startsWith('//')) {
                    e.setAttribute(name, `${this.worker}/${this.target}${val}`);
                }
            }
        };
    }

    remove(attrs) {
        return {
            element: (e) => attrs.forEach(attr => e.removeAttribute(attr))
        };
    }
}

/**
 * UI 模板：仪表盘与登录页
 */
const COMMON_STYLE = `
:root { --bg:#09090b; --box:#18181b; --text:#e4e4e7; --primary:#3b82f6; --border:#27272a; }
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif; height:100vh; display:grid; place-items:center; margin:0; }
.card { background:var(--box); border:1px solid var(--border); padding:2rem; border-radius:12px; width:300px; text-align:center; box-shadow:0 10px 30px #0008; }
input { width:100%; background:#000; border:1px solid var(--border); color:#fff; padding:12px; border-radius:6px; margin-bottom:12px; box-sizing:border-box; outline:none; }
input:focus { border-color:var(--primary); }
button { width:100%; background:var(--primary); color:#fff; border:none; padding:12px; border-radius:6px; font-weight:600; cursor:pointer; }
.list { margin-top:1.5rem; text-align:left; display:flex; flex-direction:column; gap:8px; }
.item { font-size:13px; color:#888; padding:8px; border-radius:4px; display:flex; justify-content:space-between; cursor:pointer; }
.item:hover { background:#27272a; color:#fff; }
`;

function renderDashboard() {
    return `<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>Gateway</title><style>${COMMON_STYLE}</style></head><body>
<div class="card">
    <h3 style="margin-top:0">Gateway</h3>
    <form onsubmit="go(event)">
        <input id="url" placeholder="https://..." autofocus autocomplete="off">
        <button>Connect</button>
    </form>
    <div id="hist" class="list"></div>
</div>
<script>
const KEY='gw_h', u=document.getElementById('url'), h=document.getElementById('hist');
function render(){ const d=JSON.parse(localStorage.getItem(KEY)||'[]'); h.innerHTML=d.map(i=>\`<div class="item" onclick="u.value='\${i}';go()"><span>\${i.replace(/^https?:\\/\\//,'')}</span><span onclick="event.stopPropagation();del('\${i}')">✕</span></div>\`).join(''); }
function del(v){ localStorage.setItem(KEY,JSON.stringify(JSON.parse(localStorage.getItem(KEY)||'[]').filter(i=>i!==v))); render(); }
function go(e){ if(e)e.preventDefault(); let v=u.value.trim(); if(!v)return; if(!/^https?:/i.test(v))v='https://'+v;
localStorage.setItem(KEY,JSON.stringify([v,...JSON.parse(localStorage.getItem(KEY)||'[]').filter(i=>i!==v)].slice(0,5)));
location.href=location.origin+'/'+v; }
render();
</script></body></html>`;
}

function renderLogin() {
    return `<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><title>Locked</title><style>${COMMON_STYLE}</style></head><body>
<div class="card">
    <h3 style="margin-top:0">Restricted</h3>
    <form onsubmit="event.preventDefault();location.href='/'+document.getElementById('p').value">
        <input type="password" id="p" placeholder="Password" autofocus>
        <button>Unlock</button>
    </form>
</div></body></html>`;
}