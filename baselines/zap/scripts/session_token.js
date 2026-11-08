// ZAP 会话管理脚本（Session Management / Graal.js）。
// 靶场用 Bearer token：登录响应的 JSON **体**里带 token（mock/clean/crAPI 是
// "token"，VAmPI 是 "auth_token"），后续请求靠 Authorization: Bearer <token> 携带。
//
// ===========================================================================
// 为什么不能把 token 存进 sessionWrapper.getSession()（ZAP 的结构性缺陷）：
//   ScriptBasedSessionManagementMethod 上只有一个 `session` 字段，
//   getSessionWrapper(msg) 对所有调用者复用同一个 ScriptBasedSession ——
//   与 msg 的 requestingUser 无关。多用户场景下，谁最后登录，共享 session
//   里就是谁的 token；于是 bob 的重放带着 alice 的 token、403 变 200，
//   整个 Access Control 报告全错。实测 msg 143/144（bob 重放）带 tok-alice-1。
//   绕过办法：脚本自己维护「用户名 -> token」的表，从
//   msg.getRequestingUser().getName() 取当前身份，完全不碰共享 session。
// ===========================================================================
//
// 接口签名（踩过坑）：ZAP 的 SessionScript 三个回调都是**单参数** SessionWrapper，
//   javap org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType$SessionScript
//
// 关键坑 2（删头的 API）：
//   HttpRequestHeader **没有** removeHeader()。`getHeaders()` 返回的是 ArrayList
//   副本、HttpHeaderField 不可变，改副本没用。唯一干净的写法是：
//       setHeader('Authorization', null)
//   实测效果是整行删掉（不会留下 `Authorization: ` 空行把 body 顶掉）。

var TOKEN_RE = /"(?:auth_)?token"\s*:\s*"([^"]+)"/;
var FileWriter = Java.type('java.io.FileWriter');
var System = Java.type('java.lang.System');

// 用户名 -> Bearer token，键前缀 'bola.bearer.<user>'，存 JVM 全局 System properties。
// 为什么不用脚本顶层 var：实测 Graal.js 在 ZAP 的回调机制里**每次调用都可能重新
// 求值顶层代码**——顶层 var TOKENS = new ConcurrentHashMap() 每次回调都是一张新表，
// extract 里 put 进去的 token 到 process 里 get 不出来（/tmp 日志可证：extract
// 110 次全带 token，process 218 次全 (none)）。System properties 是 JVM 级单例，
// 跨脚本实例、跨回调稳定存活；每轮 run() 会重启 JVM 进程（ZAP 容器长驻则用
// 会话前缀隔离，见下）。
var KEY_PREFIX = 'bola.bearer.';
// 调试日志：验证三个回调里 requestingUser 是否如预期（跑完可关）
var DEBUG = '/tmp/session_token_debug.log';
var LOG = new FileWriter(DEBUG, true);

dbg('=== script instance loaded ===');

function tokKey(user) {
    return KEY_PREFIX + user;
}

function dbg(s) {
    try {
        LOG.write(s + '\n');
        LOG.flush();
    } catch (e) { /* 日志失败不影响主流程 */ }
}

function userName(msg) {
    try {
        var u = msg.getRequestingUser();
        return u == null ? null : String(u.getName());
    } catch (e) {
        return null;
    }
}

function isLoginResponse(msg) {
    // 只在登录响应里取 token：别的接口万一回显了 "token" 字段，
    // 抓错会让整个后续会话挂到错误的身份上。
    try {
        return /login/i.test(String(msg.getRequestHeader().getURI().getPath()));
    } catch (e) {
        return false;
    }
}

function stripAuth(msg) {
    try {
        msg.getRequestHeader().setHeader('Authorization', null);
    } catch (e) {
        // 某些 HttpMessage 构造阶段 header 还不完整，忽略即可
    }
}

function extractWebSession(sessionWrapper) {
    var msg = sessionWrapper.getHttpMessage();
    if (msg == null) return;
    if (!isLoginResponse(msg)) return;
    var who = userName(msg);
    var m = TOKEN_RE.exec(msg.getResponseBody().toString());
    dbg('extract user=' + who + ' token=' + (m ? m[1] : '(none)'));
    if (m && who != null) {
        System.setProperty(tokKey(who), m[1]);
    }
}

function clearWebSessionIdentifiers(sessionWrapper) {
    // 语义：把**这条消息**里的会话标识去掉，不是把用户登出。
    // 早先的写法顺手 TOKENS.remove(user)，结果一旦被调用（比如构造未认证重放），
    // 该用户的 token 就永久丢了，后续重放全变 401 —— 生成大量假越权告警。
    var msg = sessionWrapper.getHttpMessage();
    dbg('clear user=' + (msg == null ? null : userName(msg)));
    if (msg != null) stripAuth(msg);
}

function processMessageToMatchSession(sessionWrapper) {
    var msg = sessionWrapper.getHttpMessage();
    if (msg == null) return;
    var who = userName(msg);
    // 先删后写：克隆出来的消息可能带着站点树里存下来的旧身份。
    stripAuth(msg);
    var token = who == null ? null : System.getProperty(tokKey(who));
    dbg('process user=' + who + ' token=' + (token == null ? '(none)' : String(token).substring(0, 24)));
    if (token != null && String(token) !== '') {
        msg.getRequestHeader().setHeader('Authorization', 'Bearer ' + token);
    }
}

// ZAP 的 SessionScript 接口还要求这两个函数，缺了会在配置时报 NullPointerException：
//   org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType$SessionScript
function getRequiredParamsNames() {
    return [];
}

function getOptionalParamsNames() {
    return [];
}