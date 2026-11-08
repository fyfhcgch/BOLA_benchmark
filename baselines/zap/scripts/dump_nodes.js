// 诊断脚本（standalone）：把站点树里所有节点的真实 (nodeName, method, URI)
// 写进容器内 /tmp/nodes.txt —— 用来确认 accessControl 规则 key 的正确写法。
//
// 用法：
//   curl -s "http://127.0.0.1:8090/JSON/script/action/runStandAloneScript/?apikey=bolabench&scriptName=dump_nodes"
//   docker exec zap cat /tmp/nodes.txt
//
// 三个踩过的坑：
//   1) Graal 的 standalone 脚本只执行**顶层代码**，写成 function run(){} 不会自动调用。
//   2) print()/System.out 不进 ZAP 日志，只有落盘才拿得到。
//   3) SiteNode 的部分 getter 在不同版本签名不同，逐个 try/catch，别让一个节点炸掉整棵树。

var Model = Java.type('org.parosproxy.paros.model.Model');
var FileWriter = Java.type('java.io.FileWriter');

var out = new FileWriter('/tmp/nodes.txt');

function uriOf(n) {
    try {
        var hr = n.getHistoryReference();
        if (hr === null) { return ''; }
        return String(hr.getHttpMessage().getRequestHeader().getURI().getEscapedURI());
    } catch (e) { return ''; }
}

function methodOf(n) {
    try {
        var m = n.getMethod();
        return m === null ? '' : String(m);
    } catch (e) {
        try {
            return String(n.getHistoryReference().getMethod());
        } catch (e2) { return ''; }
    }
}

// 递归整棵树：treePath 用 / 连接各层 nodeName，方便看出「方法前缀」到底是哪一层加的
function walk(n, depth, path) {
    var name = String(n.getNodeName());
    var p = path.length === 0 ? name : path + ' / ' + name;
    if (depth > 1) {
        // 请求体用 Base64（体里可能有换行/逗号，直接拼 | 会把行拆坏）。
        // 体里的对象 id 是 L3 批量端点唯一的实例标识，规则匹配必须要它。
        var b64body = '';
        try {
            var hr2 = n.getHistoryReference();
            if (hr2 !== null) {
                var rb = hr2.getHttpMessage().getRequestBody().toString();
                if (rb !== null && rb.length() > 0) {
                    b64body = java.util.Base64.getEncoder()
                        .encodeToString(new java.lang.String(rb).getBytes('UTF-8'));
                }
            }
        } catch (e3) { b64body = ''; }
        out.write('NODE|' + name + '|' + methodOf(n) + '|' + uriOf(n)
                  + '|' + b64body + '|' + p + '\n');
    }
    var kids = n.getChildCount();
    for (var i = 0; i < kids; i++) {
        walk(n.getChildAt(i), depth + 1, p);
    }
}

var session = Model.getSingleton().getSession();
var root = session.getSiteTree().getRoot();
out.write('=== site tree ===\n');
walk(root, 0, '');

// 再单独列一遍「ZAP accessControl 真正会扫的节点」：context 内的节点集合
out.write('=== nodes in context ===\n');
var contexts = session.getContexts();
for (var c = 0; c < contexts.size(); c++) {
    var ctx = contexts.get(c);
    var nodes = session.getNodesInContextFromSiteTree(ctx);
    out.write('--- context ' + ctx.getId() + ' ' + String(ctx.getName())
              + ' nodes=' + nodes.size() + ' ---\n');
    for (var j = 0; j < nodes.size(); j++) {
        var n = nodes.get(j);
        var b64 = '';
        try {
            var hrx = n.getHistoryReference();
            if (hrx !== null) {
                var rbx = hrx.getHttpMessage().getRequestBody().toString();
                if (rbx !== null && rbx.length() > 0) {
                    b64 = java.util.Base64.getEncoder()
                        .encodeToString(new java.lang.String(rbx).getBytes('UTF-8'));
                }
            }
        } catch (e4) { b64 = ''; }
        out.write('CTX|' + String(n.getNodeName()) + '|' + methodOf(n)
                  + '|' + uriOf(n) + '|' + b64 + '\n');
    }
}
out.close();

'ok';
