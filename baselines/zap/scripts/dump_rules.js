// 校验脚本（standalone）：确认注入到 context 文件里的 accessControl 规则
// **真的**被 ZAP 解析进 ContextAccessRulesManager，并且 key 能对上站点节点。
//
// 为什么需要它：accessControl 插件**没有任何设置规则的 API**
// （accessControl/view 只有 getScanStatus / getScanProgress），
// 规则只能靠 context 文件导入。而规则串是 `userId`RULE`base64(nodeName)`escapedURI`，
// 一个字符写错（节点名、URL 转义、base64）都不会报错，只会静默变成
// "没有规则" -> 该节点判 UNKNOWN -> 不产告警 -> 报告看起来"这个工具什么都没发现"。
// 所以规则注入完必须能机械地核对回来。
//
// 用法：
//   1) 宿主机写 /tmp/opencode/zap_rules_in.tsv，首行 "CTX\t<contextId>"，
//      其余每行 "RULE \t userId \t nodeName \t escapedURI"（实际用制表符分隔）
//   2) docker cp /tmp/opencode/zap_rules_in.tsv zap:/tmp/zap_rules_in.tsv
//   3) curl ".../JSON/script/action/runStandAloneScript/?scriptName=dump_rules"
//   4) docker exec zap cat /tmp/zap_rules_out.tsv
//
// 同 dump_nodes.js：standalone 只执行顶层代码；print 不进日志，只能落盘。

var Files = Java.type('java.nio.file.Files');
var Paths = Java.type('java.nio.file.Paths');
var Control = Java.type('org.parosproxy.paros.control.Control');
var ExtAC = Java.type('org.zaproxy.zap.extension.accessControl.ExtensionAccessControl');
var SiteTreeNode = Java.type('org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode');
var URI = Java.type('org.apache.commons.httpclient.URI');
var FileWriter = Java.type('java.io.FileWriter');

var out = new FileWriter('/tmp/zap_rules_out.tsv');
var cid = -1;
var lines = Files.readAllLines(Paths.get('/tmp/zap_rules_in.tsv'));

var mgr = null;
try {
    var ext = Control.getSingleton().getExtensionLoader().getExtension(ExtAC.class);
    if (ext !== null) {
        mgr = ext.getContextAccessRulesManager(cid);
    }
} catch (e) {
    out.write('ERR|manager-init|' + '' + e.message + '\n');
}

var stats = {};
for (var i = 0; i < lines.size(); i++) {
    var parts = ('' + lines.get(i)).split('\t');
    if (parts.length < 2 || parts[0] === '') continue;
    if (parts[0] === 'CTX') {
        cid = parseInt(parts[1], 10);
        try {
            var ext2 = Control.getSingleton().getExtensionLoader().getExtension(ExtAC.class);
            mgr = ext2 === null ? null : ext2.getContextAccessRulesManager(cid);
        } catch (e2) {
            out.write('ERR|manager|' + '' + e2.message + '\n');
        }
        out.write('CTX|' + cid + '|mgr=' + (mgr === null ? 'null' : 'ok') + '\n');
        continue;
    }
    if (mgr === null) {
        out.write('ERR|no-manager-for-line|' + parts.join('|') + '\n');
        continue;
    }
    var uid = parseInt(parts[1], 10);
    var nodeName = parts[2];
    var uriStr = parts[3];
    var got = 'ERROR';
    try {
        var rule = mgr.getDefinedRule(uid, new SiteTreeNode(nodeName, new URI(uriStr, true)));
        got = rule === null ? 'NONE' : '' + rule.name();  // name() 不是 toString()：后者会跟着界面语言变
    } catch (e3) {
        got = 'THROW:' + '' + e3.message;
    }
    stats[got] = (stats[got] || 0) + 1;
    out.write('RULE|' + uid + '|' + got + '|' + nodeName + '|' + uriStr + '\n');
}
out.write('SUMMARY|' + JSON.stringify(stats) + '\n');
out.close();

'ok';
