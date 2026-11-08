// 清掉 session_token.js 存在 JVM 全局里的 Bearer token。
// 单独成脚本的原因：session_token 是 session 型脚本，它的顶层代码在每次回调时
// 都可能重新求值，没法可靠地持有"跨回调"的状态；System properties 是 JVM 级的，
// 用这个 standalone 脚本（每次显式运行一次）来清最简单可靠。
// zap_access_control.py 在每轮 run() 一开始调用（runStandAloneScript）。

var System = Java.type('java.lang.System');
var props = System.getProperties();
var keys = props.stringPropertyNames().toArray();
var n = 0;
for (var i = 0; i < keys.length; i++) {
    if (String(keys[i]).indexOf('bola.bearer.') === 0) {
        System.clearProperty(String(keys[i]));
        n++;
    }
}
// 结果落盘供驱动脚本断言（Graal standalone 的 print 不进 ZAP 日志）
var FileWriter = Java.type('java.io.FileWriter');
var out = new FileWriter('/tmp/clear_tokens_result.txt');
out.write('cleared=' + n + '\n');
out.close();
'ok';