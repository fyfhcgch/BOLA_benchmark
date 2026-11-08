// 诊断：确认 HttpRequestHeader 上删除 Authorization 的可行写法。
// 背景：HttpHeader 没有 removeHeader()，getHeaders() 返回的是 ArrayList 副本，
// HttpHeaderField 又是不可变的；只能看 setHeader(name, "") 到底把原始 header
// 串改成什么样（会不会留下空行把 body 顶掉）。

var FileWriter = Java.type('java.io.FileWriter');
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');

var out = new FileWriter('/tmp/hdr_probe.txt');

var raw = 'GET http://127.0.0.1:8765/api/me HTTP/1.1\r\n'
        + 'Host: 127.0.0.1:8765\r\n'
        + 'Authorization: Bearer abc.def.ghi\r\n'
        + 'Content-Type: application/json\r\n'
        + 'Content-Length: 2\r\n\r\n';

var h = new HttpRequestHeader(raw);
out.write('BEFORE|' + h.toString().replace(/\r/g, '\\r').replace(/\n/g, '\\n') + '\n');

try {
    h.setHeader('Authorization', '');
    out.write('SETEMPTY|' + h.toString().replace(/\r/g, '\\r').replace(/\n/g, '\\n') + '\n');
} catch (e) {
    out.write('SETEMPTY-ERR|' + ('' + e.message) + '\n');
}

try {
    var h2 = new HttpRequestHeader(raw);
    h2.setHeader('Authorization', null);
    out.write('SETNULL|' + h2.toString().replace(/\r/g, '\\r').replace(/\n/g, '\\n') + '\n');
} catch (e2) {
    out.write('SETNULL-ERR|' + ('' + e2.message) + '\n');
}
out.close();
'ok';