var FileWriter = Java.type('java.io.FileWriter');
var w = new FileWriter('/tmp/probe.txt');
w.write('hello\n');
w.close();
