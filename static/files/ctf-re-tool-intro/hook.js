// Frida Hook Script —— app-release.apk (com.nctf.hookmysecret)
// 由 CTF-RE-TOOL 的「Frida 自动 Hook」生成，用于在多阶段校验中抓取运行时明文。
// 运行:  frida -H 127.0.0.1:27042 -f com.nctf.hookmysecret -l hook.js --no-pause
'use strict';

Java.perform(function () {
    console.log('[*] hook loaded');

    // 1) native 加密函数：观察输入字符串与返回的 int[]
    try {
        var NB = Java.use('com.nctf.hookmysecret.nativebridge.NativeBridge');
        NB.encryptStage2.overload('java.lang.String').implementation = function (s) {
            var r = this.encryptStage2(s);
            console.log('[HIT] encryptStage2("' + s + '") = ' + JSON.stringify(r));
            return r;
        };
    } catch (e) { console.log('[-] NativeBridge: ' + e); }

    // 2) AES 参数：抓 key / IV / 明文
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            var out = this.doFinal(input);
            console.log('[Cipher] ' + this.getAlgorithm()
                + ' in=' + bytesToHex(input) + ' -> out=' + bytesToHex(out));
            return out;
        };
        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            console.log('[Cipher] init ' + (mode === 1 ? 'ENCRYPT' : 'DECRYPT')
                + ' key=' + bytesToHex(key.getEncoded()));
            return this.init(mode, key);
        };
    } catch (e) { console.log('[-] Cipher: ' + e); }

    // 3) 阶段状态：stage1Passed / stage2Passed / stage2Key
    try {
        var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Ed.putBoolean.implementation = function (k, v) {
            console.log('[DATA] putBoolean ' + k + ' = ' + v);
            return this.putBoolean(k, v);
        };
        Ed.putString.implementation = function (k, v) {
            console.log('[DATA] putString ' + k + ' = ' + v);
            return this.putString(k, v);
        };
    } catch (e) { console.log('[-] SharedPreferences: ' + e); }

    // 4) SQLite 里的 IV 常量
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
            .implementation = function (sql, args) {
                console.log('[SQL] ' + sql + ' args=' + JSON.stringify(args));
                return this.rawQuery(sql, args);
            };
    } catch (e) { console.log('[-] SQLite: ' + e); }

    function bytesToHex(b) {
        if (!b) return 'null';
        var h = [];
        for (var i = 0; i < b.length; i++) h.push(('0' + (b[i] & 0xff).toString(16)).slice(-2));
        return h.join('');
    }
});
