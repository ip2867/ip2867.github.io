@echo off
chcp 65001 >nul
title Firebase Deploy
cd /d "E:\blog\hugo_extended_0.153.2_windows-amd64\MyBlog"

REM Firebase CLI 在某些版本下对 HTTP(S)_PROXY 的 ProxyAgent 有循环引用 bug。
REM 改用 CLI 自己的 --proxy 参数（如果支持）或系统级代理。
echo ================================================
echo  Firebase Hosting 部署
echo ================================================
echo.

echo [1/2] 检查 CLI 选项
"E:\blog\node\node_global\firebase.cmd" deploy --help 2>&1 | findstr /I "proxy"
echo.

echo [2/2] 执行部署
"E:\blog\node\node_global\firebase.cmd" deploy --only hosting --non-interactive
set RC=%ERRORLEVEL%
echo.
echo ===== 退出码: %RC% =====
echo 按任意键关闭...
pause >nul
