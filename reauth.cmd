@echo off
chcp 65001 >nul
title Firebase Reauth
set HTTP_PROXY=http://127.0.0.1:7890
set HTTPS_PROXY=http://127.0.0.1:7890
cd /d "E:\blog\hugo_extended_0.153.2_windows-amd64\MyBlog"
echo ================================================
echo  Firebase 重新授权
echo  浏览器会自动打开，请用 fufu98652@gmail.com 登录
echo  完成后本窗口会自动关闭
echo ================================================
echo.
"E:\blog\node\node_global\firebase.cmd" login --reauth
echo.
echo ===== 退出码: %ERRORLEVEL% =====
echo 按任意键关闭...
pause >nul
