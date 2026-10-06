# JianrongInternetSecurity｜金荣安全 v1.0.3
> 自研Windows主动防御安全软件，基于 .NET + CefSharp，支持TLSH云模糊哈希库、YARA本地扫描。

## ✨ 项目简介
金荣安全是独立开发的Windows平台HIPS类安全引擎，主打：
- 进程创建主动防御
- YARA本地病毒扫描
- TLSH云端特征上报与云比对API（金荣安全云）
- 版本检测（仅提示更新，**不会自动下载安装**）

> ⚠️ 测试警告：恶意样本仅建议在虚拟机内进行测试，禁止裸机运行！

## 📦 当前版本：Beta 1.0.3
### 更新要点（中文 / English / Français / Русский）
#### 中文
- 回退稳定.NET版本，修复C++版本文件防护休眠、扫描漏报问题
- 默认关闭云查杀，大幅提升大批量样本扫描速度
- 云端入库1906条TLSH恶意样本指纹，扩充云病毒库
- 新增GitHub版本检测，仅弹窗提醒更新，自动打开浏览器跳转下载页，无强制更新

#### English
- Rollback to stable .NET build, fixed broken file protection & detection missing in C++ version
- Cloud scan disabled by default for much faster bulk scanning
- 1906 TLSH malware fingerprints added to cloud database
- GitHub version checker added: only notify updates, open download page in browser, no auto-update.

#### Français
- Retour à la version stable .NET, correction des défauts de protection des fichiers de la version C++
- Analyse cloud désactivée par défaut pour accélérer l'analyse de nombreux fichiers
- 1906 empreintes TLSH de logiciels malveillants ajoutées à la base cloud
- Vérificateur de version GitHub : notification simple, ouverture de la page de téléchargement, pas de mise à jour automatique.

#### Русский
- Откат к стабильной сборке .NET, исправлена неработающая защита файлов в C++ версии
- Облачное сканирование отключено по умолчанию для ускорения массовой проверки
- В облачную базу добавлено 1906 TLSH сигнатур вредоносного ПО
- Проверка версии GitHub: только уведомление, открытие страницы загрузки, принудительного обновления нет.

## 🔗 相关链接
- 官网：https://wubinhao.pythonanywhere.com/
- 旧官网：https://jianrongstudio.github.io/web/
- 云API文档：[你的API页面地址]

## 📜 License
MIT License
