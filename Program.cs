using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using CefSharp;
using CefSharp.WinForms;
using JianRongSecurity.Desktop;
using JianRongSecurity.Engine;

namespace JianRongSecurity
{
    /// <summary>
    /// 程序入口：初始化 CEF（高 DPI、缓存目录、日志），运行主窗体。
    /// 顶层未处理异常统一写入输出目录 jianrong-error.log，不弹窗崩溃。
    /// 新增：单实例互斥锁 + 开机自启（--autostart/--tray）托盘后台模式（不拉主窗口）。
    /// 新增：--scan "&lt;path&gt;" 右键菜单独立扫描——已有实例时通过管道转发 'C'+path，无实例时直接跑独立扫描窗口。
    ///
    /// 【v2.2.1 紧急修复：Win10 1507 主窗口不显示】
    /// 旧版外层 catch 只 WriteError 后静默结束进程——Cef.Initialize 在缺 VC++ 运行库 / KB3064209
    /// 字体补丁等老系统环境下抛异常时，进程直接退出、无窗口无提示。
    /// 现改为：
    ///   1) 每个启动阶段写诊断打点到 jianrong-error.log（WriteDiagnostic）；
    ///   2) Cef.Initialize 单独 try/catch，失败时弹可见提示并进入纯 WinForms FallbackForm（基础模式），
    ///      绝不允许"无窗口静默失败"；
    ///   3) 启动早期做兼容性轻量探测（系统版本 / VC++ 运行库 / KB3064209），只记录+提示，不阻塞；
    ///   4) --scan 模式失败也弹可见提示。
    /// </summary>
    internal static class Program
    {
        /// <summary>
        /// 单实例命名 Mutex 引用：整个进程生命周期持有，不 Dispose；
        /// 进程退出时由操作系统自动释放。绝不能用 using 包裹提前释放。
        /// </summary>
        private static Mutex? _singleInstanceMutex;

        [STAThread]
        private static void Main(string[] args)
        {
            // 全局异常兜底：任何未处理异常都落盘，避免系统弹窗直接崩溃
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            Application.ThreadException += (s, e) => WriteError(e.Exception);
            AppDomain.CurrentDomain.ProcessExit += (s, e) =>
            {
                try { if (Cef.IsInitialized) Cef.Shutdown(); } catch { /* 退出路径，吞掉 */ }
            };

            WriteDiagnostic("process-start args=" + (args == null || args.Length == 0 ? "(none)" : string.Join("|", args)));

            // ===== 解析 --scan "<path>" 参数 =====
            // 右键菜单扫描：--scan 后跟一个路径（文件或目录，可能含空格，由 shell 引号传入）。
            string? scanPath = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "--scan", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    scanPath = args[i + 1];
                    break;
                }
            }
            bool isScanMode = scanPath != null;

            // ===== 启动时自动提权（v2.6.0+ 新增）=====
            // 杀毒软件主程序需要写系统保护/驱动/隔离区，非管理员运行会功能受限。
            // 非自启场景（双击快捷方式/菜单启动）检测到未提权时，以 runas 方式重启自己（带原参数），
            // 当前进程退出；自启模式（--autostart/--tray，开机静默后台）不强制提权，
            // 避免开机弹 UAC——后台引擎职责由 ServiceHost 服务承担。
            if (!isScanMode && !HasAutoStartArg(args) && !IsRunningAsAdministrator())
            {
                WriteDiagnostic("elevation: not-admin -> relaunch with runas");
                if (TryRelaunchElevated(args))
                {
                    WriteDiagnostic("elevation: relaunch-started, exiting");
                    return;
                }
                // 提权重启失败（如用户取消 UAC）——记录后继续以当前权限运行，不阻塞
                WriteDiagnostic("elevation: relaunch-failed, continue unelevated");
            }

            // ===== 单实例检测（必须在 Cef.Initialize 之前）=====
            WriteDiagnostic("single-instance-check-start");
            if (!TryAcquireSingleInstance())
            {
                WriteDiagnostic("single-instance-already-running -> forward & exit");
                if (isScanMode)
                    NotifyExistingInstanceToScan(scanPath!);
                else
                    NotifyExistingInstanceToShowMain();
                return;
            }
            WriteDiagnostic("single-instance-acquired");

            // ===== 早期兼容性探测（只记录+提示，不阻塞启动）=====
            CompatProbe probe;
            try
            {
                probe = CompatProbe.Detect();
                WriteDiagnostic("compat-probe: " + probe.Summary);
            }
            catch (Exception ex)
            {
                WriteDiagnostic("compat-probe-threw: " + ex.Message);
                probe = CompatProbe.Empty;
            }

            // ===== --scan 模式且为第一实例：不走 CEF/主窗口，直接跑独立扫描窗口 =====
            if (isScanMode)
            {
                try
                {
                    WriteDiagnostic("scan-mode: enable-visual-styles");
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    WriteDiagnostic("scan-mode: construct ScanWindowForm path=" + scanPath);
                    var scanForm = new ScanWindowForm(scanPath!);
                    WriteDiagnostic("scan-mode: application.run");
                    Application.Run(scanForm);
                    WriteDiagnostic("scan-mode: application-run-returned");
                }
                catch (Exception ex)
                {
                    WriteError(ex);
                    WriteDiagnostic("scan-mode-exception: " + ex.GetType().Name + ": " + ex.Message);
                    // 可见兜底：右键扫描失败也必须提示，不能静默
                    try
                    {
                        MessageBox.Show(
                            "安全扫描启动失败：" + ex.Message + "\n\n详情请查看安装目录下 jianrong-error.log。",
                            "坚荣终端安全", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                    catch { /* UI 已不可用时吞掉 */ }
                }
                return;
            }

            // ===== 启动画面状态（try/catch 外声明，失败兜底路径也要能 StopSplash）=====
            // 独立 STA 后台线程跑 WinForms 消息循环，不阻塞主线程 Cef.Initialize；
            // 主窗体构造后由 StopSplash 补齐 2 秒硬控再关闭。启动图缺失则不显示，正常启动。
            System.Threading.Thread? splashThread = null;
            Form? splashForm = null;
            DateTime splashShownAt = DateTime.MinValue;

            void StartSplash()
            {
                try
                {
                    string imgPath = Path.Combine(AppContext.BaseDirectory, "UI", "assets", "splash-start.png");
                    if (!File.Exists(imgPath))
                    {
                        WriteDiagnostic("splash-image-missing: " + imgPath);
                        return;
                    }
                    splashShownAt = DateTime.Now;
                    splashThread = new System.Threading.Thread(() =>
                    {
                        try
                        {
                            var f = new SplashForm();
                            splashForm = f;
                            Application.Run(f); // 直到 f.Close() 才退出消息循环
                        }
                        catch { /* 启动画面线程异常不影响主流程 */ }
                    });
                    splashThread.IsBackground = true;
                    splashThread.SetApartmentState(System.Threading.ApartmentState.STA);
                    splashThread.Start();
                    WriteDiagnostic("splash-shown");
                }
                catch (Exception ex)
                {
                    WriteError(ex);
                    WriteDiagnostic("splash-start-failed: " + ex.Message);
                }
            }

            void StopSplash()
            {
                if (splashThread == null) return;
                try
                {
                    // 硬控 2 秒：Cef.Initialize 耗时已超过 2 秒时此处直接放行
                    double remainMs = 2000.0 - (DateTime.Now - splashShownAt).TotalMilliseconds;
                    if (remainMs > 0) System.Threading.Thread.Sleep((int)remainMs);

                    var f = splashForm;
                    if (f != null && !f.IsDisposed)
                    {
                        try { f.Invoke(new Action(() => { try { f.Close(); } catch { } })); }
                        catch { }
                    }
                    splashThread.Join(2000);
                    WriteDiagnostic("splash-closed");
                }
                catch (Exception ex) { WriteError(ex); }
                finally
                {
                    splashThread = null;
                    splashForm = null;
                }
            }

            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                WriteDiagnostic("winforms-visual-styles-ok");

                // ===== 启动画面（硬控至少 2 秒，不可跳过）=====
                // 状态变量与 Start/Stop 局部函数定义在 try 之外——catch 兜底路径也要能 StopSplash。
                StartSplash();

                // CEF 高 DPI 支持
                Cef.EnableHighDPISupport();
                WriteDiagnostic("cef-enable-high-dpi");

                // 绑定对象方法返回 Task<T>（isAsync 绑定）时，CefSharp 默认不支持并发 Task 执行，
                // 必须在创建首个 ChromiumWebBrowser 之前开启此开关，否则 JS 调用 getVersion/quickScan 等
                // 会抛 "Your method returned a Task which is not supported by default"。
                CefSharpSettings.ConcurrentTaskExecution = true;

                // 缓存目录：%LOCALAPPDATA%\JianrongSecurity\cef-cache
                string cacheDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "JianrongSecurity",
                    "cef-cache");
                Directory.CreateDirectory(cacheDir);

                var settings = new CefSettings
                {
                    CachePath = cacheDir,
                    // 排错日志：输出目录 cef.log
                    LogFile = Path.Combine(AppContext.BaseDirectory, "cef.log"),
                    LogSeverity = LogSeverity.Info,
                    Locale = "zh-CN"
                };

                // 白屏/黑屏兜底：虚拟机/远程桌面/无 GPU 环境下关闭 GPU 合成，改用软件渲染。
                settings.CefCommandLineArgs.Add("disable-gpu", "1");
                settings.CefCommandLineArgs.Add("disable-gpu-compositing", "1");

                // 【兼容性参数评估结论】
                //  - --no-sandbox：不加。沙箱是 Chromium 安全边界，对安全产品自身 UI 尤其重要，
                //    老系统初始化失败大概率不是沙箱策略导致，而是系统组件（VC++ 运行库 / 字体补丁）缺失，
                //    用沙箱换窗口显示得不偿失。
                //  - --disable-direct-write：不加。DirectWrite 是 Chromium 在 Win10 上的默认文本渲染路径，
                //    禁用后会回退到更老的 GDI/Uniscribe 路径，反而可能加剧字体崩溃；
                //    KB3064209 缺失的正确处置是检测后提示用户打补丁，而不是牺牲渲染质量硬绕。
                // 保持现有 disable-gpu + disable-gpu-compositing（软件渲染）。

                WriteDiagnostic("cef-initialize-start");
                Cef.Initialize(settings);
                WriteDiagnostic("cef-initialize-ok");

                // 解析启动参数：包含 --autostart 或 --tray（任一）→ 开机自启模式
                // 安装包 ISS 侧已按 --autostart 参数名写入 HKCU Run 键，不可更改参数名。
                bool isAutoStart = Array.Exists(args,
                    a => string.Equals(a, "--autostart", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));

                // 桌面小部件（桌宠；加速球已移除）钩子装配：打开主窗口 / 快速扫描。
                // 两种启动模式一视同仁——自启模式 MainForm 虽未 Show，但句柄已强制创建，
                // 后续 Show() 即可正常弹出。
                void SetupDesktopWidgets(MainForm mf)
                {
                    DesktopWidgets.OpenMainWindow = () =>
                    {
                        try
                        {
                            if (mf.IsDisposed) return;
                            if (!mf.Visible) mf.Show();
                            mf.WindowState = FormWindowState.Normal;
                            mf.BringToFront();
                            mf.Activate();
                        }
                        catch { }
                    };
                    DesktopWidgets.QuickScan = () =>
                    {
                        try
                        {
                            _ = JinRongBridge.QuickScanAsync();
                            DesktopWidgets.OpenMainWindow?.Invoke();
                        }
                        catch (Exception ex) { WriteError(ex); }
                    };
                    DesktopWidgets.Start(showPet: true);
                }

                if (isAutoStart)
                {
                    // 自启模式：用 ApplicationContext 运行主窗体，ApplicationContext 不会自动 Show 主窗体，
                    // 实现"只托盘图标 + 后台引擎，不拉主窗口"。
                    WriteDiagnostic("mainform-ctor-start autostart=true");
                    var mainForm = new MainForm { AutoStartMode = true };
                    SetupDesktopWidgets(mainForm);
                    StopSplash(); // 主窗体就绪：补齐 2 秒硬控后关闭启动画面
                    WriteDiagnostic("mainform-ctor-done autostart=true; application.run-ctx");
                    Application.Run(new ApplicationContext(mainForm));
                    WriteDiagnostic("application-run-ctx-returned");
                }
                else
                {
                    // 正常模式（双击快捷方式，无参数）：显示主窗口
                    WriteDiagnostic("mainform-ctor-start autostart=false");
                    var mainForm = new MainForm();
                    SetupDesktopWidgets(mainForm);
                    StopSplash(); // 主窗体就绪：补齐 2 秒硬控后关闭启动画面
                    WriteDiagnostic("mainform-ctor-done; application.run");
                    Application.Run(mainForm);
                    WriteDiagnostic("application-run-returned");
                }
            }
            catch (Exception ex)
            {
                WriteError(ex);
                WriteDiagnostic("startup-exception: " + ex.GetType().FullName + " | " + ex.Message);
                // 启动失败路径也要先关掉启动画面，避免 FallbackForm 后面挡着一个死窗
                try { StopSplash(); } catch { }
                // 任何启动失败（含 Cef.Initialize 抛异常）→ 可见兜底：提示 + FallbackForm，绝不静默退出。
                // 注意：FallbackForm 是纯 WinForms，不构造 MainForm、不启动 RealtimeEngine/ProcessGuard。
                RunFallbackMode(ex, probe);
            }
        }

        /// <summary>
        /// 启动失败兜底路径：先弹可见 MessageBox 说明，再打开纯 WinForms 的 FallbackForm（基础模式）。
        /// 调用前异常已写入 jianrong-error.log。若 CEF 已部分初始化则先 Shutdown 干净退出。
        /// </summary>
        private static void RunFallbackMode(Exception failure, CompatProbe probe)
        {
            WriteDiagnostic("fallback-mode-enter");

            // CEF 若已部分初始化（异常发生在 Initialize 之后、MainForm 构造阶段），先干净 Shutdown，
            // 避免残留浏览器子进程；未初始化时 Cef.IsInitialized=false，直接跳过。
            try { if (Cef.IsInitialized) Cef.Shutdown(); } catch { }

            try
            {
                MessageBox.Show(
                    "界面组件初始化失败，已启动基础模式。\n\n原因：" + failure.Message +
                    "\n\n详情请查看安装目录下 jianrong-error.log。",
                    "坚荣终端安全 — 基础模式", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch { /* 弹窗本身失败不阻断后续 FallbackForm */ }

            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new FallbackForm(failure, probe));
            }
            catch (Exception ex2)
            {
                WriteError(ex2);
                try
                {
                    MessageBox.Show(
                        "基础模式窗口也无法启动：" + ex2.Message +
                        "\n\n详情请查看安装目录下 jianrong-error.log。",
                        "坚荣终端安全", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch { }
            }
            WriteDiagnostic("fallback-mode-exit");
        }

        /// <summary>
        /// 当前是否处于开机自启/托盘后台模式（--autostart 或 --tray）。
        /// 该场景跳过强制提权，避免开机弹 UAC；后台职责由 ServiceHost 服务承担。
        /// </summary>
        private static bool HasAutoStartArg(string[] args)
        {
            if (args == null) return false;
            foreach (string a in args)
            {
                if (string.Equals(a, "--autostart", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        /// <summary>当前进程是否具备管理员权限。</summary>
        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        /// <summary>
        /// 以管理员权限重新启动本程序（runas），保留原命令行参数。
        /// 成功返回 true（新进程已拉起）；失败（如用户取消 UAC）返回 false。
        /// </summary>
        private static bool TryRelaunchElevated(string[] args)
        {
            try
            {
                string exePath = Environment.ProcessPath ?? AppContext.BaseDirectory + "JianRongSecurity.CefSharp.exe";
                var psi = new ProcessStartInfo(exePath)
                {
                    UseShellExecute = true,
                    Verb = "runas", // 触发 UAC 提权
                    WorkingDirectory = AppContext.BaseDirectory
                };
                if (args != null)
                {
                    foreach (string a in args)
                        psi.ArgumentList.Add(a);
                }
                Process.Start(psi);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 尝试获取单实例命名 Mutex。
        /// 成功返回 true（本进程为第一实例，Mutex 引用存入 _singleInstanceMutex 全程持有）；
        /// 检测到已有实例时返回 false。
        /// 优先用 Global\ 前缀（跨会话），权限失败则回退不带前缀的会话内 Mutex。
        /// </summary>
        private static bool TryAcquireSingleInstance()
        {
            string[] candidateNames =
            {
                @"Global\JianrongEndpointSecurity_SingleInstance",
                @"JianrongEndpointSecurity_SingleInstance"
            };

            foreach (string name in candidateNames)
            {
                try
                {
                    bool createdNew;
                    var mutex = new Mutex(false, name, out createdNew);

                    if (createdNew)
                    {
                        // 本进程创建了内核命名 Mutex——是第一实例，立即获取所有权
                        mutex.WaitOne(0);
                        _singleInstanceMutex = mutex;
                        return true;
                    }

                    // Mutex 已存在：尝试非阻塞获取
                    try
                    {
                        if (mutex.WaitOne(0))
                        {
                            // 成功获取（前一实例已退出但内核 Mutex 对象尚未回收）——视为第一实例
                            _singleInstanceMutex = mutex;
                            return true;
                        }
                    }
                    catch (AbandonedMutexException)
                    {
                        // 前一进程异常退出留下废弃 Mutex——视为第一实例继续持有
                        _singleInstanceMutex = mutex;
                        return true;
                    }

                    // WaitOne(0) 超时：确有另一实例正在持有该 Mutex
                    mutex.Dispose();
                    return false;
                }
                catch
                {
                    // Global 前缀可能因权限/安全异常失败，继续尝试下一个名称
                }
            }

            // 两种命名方式都失败——不阻塞启动，放行（极端兜底）
            return true;
        }

        /// <summary>
        /// 本进程为重复实例时，连接命名管道通知已有实例显示主窗口。
        /// 管道名：\\.\pipe\JianRongSecurity.ShowMain；连接超时 2 秒；发送单字节 'S'。
        /// 所有异常静默丢弃，不影响本进程退出。
        /// </summary>
        private static void NotifyExistingInstanceToShowMain()
        {
            try
            {
                using var client = new NamedPipeClientStream(
                    ".", "JianRongSecurity.ShowMain", PipeDirection.Out);
                client.Connect(2000); // 2 秒超时
                client.WriteByte((byte)'S');
                client.Flush();
            }
            catch
            {
                // 管道不可达或写入失败——静默丢弃，本进程直接退出
            }
        }

        /// <summary>
        /// 本进程为 --scan 重复实例时，连接命名管道通知已有实例弹出独立扫描窗口。
        /// 协议：首字节 'C' + UTF-8 编码的路径字符串（直到客户端关闭流为止）。
        /// 连接超时 2 秒；所有异常静默丢弃，不影响本进程退出。
        /// </summary>
        private static void NotifyExistingInstanceToScan(string path)
        {
            try
            {
                using var client = new NamedPipeClientStream(
                    ".", "JianRongSecurity.ShowMain", PipeDirection.Out);
                client.Connect(2000); // 2 秒超时
                client.WriteByte((byte)'C');
                byte[] pathBytes = Encoding.UTF8.GetBytes(path);
                client.Write(pathBytes, 0, pathBytes.Length);
                client.Flush();
                // using 结束时 Dispose 关闭流，服务端读到 EndOfStream
            }
            catch
            {
                // 管道不可达或写入失败——静默丢弃，本进程直接退出
            }
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                WriteError(ex);
            }
        }

        /// <summary>把异常追加写入输出目录 jianrong-error.log（含完整堆栈）。</summary>
        internal static void WriteError(Exception ex)
        {
            try
            {
                string logPath = Path.Combine(AppContext.BaseDirectory, "jianrong-error.log");
                File.AppendAllText(
                    logPath,
                    "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "] " + ex + Environment.NewLine + Environment.NewLine);
            }
            catch
            {
                // 写日志本身失败则静默吞掉，避免二次崩溃
            }
        }

        /// <summary>
        /// 启动阶段诊断打点：统一追加到 jianrong-error.log。
        /// 格式：[yyyy-MM-dd HH:mm:ss.fff] STAGE: &lt;message&gt;
        /// 用于在"窗口不显示"时按时间线还原启动走到了哪一步。
        /// </summary>
        internal static void WriteDiagnostic(string stage)
        {
            try
            {
                string logPath = Path.Combine(AppContext.BaseDirectory, "jianrong-error.log");
                File.AppendAllText(
                    logPath,
                    "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "] STAGE: " + stage + Environment.NewLine);
            }
            catch
            {
                // 写日志失败静默吞掉
            }
        }
    }

    /// <summary>
    /// 启动早期兼容性轻量探测（只读、不阻塞、不抛异常）：
    /// ① 系统版本（注册表 CurrentBuild/UBR，识别 Win10 1507(build 10240)/1511(10586) 等老版本）；
    /// ② VC++ 2015-2022 运行库可加载性（检测 System32 下 msvcp140.dll / vcruntime140.dll 是否存在）；
    /// ③ KB3064209 字体补丁（老 Win10 缺该补丁 Chromium 字体渲染会崩溃；在卸载注册表中检索）。
    /// 探测失败不阻塞启动，只记录 + 在 FallbackForm 中提示。
    /// </summary>
    internal sealed class CompatProbe
    {
        public string OsCaption { get; private set; } = "";
        public bool IsOldWin10 { get; private set; }
        public bool VcRuntimePresent { get; private set; } = true;
        public bool Kb3064209Present { get; private set; } = true;

        /// <summary>给日志用的一行摘要。</summary>
        public string Summary =>
            "OS=" + OsCaption + " OldWin10=" + IsOldWin10 +
            " VcRuntime=" + VcRuntimePresent + " KB3064209=" + Kb3064209Present;

        public static readonly CompatProbe Empty = new();

        public static CompatProbe Detect()
        {
            var p = new CompatProbe();
            try
            {
                // ---- ① 系统版本：注册表 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion ----
                string productName = "";
                int build = 0, ubr = 0;
                using (var ndp = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (ndp != null)
                    {
                        productName = ndp.GetValue("ProductName") as string ?? "";
                        string? buildStr = ndp.GetValue("CurrentBuild") as string;
                        if (int.TryParse(buildStr, out int b)) build = b;
                        object? ubrObj = ndp.GetValue("UBR");
                        if (ubrObj != null) int.TryParse(ubrObj.ToString(), out ubr);
                    }
                }
                // Environment.OSVersion 作为兜底（无应用清单时老程序可能被 shim 成 6.2）
                var ov = Environment.OSVersion;
                p.OsCaption = productName + " (build " + build + "." + ubr + "; envOS=" + ov.Version + ")";

                // Win10 早期版本：1507=10240, 1511=10586；build<=10586 视为老版本
                p.IsOldWin10 = build is >= 10240 and <= 10586;

                // ---- ② VC++ 2015-2022 运行库：System32 下 msvcp140.dll / vcruntime140.dll ----
                string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                bool msvcp = File.Exists(Path.Combine(sysDir, "msvcp140.dll"));
                bool vcr = File.Exists(Path.Combine(sysDir, "vcruntime140.dll"));
                p.VcRuntimePresent = msvcp && vcr;

                // ---- ③ KB3064209：在卸载注册表键中检索补丁显示名 ----
                p.Kb3064209Present = SearchUninstallForKb("KB3064209");
            }
            catch
            {
                // 探测本身任何失败都不影响启动
            }
            return p;
        }

        private static bool SearchUninstallForKb(string kb)
        {
            // 64 位系统上 32 位补丁列表在 Wow6432Node；两处都查一遍
            string[] roots =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };
            foreach (string root in roots)
            {
                try
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(root))
                    {
                        if (key == null) continue;
                        foreach (string sub in key.GetSubKeyNames())
                        {
                            using var sk = key.OpenSubKey(sub);
                            string? name = sk?.GetValue("DisplayName") as string;
                            if (name != null && name.IndexOf(kb, StringComparison.OrdinalIgnoreCase) >= 0)
                                return true;
                        }
                    }
                }
                catch { }
            }
            return false;
        }
    }
}
