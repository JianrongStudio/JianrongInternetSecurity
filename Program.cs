using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;
using CefSharp;
using CefSharp.WinForms;

namespace JianRongSecurity
{
    /// <summary>
    /// 程序入口：初始化 CEF（高 DPI、缓存目录、日志），运行主窗体。
    /// 顶层未处理异常统一写入输出目录 jianrong-error.log，不弹窗崩溃。
    /// </summary>
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            // 全局异常兜底：任何未处理异常都落盘，避免系统弹窗直接崩溃
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
            Application.ThreadException += (s, e) => WriteError(e.Exception);
            AppDomain.CurrentDomain.ProcessExit += (s, e) => Cef.Shutdown();

            try
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // CEF 高 DPI 支持
                Cef.EnableHighDPISupport();

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

                Cef.Initialize(settings);

                // 后台检测更新：版本过期则用默认浏览器打开下载页（只提示，不自动更新）。
                _ = Task.Run(async () =>
                {
                    await Task.Delay(1500);
                    await new Engine.UpdateEngine().CheckAndOpenIfOutdatedAsync();
                });

                Application.Run(new MainForm());
            }
            catch (Exception ex)
            {
                WriteError(ex);
                // 不 rethrow：进程已在退出路径，直接结束即可
            }
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                WriteError(ex);
            }
        }

        /// <summary>把异常追加写入输出目录 jianrong-error.log。</summary>
        private static void WriteError(Exception ex)
        {
            try
            {
                string logPath = Path.Combine(AppContext.BaseDirectory, "jianrong-error.log");
                File.AppendAllText(
                    logPath,
                    "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + ex + Environment.NewLine + Environment.NewLine);
            }
            catch
            {
                // 写日志本身失败则静默吞掉，避免二次崩溃
            }
        }
    }
}
