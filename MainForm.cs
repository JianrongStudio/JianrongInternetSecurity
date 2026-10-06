using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using CefSharp;
using CefSharp.WinForms;
using JianRongSecurity.Bridge;
using JianRongSecurity.Engine;

namespace JianRongSecurity
{
    /// <summary>
    /// 主窗体：承载 ChromiumWebBrowser（Dock=Fill），加载输出目录下 UI\index.html。
    /// 负责：桥接注册、托盘最小化/恢复、.NET->页面 事件推送。
    /// </summary>
    public class MainForm : Form
    {
        private readonly ChromiumWebBrowser _browser;
        private readonly JsBackend _jsBackend;
        private readonly NotifyIcon _notifyIcon;

        /// <summary>是否由托盘菜单「退出」触发关闭。非此来源一律最小化到托盘。</summary>
        private bool _exitFromTray;

        /// <summary>UI 线程宿主控件：供引擎层（JinRongBridge）把 Toast 弹窗 marshal 到 UI 线程。</summary>
        public static Control? UIHost { get; private set; }

        public MainForm()
        {
            Text = "金荣安全";
            // 回归原生 Windows 窗口：恢复系统标题栏与标准关闭/最小化/最大化按钮，
            // 原生标题栏自带窗口拖动与调整大小，不再依赖前端 windowHost 桥接控制窗口。
            // 尺寸、位置、启动逻辑、FormClosing 退出流程均保持不变。
            FormBorderStyle = FormBorderStyle.Sizable;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1280, 800);
            MinimumSize = new Size(1024, 720);

            // 窗体与托盘图标（若输出目录存在 appicon.ico）
            TryApplyIcon();

            // 桥接后端（单实例），并订阅 .NET->页面 推送事件
            _jsBackend = new JsBackend();
            _jsBackend.ScriptToExecute += OnScriptToExecute;

            // 1) 先建浏览器（不带 URL），2) 注册桥接，3) 再加载页面，确保页面 JS 执行前绑定就绪
            _browser = new ChromiumWebBrowser
            {
                Dock = DockStyle.Fill
            };
            Controls.Add(_browser);
            UIHost = this; // 供引擎层 Toast 弹窗 marshal 到 UI 线程

            // 注册桥接对象。注意：CefSharp 109 的 BindingOptions 无 CamelCaseJavascriptNames 属性，
            // 仓库默认命名转换器为 LegacyCamelCaseJavascriptNameConverter，已将 C# 方法名首字母转小写
            // （GetVersion -> getVersion），与页面 window.jianrong.getVersion() 调用约定一致。
            _browser.JavascriptObjectRepository.Register(
                "jianrong",
                _jsBackend,
                isAsync: true,
                options: new BindingOptions());

            // 注册窗口控制桥接对象 windowHost（方法名经 CefSharp 默认命名转换器转首字母小写：
            // Minimize->minimize / ToggleMaximize->toggleMaximize / Close->close /
            // StartDrag->startDrag / SetAlwaysOnTop->setAlwaysOnTop，与前端约定一致）。
            // 同样为异步绑定，方法回调发生在 CEF 线程，内部已自行 marshal 到 UI 线程。
            var windowHost = new WindowHostBridge(this);
            _browser.JavascriptObjectRepository.Register(
                "windowHost",
                windowHost,
                isAsync: true,
                options: new BindingOptions());

            string indexPath = Path.Combine(AppContext.BaseDirectory, "UI", "index.html");
            string indexUrl = new Uri(indexPath).AbsoluteUri; // file:///C:/...
            _browser.Load(indexUrl);

            // 托盘图标 + 右键菜单
            _notifyIcon = BuildNotifyIcon();
            _notifyIcon.Visible = true;
        }

        /// <summary>加载 App.ico 作为窗体与托盘图标；缺失则回退系统默认，不抛错。</summary>
        private void TryApplyIcon()
        {
            string icoPath = Path.Combine(AppContext.BaseDirectory, "App.ico");
            if (!File.Exists(icoPath))
            {
                // 开发期直接从源码工程根取
                icoPath = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "App.ico");
            }
            if (File.Exists(icoPath))
            {
                try { Icon = new Icon(icoPath); }
                catch { /* 图标损坏则忽略，使用系统默认 */ }
            }
        }

        /// <summary>构建托盘图标与右键菜单：显示主界面 / 退出。</summary>
        private NotifyIcon BuildNotifyIcon()
        {
            var menu = new ContextMenuStrip();
            menu.Items.Add("显示主界面", null, (s, e) => RestoreFromTray());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出", null, (s, e) => ExitFromTray());

            var ni = new NotifyIcon
            {
                Text = "金荣安全",
                ContextMenuStrip = menu
            };
            ni.DoubleClick += (s, e) => RestoreFromTray();

            // 托盘图标优先沿用窗体图标，否则系统默认
            ni.Icon = Icon.Handle != IntPtr.Zero ? Icon : SystemIcons.Application;
            return ni;
        }

        /// <summary>.NET -> 页面：把桥接后端产生的脚本推给当前页面执行。</summary>
        private void OnScriptToExecute(string js)
        {
            if (_browser.IsDisposed) return;
            if (!_browser.IsBrowserInitialized) return;
            // EvaluateScriptAsync 内部会自行 marshal 到 CEF UI 线程，可跨线程调用
            _ = _browser.EvaluateScriptAsync(js);
        }

        /// <summary>首次显示后：按持久化配置自恢复实时防护与主动防御（浏览器已初始化完毕）。</summary>
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            try
            {
                JinRongBridge.EnsureAutoStart();
            }
            catch { /* 自恢复失败不影响主界面使用 */ }
        }

        /// <summary>从托盘恢复主窗口。</summary>
        private void RestoreFromTray()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        /// <summary>托盘菜单「退出」：置标志位后真正关闭。</summary>
        private void ExitFromTray()
        {
            _exitFromTray = true;
            Close();
        }

        /// <summary>关闭按钮（非托盘退出）：取消关闭、隐藏到托盘。</summary>
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!_exitFromTray)
            {
                e.Cancel = true;
                Hide();
                WindowState = FormWindowState.Minimized;
                return;
            }

            _notifyIcon.Visible = false;
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _notifyIcon?.Dispose();
                _browser?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// 窗口控制桥接对象：供前端自定义标题栏通过 window.windowHost.* 控制无边框主窗口。
    /// 方法名经 CefSharp 默认命名转换器转首字母小写后暴露给 JS。
    /// 注意：异步绑定的方法回调运行在 CEF 线程，所有触碰窗体句柄的操作都必须
    /// 切回 UI 线程（通过 MainForm.Invoke/BeginInvoke）执行。
    /// </summary>
    public class WindowHostBridge
    {
        /// <summary>消息：非客户区鼠标左键按下（用于假装点在标题栏上以拖动窗口）。</summary>
        private const int WM_NCLBUTTONDOWN = 0x00A1;
        /// <summary>命中测试结果：标题栏区域。</summary>
        private const int HTCAPTION = 0x0002;

        private readonly MainForm _form;

        public WindowHostBridge(MainForm form)
        {
            _form = form;
        }

        /// <summary>窗口最小化。</summary>
        public void Minimize()
        {
            RunOnUiThread(() => _form.WindowState = FormWindowState.Minimized);
        }

        /// <summary>最大化 / 还原切换：依据当前 WindowState 判断。</summary>
        public void ToggleMaximize()
        {
            RunOnUiThread(() =>
            {
                _form.WindowState = _form.WindowState == FormWindowState.Maximized
                    ? FormWindowState.Normal
                    : FormWindowState.Maximized;
            });
        }

        /// <summary>
        /// 关闭窗口：直接走 MainForm.Close()，复用现有 OnFormClosing 流程——
        /// 非托盘退出来源一律隐藏到托盘，与旧系统关闭按钮行为完全一致。
        /// </summary>
        public void Close()
        {
            RunOnUiThread(() => _form.Close());
        }

        /// <summary>
        /// 无边框窗口拖动：先 ReleaseCapture 释放鼠标捕获，再向窗体发送
        /// WM_NCLBUTTONDOWN 并带 HTCAPTION 命中测试值，让系统误以为鼠标
        /// 点在标题栏上，从而接管窗口拖动。
        /// </summary>
        public void StartDrag()
        {
            RunOnUiThread(() =>
            {
                ReleaseCapture();
                SendMessage(_form.Handle, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero);
            });
        }

        /// <summary>窗口置顶开关：沙箱引导弹窗打开时传 true、关闭时传 false。</summary>
        public void SetAlwaysOnTop(bool on)
        {
            RunOnUiThread(() => _form.TopMost = on);
        }

        /// <summary>切到 UI 线程执行窗体操作；已在 UI 线程则直接执行，窗体已释放则忽略。</summary>
        private void RunOnUiThread(Action action)
        {
            if (_form.IsDisposed) return;
            if (_form.InvokeRequired)
                _form.BeginInvoke(action);
            else
                action();
        }

        // ---- Win32 API：无边框窗口拖动所需 ----
        /// <summary>释放当前线程窗口上的鼠标捕获。</summary>
        [DllImport("user32.dll")]
        private static extern bool ReleaseCapture();

        /// <summary>向窗口发送消息（这里用于发送 WM_NCLBUTTONDOWN 触发系统拖动）。</summary>
        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    }

    /// <summary>Win32 MINMAXINFO 结构：WM_GETMINMAXINFO 携带的最大化边界信息。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct POINT
    {
        public int x;
        public int y;
    }

    /// <summary>Win32 MINMAXINFO 结构体。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct MINMAXINFO
    {
        public POINT ptReserved;
        public POINT ptMaxSize;
        public POINT ptMaxPosition;
        public POINT ptMinTrackSize;
        public POINT ptMaxTrackSize;
    }
}
