using System.Text;
using Ufi.Analysis;
using Ufi.UI;

namespace Ufi;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        System.Globalization.CultureInfo.DefaultThreadCurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
        System.Globalization.CultureInfo.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;

        // Headless mode:  UniversalFileInspector.exe --report <file> [<output.txt>]
        int ri = Array.FindIndex(args, a => a.Equals("--report", StringComparison.OrdinalIgnoreCase));
        if (ri >= 0 && ri + 1 < args.Length) return Report(args[ri + 1], ri + 2 < args.Length ? args[ri + 2] : null);

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.ThreadException += (_, e) => MessageBox.Show(e.Exception.ToString(), "Universal File Inspector – unexpected error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        Application.Run(new MainForm(args.FirstOrDefault(a => !a.StartsWith("--"))));
        return 0;
    }

    static int Report(string file, string output)
    {
        try
        {
            using var s = new Session(file);
            s.Start();
            var until = DateTime.Now.AddMinutes(30);
            while (!(s.DoneMeta && s.DoneHash && s.DoneScan) && DateTime.Now < until) Thread.Sleep(50);
            Thread.Sleep(100);
            s.RebuildOverview();
            string text = s.BuildReport();
            File.WriteAllText(output ?? file + ".report.txt", text, new UTF8Encoding(true));
            return 0;
        }
        catch (Exception ex)
        {
            File.WriteAllText((output ?? file + ".report.txt"), "ERROR: " + ex);
            return 1;
        }
    }
}
