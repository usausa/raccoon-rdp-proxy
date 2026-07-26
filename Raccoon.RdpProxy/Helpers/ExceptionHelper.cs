namespace Raccoon.RdpProxy.Helpers;

using System.Text;

internal static class ExceptionHelper
{
    // 例外チェーンを内側までつなげて 1 行に。TLS 切断等の根本原因を出す。
    // Flatten the whole exception chain into a single line, so the root cause (TLS disconnects, etc.) is visible.
    public static string FullMessage(Exception e)
    {
        var sb = new StringBuilder(e.Message);
        for (var ie = e.InnerException; ie is not null; ie = ie.InnerException)
        {
            sb.Append("  <- ").Append(ie.GetType().Name).Append(": ").Append(ie.Message);
        }

        return sb.ToString();
    }
}
