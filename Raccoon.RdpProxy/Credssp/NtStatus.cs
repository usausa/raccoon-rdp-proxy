namespace Raccoon.RdpProxy.Credssp;

internal static class NtStatus
{
    public static string Describe(int code)
    {
        var name = Name(code);
        return name is null ? $"0x{code:X8}" : $"0x{code:X8} ({name})";
    }

    public static string? Name(int code) => (uint)code switch
    {
        0x80090302 => "SEC_E_UNSUPPORTED_FUNCTION",
        0x80090304 => "SEC_E_INTERNAL_ERROR",
        0x80090308 => "SEC_E_INVALID_TOKEN",
        0x8009030C => "SEC_E_LOGON_DENIED",
        0x8009030E => "SEC_E_NO_CREDENTIALS",
        0x80090322 => "SEC_E_WRONG_PRINCIPAL",
        0x80090346 => "SEC_E_BAD_BINDINGS",
        0xC000000D => "STATUS_INVALID_PARAMETER",
        0xC0000022 => "STATUS_ACCESS_DENIED",
        0xC000005E => "STATUS_NO_LOGON_SERVERS",
        0xC0000064 => "STATUS_NO_SUCH_USER",
        0xC000006A => "STATUS_WRONG_PASSWORD",
        0xC000006D => "STATUS_LOGON_FAILURE",
        0xC000006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000006F => "STATUS_INVALID_LOGON_HOURS",
        0xC0000070 => "STATUS_INVALID_WORKSTATION",
        0xC0000071 => "STATUS_PASSWORD_EXPIRED",
        0xC0000072 => "STATUS_ACCOUNT_DISABLED",
        0xC00000DF => "STATUS_NO_SUCH_DOMAIN",
        0xC000015B => "STATUS_LOGON_TYPE_NOT_GRANTED",
        0xC0000193 => "STATUS_ACCOUNT_EXPIRED",
        0xC0000224 => "STATUS_PASSWORD_MUST_CHANGE",
        0xC0000234 => "STATUS_ACCOUNT_LOCKED_OUT",
        0xC000035F => "STATUS_BAD_BINDINGS",
        0xC0000388 => "STATUS_DOWNGRADE_DETECTED",
        0xC0000418 => "STATUS_NTLM_BLOCKED",
        _ => null
    };
}
