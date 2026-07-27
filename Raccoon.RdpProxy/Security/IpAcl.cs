namespace Raccoon.RdpProxy.Security;

using System.Linq;

// Allow list of source IPs (CIDR). Empty means allow all. Supports both IPv4 and IPv6.
// Examples: "192.168.100.9", "192.168.100.0/24", "10.0.0.0/8"
internal sealed class IpAcl
{
    private readonly List<(byte[] Net, int Prefix, AddressFamily Af)> rules = [];

    public bool IsEmpty => rules.Count == 0;

    public static IpAcl Parse(IEnumerable<string> entries)
    {
        var acl = new IpAcl();
        foreach (var raw in entries)
        {
            var s = raw.Trim();
            if (s.Length == 0)
            {
                continue;
            }

            var slash = s.IndexOf('/', StringComparison.Ordinal);
            var ipStr = slash >= 0 ? s[..slash] : s;
            if (!IPAddress.TryParse(ipStr, out var ip))
            {
                throw new ArgumentException($"allow: invalid IP/CIDR: {raw}");
            }

            var maxPrefix = ip.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
            var prefix = maxPrefix;
            if (slash >= 0)
            {
                if (!int.TryParse(s[(slash + 1)..], out prefix) || (prefix < 0) || (prefix > maxPrefix))
                {
                    throw new ArgumentException($"allow: invalid prefix length: {raw}");
                }
            }

            acl.rules.Add((ip.GetAddressBytes(), prefix, ip.AddressFamily));
        }

        return acl;
    }

    public bool IsAllowed(IPAddress? ip)
    {
        if (rules.Count == 0)
        {
            return true; // No ACL = allow all
        }

        if (ip is null)
        {
            return false;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4(); // Normalize ::ffff:a.b.c.d to IPv4
        }

        var a = ip.GetAddressBytes();
        foreach (var (net, prefix, af) in rules)
        {
            if (af != ip.AddressFamily)
            {
                continue;
            }

            if (Match(a, net, prefix))
            {
                return true;
            }
        }

        return false;
    }

    public string Describe() => rules.Count == 0 ? "(all)" : String.Join(",", rules.Select(static r => $"{new IPAddress(r.Net)}/{r.Prefix}"));

    private static bool Match(byte[] a, byte[] net, int prefix)
    {
        var fullBytes = prefix >> 3;
        var remBits = prefix & 7;
        for (var i = 0; i < fullBytes; i++)
        {
            if (a[i] != net[i])
            {
                return false;
            }
        }

        if (remBits != 0)
        {
            var mask = (0xFF << (8 - remBits)) & 0xFF;
            if ((a[fullBytes] & mask) != (net[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }
}
