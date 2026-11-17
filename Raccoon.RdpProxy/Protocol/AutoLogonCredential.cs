namespace Raccoon.RdpProxy.Protocol;

internal readonly record struct AutoLogonCredential(string Domain, string User, string Password);
