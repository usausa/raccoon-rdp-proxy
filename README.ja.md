# Raccoon.RdpProxy

[English](README.md) | **日本語**

RDP を中継し、**RDP プロトコル内部の `clientAddress`（`TS_EXTENDED_INFO_PACKET`, Client Info PDU 内）を書き換えて**別ホストへ張り直すプロキシです。NLA（ネットワークレベル認証）必須のターゲットには、**ハンドロール実装の CredSSP 資格情報ブリッジ**で認証します。**実 Windows NLA サーバで動作確認済み。**

- .NET 10 / Worker service（Windows サービス / systemd デーモン）
- RDP プロトコル内の `clientAddress` / `clientName` / 識別情報の書き換え
- NLA 必須ターゲット向け CredSSP 資格情報ブリッジ（NTLMv2＋pubKeyAuth＋TSCredentials をハンドロール実装）
- 接続元 IP 制限（CIDR ACL）・複数ターゲットの同時中継
- 外部ランタイム依存なしの単一バイナリ

## 構成

```
[クライアント]     [中継Linux (このプロキシ)]                        [ターゲット]
192.168.1.10  ──▶  192.168.1.20 : 3389   ┐ 自己署名TLSで終端         192.168.2.10:3389
 mstsc(NLA要求)    (デュアルホーム)      │ (クライアント脚=TLSのみ)  (NLA 必須のまま)
                   192.168.2.20 ─────────┘ CredSSPで認証+書き換え ─▶
                   (TCP送信元 & CredSSP)
```

目標: **`192.168.2.10` で `WTSClientAddress` が `192.168.2.20` になること。** → 達成。

## 仕組み

プロキシは **2 つの TLS を終端**し、SSL（クライアント側）↔ NLA（バックエンド側）を橋渡ししながら **3 箇所の PDU を書き換え**ます。

| 脚 | セキュリティ | 内容 |
|---|---|---|
| **クライアント脚**（mstsc→中継） | TLS のみ | mstsc は NLA を要求するが SSL に落として終端（NTLM サーバ役を回避） |
| **バックエンド脚**（中継→ターゲット） | **NLA(CredSSP)** | 設定の資格情報で **CredSSP 認証**（NTLMv2＋pubKeyAuth＋TSCredentials をハンドロール実装） |

**中継中の 3 つの書き換え**（SSL↔NLA の食い違いを吸収）:

1. **`serverSelectedProtocol`**（client→backend, MCS Connect Initial / CS_CORE）: SSL → バックエンド選択値(HYBRID)。
   これが無いとバックエンドがダウングレード検知で RST。
2. **`clientRequestedProtocols`**（backend→client, MCS Connect Response / SC_CORE）: プロキシが送った要求 → mstsc の要求値。
   これが無いと mstsc が認証エラー(0x609)。
3. **`clientAddress`**（client→backend, Client Info PDU / TS_EXTENDED_INFO_PACKET）: 本命の書き換え。

TCP 送信元も `Source` で bind するため、**パケット内 clientAddress と実 TCP 送信元の両方**が指定値になります。

## 動作要件

- 中継ホストはターゲットへ到達でき、`Source` に指定する IP が実在すること（デュアルホーム推奨）
- 配布バイナリは自己完結のため、**中継ホストに .NET ランタイムは不要**。.NET 10 SDK はソースから実行する（`dotnet run`）場合のみ必要
- 中継ホストで受付ポートを開放: `sudo firewall-cmd --add-port=3389/tcp`（環境により nftables 等の分離設定も要確認）

## 実行

```bash
# 配布バイナリ(カレントディレクトリの appsettings.json を読む)
./Raccoon.RdpProxy
```

```pwsh
# ソースから既定設定(appsettings.json)で実行
dotnet run --project Raccoon.RdpProxy

# 開発(appsettings.Development.json: 127.0.0.1 待受 / Debug ログ)
$env:DOTNET_ENVIRONMENT = "Development"
dotnet run --project Raccoon.RdpProxy
```

## 設定（appsettings.json）

設定は **`Proxy` セクション**にまとめます。**セクション直下の値が既定**で、**`Maps[]` の各要素**が受付ポート→ターゲットの 1 マッピングを表し、`Source` / `ClientAddress` / `ClientName` / `MaskClientInfo` / `Credentials` / `Allow` を **map 毎に上書き**できます（未指定はグローバルを継承）。

| キー | 既定 | 説明 |
|---|---|---|
| `Proxy:Listen` | `0.0.0.0` | 待受アドレス |
| `Proxy:Cert` | `proxy.pfx` | サーバ証明書(PFX)。無ければ初回に 10 年物を生成 |
| `Proxy:CertPassword` | `null` | PFX パスワード |
| `Proxy:Source` | `null` | ターゲットへの TCP 送信元 bind（`null`=既定ルート） |
| `Proxy:ClientAddress` | `""` | RDP パケットに書き込む clientAddress |
| `Proxy:ClientName` | `null` | clientName を書き換え（`""` で空名、`null` で素通し） |
| `Proxy:MaskClientInfo` | `false` | 追加で `clientDigProductId` / `clientDir` を消去 |
| `Proxy:CredsspImpl` | `handroll` | CredSSP 実装（`handroll` / `negotiate`） |
| `Proxy:Credentials` | — | CredSSP 資格情報（`Domain` / `User` / `Password` / `NtHash`） |
| `Proxy:Allow` | `[]` | 接続元 IP 許可（CIDR、空なら全許可） |
| `Proxy:Maps` | `[]` | 受付ポート→ターゲットの配列（1 つ以上必須） |

`Maps[]` 要素: `ListenPort`（受付ポート）/ `Host`（ターゲット）/ `Port`（既定 3389）＋上書き用の `Source` / `ClientAddress` / `ClientName` / `MaskClientInfo` / `Credentials` / `Allow`。

```jsonc
{
  "Proxy": {
    "Listen": "0.0.0.0",
    "Cert": "proxy.pfx",
    "Source": "192.168.2.20",
    "ClientAddress": "192.168.2.20",
    "Credentials": { "Domain": "", "User": "Administrator", "Password": "ChangeMe" },
    "Maps": [
      { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 },
      { "ListenPort": 13389, "Host": "192.168.2.11", "Port": 3389,
        "Credentials": { "Domain": "", "User": "Administrator", "Password": "other-pass" } },
      { "ListenPort": 23389, "Host": "192.168.2.12", "Port": 3389 }
    ]
  }
}
```
- 待受アドレスは共通のため、**`ListenPort` は map ごとに別**にします。例では 1 台目を標準の 3389（ホスト名だけで接続可）、以降を 13389 / 23389 にしています。
- 起動ログに各 map の実効値（`Map 0.0.0.0:3389 -> 192.168.2.10:3389 src=… clientAddr=… domain=… user=… allow=…`）が出ます。
- `Password` / `NtHash` が未設定なら CredSSP 無効（TLS 終端のみ＝NLA 無効ターゲット向け）。
- `Domain`: ローカルアカウントは空 or `.`、ドメインは NetBIOS 名。平文 `Password` の代わりに `NtHash`（MD4(password) の 16byte hex）も指定可。

環境変数やコマンドライン引数でも上書きできます（`--Proxy:ClientAddress=…`、`Proxy__Maps__0__Host=…`、`--Serilog:MinimumLevel:Default=Debug` など）。

### 接続元 IP 制限（Allow）
許可した CIDR 以外からの接続は**TLS 前に即拒否**（`connection rejected (not in allow list).` をログ）。未指定/空なら全許可。**map 毎に上書き可**（未指定はグローバルを継承）。
```jsonc
{
  "Proxy": {
    "Allow": ["192.168.1.0/24"],
    "Maps": [
      { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 },
      { "ListenPort": 13389, "Host": "192.168.2.13", "Port": 3389,
        "Allow": ["192.168.1.10/32", "192.168.1.11/32"] }
    ]
  }
}
```

### 識別情報のマスク（ClientName / MaskClientInfo）
`ClientAddress`（IP）以外の識別フィールドも書き換えられます。**2 つの独立したスイッチ**で粒度を選べます（map 毎に上書き可）。

| 設定 | 効果 | 対象フィールド | 露出先の例 |
|---|---|---|---|
| `ClientAddress`（常時） | 常に書換 | `clientAddress` | `WTSClientAddress` |
| **`ClientName`** = 値 | clientName を書き換え | `clientName`（`""` で空） | `WTSClientName`・一部ログ |
| **`MaskClientInfo`** = true | 追加で消去 | `clientDigProductId`＋`clientDir` | 製品ID・パス |

```jsonc
// (A) clientName と clientAddress "だけ" 書き換え
{ "Proxy": { "ClientAddress": "192.168.2.20", "ClientName": "RELAY01",
  "Maps": [ { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 } ] } }

// (B) 上記に加えて製品ID・パスも消す(最大限マスク)
{ "Proxy": { "ClientAddress": "192.168.2.20", "ClientName": "RELAY01", "MaskClientInfo": true,
  "Maps": [ { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 } ] } }
```
**マスクしない項目**（セッション動作/UX に影響するため既定で保持）: `clientBuild`（版）、キーボードレイアウト/IME（ロケール）、`clientTimeZone`（タイムゾーン）、画面解像度。

### 証明書
- `Cert` 未指定なら起動時に自己署名(10 年)を動的生成。`Cert = proxy.pfx` を指定してファイルが無ければ **初回に 10 年 PFX＋.CER を生成**し、以後は同じファイルを読む（証明書が毎回同じ）。
- `--make-cert proxy.pfx` で単体生成も可。`.CER` をクライアントの「信頼されたルート」に入れれば mstsc の証明書警告が消えます。

## ログ

ログは Serilog（`Serilog` セクション、Console＋File シンク）。**ホットパス（毎パケット転送）にログは無く**、全て接続単位です。ログ量は `Serilog:MinimumLevel:Default` で調整します。

- **`Information`（既定）**: スタートアップ設定とエラー/警告のみ。成功接続は無出力（＝低ボリューム、常駐向き）。
- **`Debug`**: 接続ごとに各ステップが出る。
  ```
  [192.168.1.10:52134] CredSSP authenticated (domain= user=Administrator, impl=handroll).
  [192.168.1.10:52134] serverSelectedProtocol rewritten SSL -> 0x2 (MCS Connect Initial).
  [192.168.1.10:52134] clientRequestedProtocols rewritten 0x3 -> 0xB (MCS Connect Response).
  [192.168.1.10:52134] clientAddress rewritten 192.168.1.10 -> 192.168.2.20 (maskClientInfo=False).
  ```

## 常駐運用

**1 インスタンスで複数ターゲットを捌けます**（`Proxy:Maps` に複数 map・ターゲット別資格情報を記載）。常駐は Windows サービス / systemd / Docker のいずれかで。

（Linux 向けバイナリの生成は `build-linux-aot.sh` / `build-linux-aot.bat` / `build-linux-singlefile.bat`。詳細は各スクリプト冒頭のコメント参照。）

### Windows サービス
```pwsh
# 登録(要管理者。binPath= の後ろのスペースは必須)
sc.exe create Raccoon.RdpProxy binPath= "C:\path\to\Raccoon.RdpProxy.exe" start= auto
sc.exe start Raccoon.RdpProxy

# 解除
sc.exe stop Raccoon.RdpProxy
sc.exe delete Raccoon.RdpProxy
```
サービス起動時はカレントが実行ファイルの場所に固定され、`appsettings.json` / `proxy.pfx` / `Log/` はそこから解決されます。

### systemd（Linux）
```bash
sudo mkdir -p /opt/rdp-proxy
sudo cp Raccoon.RdpProxy /opt/rdp-proxy/
sudo cp appsettings.json /opt/rdp-proxy/       # 複数 map をここに記載
sudo chmod 600 /opt/rdp-proxy/appsettings.json # 資格情報を含むため権限を絞る
sudo cp rdp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rdp-proxy
journalctl -u rdp-proxy -f                     # ログ確認
```
（同梱 [rdp-proxy.service](rdp-proxy.service)。`Type=notify` で待受確立まで待機。`proxy.pfx` は初回に自動生成され `/opt/rdp-proxy` に保存。ディレクトリを変える場合は unit 内の `WorkingDirectory` / `ExecStart` / `ReadWritePaths` を揃えて修正。）

### Docker / docker-compose
デュアルホームと source bind のため **host ネットワーク必須**（受付ポートはホストに直接開く）。資格情報はイメージに焼かず `/cfg` にマウント。
```bash
sudo mkdir -p /opt/raccoon-rdpproxy
sudo cp Raccoon.RdpProxy/appsettings.json /opt/raccoon-rdpproxy/
sudo chmod 600 /opt/raccoon-rdpproxy/appsettings.json
docker compose up -d --build      # 同梱 docker-compose.yml (network_mode: host, /opt/raccoon-rdpproxy:/cfg)
docker compose logs -f
```
compose を使わない場合:
```bash
docker build -t raccoon-rdpproxy .
docker run -d --name raccoon-rdpproxy --restart unless-stopped \
  --network host -v /opt/raccoon-rdpproxy:/cfg raccoon-rdpproxy
```
（同梱 [Dockerfile](Dockerfile) / [docker-compose.yml](docker-compose.yml)。ソースからバイナリをビルドするので事前のローカルビルドは不要。`/cfg` の `appsettings.json` / `proxy.pfx` / `Log/` が使われる。）

## 書き換わったことの確認（ターゲットで実行）

**`WTSClientAddress`（＝RDP パケット内 clientAddress）を表示:**
```powershell
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class Wts {
  [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool WTSQuerySessionInformationW(IntPtr h,int sid,int cls,out IntPtr p,out int n);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
  public static string Addr(int sid){ IntPtr p; int n;
    if(!WTSQuerySessionInformationW(IntPtr.Zero,sid,14,out p,out n)) return null; // 14=WTSClientAddress
    try{ if(Marshal.ReadInt32(p)!=2) return null;   // AF_INET / IPv4は offset 6..9
      return Marshal.ReadByte(p,6)+"."+Marshal.ReadByte(p,7)+"."+Marshal.ReadByte(p,8)+"."+Marshal.ReadByte(p,9);
    } finally { WTSFreeMemory(p);} }
  public static string User(int sid){ IntPtr p; int n;
    if(!WTSQuerySessionInformationW(IntPtr.Zero,sid,5,out p,out n)) return "";
    try{ return Marshal.PtrToStringUni(p);} finally { WTSFreeMemory(p);} }
}
'@
0..15 | % { $a=[Wts]::Addr($_); if($a){ "session {0,-3} user={1,-18} WTSClientAddress={2}" -f $_,[Wts]::User($_),$a } }
```
中継経由で接続後、ここが設定した `ClientAddress` になっていれば書き換え成功。

**参考**: イベントビューア(Security 4624 / TerminalServices 1149)の「ソース ネットワーク アドレス」は **TCP 送信元由来**で、`Source` バインドだけで反映されます（パケット内書き換えとは別系統）。

## 診断ツール（CLI モード）

ホストを立てずに実行して終了する診断/ユーティリティモード:

- **`--credssp-probe HOST:PORT`**: mstsc 不要で **CredSSP 認証だけを検証**（TCP→X.224→TLS→CredSSP）。資格情報の妥当性・接続性の切り分けに。
  ```bash
  ./Raccoon.RdpProxy --credssp-probe 192.168.2.10:3389 --user Administrator --password 'pw' --domain ''
  ```
  `★ CredSSP 認証成功` か `× … errorCode=0xC000006D`(=パスワード不一致) 等で判定。
- **`--credssp-impl handroll|negotiate`**: 既定は依存なしの `handroll`。`negotiate` は .NET 標準 SSPI（Linux は `gss-ntlmssp` 要）。ハンドロールが SSPI と等価であることは検証済みなので通常は既定でよい。
- **`--make-cert PATH`**: 10 年 PFX/.CER を生成して終了。
- **`--selftest`**: 自己テスト（プロトコル書き換え・NTLM 暗号ベクタ・CredSSP DER）。
- **`--e2etest`**: 結合テスト（疑似クライアント↔実サービス↔疑似バックエンドで clientAddress 書き換えを全経路検証）。

## 制限・セキュリティ
- RDP を復号して中継する実質的な MITM です。**自身のインフラでの利用**が前提。
- **接続元 IP 制限（`Allow`）**で受付を絞れます（許可外は TLS 前に即拒否）。ファイアウォールと併用推奨。
- 資格情報は `appsettings.json` に置きます。`chmod 600` で権限を絞るか `NtHash` の使用を推奨。
- Kerberos は対象外（IP 接続で NTLM に倒れる前提）。標準 RDP セキュリティ(RC4)も対象外。
- クライアント脚は NLA を SSL に落とします。mstsc 側の「サーバ認証」ポリシーが厳格だと接続不可の場合あり（既定は接続可）。
