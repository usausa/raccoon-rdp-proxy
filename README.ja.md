# Raccoon.RdpProxy

[English](README.md) | **日本語**

RDP を中継し、**RDP プロトコル内部の `clientAddress`（`TS_EXTENDED_INFO_PACKET`, Client Info PDU 内）を書き換えて**別ホストへ張り直すプロキシです。NLA（ネットワークレベル認証）必須のターゲットには、**ハンドロール実装の CredSSP 資格情報ブリッジ**で認証します。**実 Windows NLA サーバで動作確認済み。**

- .NET 10 / Worker service（Windows サービス / systemd デーモン）
- RDP プロトコル内の `clientAddress` / `clientName` / 識別情報の書き換え
- NLA 必須ターゲット向け CredSSP 資格情報ブリッジ（NTLMv2＋pubKeyAuth＋TSCredentials をハンドロール実装）
- 接続元 IP 制限（CIDR ACL）・複数ターゲットの同時中継
- 外部ランタイム依存なしの単一バイナリ / NativeAOT に対応
- ホットパスにログ無しの低アロケーション設計（`Span` / `ArrayPool` / 生 `Socket`）

## 構成

```
[クライアント]            [中継Linux (このプロキシ)]                    [ターゲット]
192.168.100.9  ──▶  192.168.100.99 : 33031  ┐ 自己署名TLSで終端         192.168.50.31:3389
 mstsc(NLA要求)      (デュアルホーム)          │ (クライアント脚=TLSのみ)   (NLA 必須のまま)
                    192.168.50.254 ───────────┘ CredSSPで認証+書き換え ─▶
                    (TCP送信元 & CredSSP)
```

目標: **`192.168.50.31` で `WTSClientAddress` が `192.168.50.254` になること。** → 達成。

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

## Requirements

- .NET 10 SDK / runtime
- 中継ホストはターゲットへ到達でき、`Source` に指定する IP が実在すること（デュアルホーム推奨）

## ビルド

```pwsh
# 開発ビルド
dotnet build Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release
```

### Linux 配布バイナリ

Linux 向け成果物を作る bat は 2 つあります。どちらも自己完結（リレー機に .NET 不要）で、**成果物の生成のみ**を行います（転送は手動）。

| | `build-aot.bat` | `build-linux.bat` |
| --- | --- | --- |
| ビルドホスト | **WSL**（Linux ホストが必要） | **Windows 単体** |
| コンパイル方式 | NativeAOT（ネイティブコード） | JIT・単一ファイルバンドル |
| 出力先 | `publish/aot-linux-x64/` | `publish/linux-x64/` |
| サイズ | **約 9 MB** | 約 38 MB |
| 起動速度 / メモリ | 最速 / 最小 | 劣る（JIT＋起動時展開） |
| 前提 | WSL＋.NET SDK＋clang＋zlib ヘッダ | Windows の .NET SDK のみ |
| SELinux `enforcing` | `execmem` 不要 | `execmem` が要る場合あり（展開＋JIT） |

リリースには `build-aot.bat` を推奨。Linux ビルドホストが用意できない場合に `build-linux.bat` を使います。

#### A. NativeAOT（build-aot.bat）

NativeAOT は Windows から Linux 向けにクロスコンパイルできず **Linux ビルドホストが必須**のため、発行自体は **WSL** で実行します。

```bat
build-aot.bat                 :: linux-x64（既定）
build-aot.bat linux-arm64     :: ARM リレー向け
```
→ `publish/aot-linux-x64/Raccoon.RdpProxy`。`appsettings.json` と一緒にリレー機へコピーします。

#### B. Windows 単体（build-linux.bat）

自己完結の単一ファイルを **Windows だけ**でクロス発行します（WSL・コンテナ不要）。NativeAOT ではなく JIT ランタイムを同梱する方式なので、OS を跨いだ発行が可能です。

```bat
build-linux.bat                 :: linux-x64（既定）
build-linux.bat linux-arm64     :: ARM リレー向け
```
→ `publish/linux-x64/Raccoon.RdpProxy`。`appsettings.json` と一緒にリレー機へコピーします。

Windows 側に必要なのは .NET SDK だけです。

#### WSL の初期セットアップ（build-aot.bat 用・初回のみ）

発行は **既定のディストロ**で実行されます。WSL はカレントの Windows ディレクトリを自動的にマウントするため、成果物はこのリポジトリ内に戻ってきます。

```bat
:: 1. ディストロの導入（既にあれば不要）
wsl --install -d Ubuntu

:: 2. 既定に設定（build-aot.bat は既定のディストロを使う）
wsl --set-default Ubuntu
wsl --list --verbose
```

続いてディストロ内で、.NET SDK 10 と NativeAOT のリンクに必要なパッケージを導入します:

```bash
sudo apt update
sudo apt install -y dotnet-sdk-10.0 clang zlib1g-dev
```

`dotnet-sdk-10.0` パッケージが無いディストロでは、[Microsoft の導入手順](https://learn.microsoft.com/ja-jp/dotnet/core/install/linux)に従うか、インストールスクリプトを使います:

```bash
curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0
echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.bashrc
```

確認（`build-aot.bat` はこの 2 つを起動時にチェックします）:

```bash
dotnet --version
clang --version
```

> ビルドは `/mnt/...`（drvfs）越しに走るため、Linux ファイルシステム内でのビルドより低速です。頻繁に回すならディストロ側にクローンしてビルドする方が高速です。

> `build-aot.bat` のコメントだけ英語のみです。cmd.exe はバッチファイルをコンソールのコードページで読むため、UTF-8 の日本語が化け、化けたバイトがコマンド区切りとして解釈されて動作しなくなるためです。

**Linux ホスト上**で直接ビルドする場合:
```bash
sudo dnf install -y clang zlib-devel      # RHEL系（Debian系: apt install clang zlib1g-dev）
dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r linux-x64 \
  -p:PublishAot=true -p:StripSymbols=true -o publish/aot-linux-x64
```

## 実行

```pwsh
# 既定設定(appsettings.json)で実行
dotnet run --project Raccoon.RdpProxy

# 開発(appsettings.Development.json: 127.0.0.1 待受 / Debug ログ)
$env:DOTNET_ENVIRONMENT = "Development"
dotnet run --project Raccoon.RdpProxy
```

- 受付ポート開放: `sudo firewall-cmd --add-port=33031/tcp`（環境により nftables 等の分離設定も要確認）。
- `Source` の IP は中継ホストに実在すること。

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
    "Source": "192.168.50.254",
    "ClientAddress": "192.168.50.254",
    "Credentials": { "Domain": "", "User": "Administrator", "Password": "ChangeMe" },
    "Maps": [
      { "ListenPort": 33031, "Host": "192.168.50.31", "Port": 3389 },
      { "ListenPort": 33032, "Host": "192.168.50.32", "Port": 3389,
        "Credentials": { "Domain": "", "User": "Administrator", "Password": "other-pass" } },
      { "ListenPort": 33033, "Host": "192.168.50.33", "Port": 3389 }
    ]
  }
}
```
- 起動ログに各 map の実効値（`src=… clientAddr=… user=DOM\user allow=…`）が出ます。
- `Password` / `NtHash` が未設定なら CredSSP 無効（TLS 終端のみ＝NLA 無効ターゲット向け）。
- `Domain`: ローカルアカウントは空 or `.`、ドメインは NetBIOS 名。平文 `Password` の代わりに `NtHash`（MD4(password) の 16byte hex）も指定可。

環境変数やコマンドライン引数でも上書きできます（`--Proxy:ClientAddress=…`、`Proxy__Maps__0__Host=…`、`--Serilog:MinimumLevel:Default=Debug` など）。

### 接続元 IP 制限（Allow）
許可した CIDR 以外からの接続は**TLS 前に即拒否**（`接続拒否: 許可IP外` をログ）。未指定/空なら全許可。**map 毎に上書き可**（未指定はグローバルを継承）。
```jsonc
{
  "Proxy": {
    "Allow": ["192.168.100.0/24"],
    "Maps": [
      { "ListenPort": 33031, "Host": "192.168.50.31", "Port": 3389 },
      { "ListenPort": 33099, "Host": "192.168.50.99", "Port": 3389,
        "Allow": ["192.168.100.9/32", "192.168.100.10/32"] }
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
{ "Proxy": { "ClientAddress": "192.168.50.254", "ClientName": "RELAY01",
  "Maps": [ { "ListenPort": 33031, "Host": "192.168.50.31", "Port": 3389 } ] } }

// (B) 上記に加えて製品ID・パスも消す(最大限マスク)
{ "Proxy": { "ClientAddress": "192.168.50.254", "ClientName": "RELAY01", "MaskClientInfo": true,
  "Maps": [ { "ListenPort": 33031, "Host": "192.168.50.31", "Port": 3389 } ] } }
```
**マスクしない項目**（セッション動作/UX に影響するため既定で保持）: `clientBuild`（版）、キーボードレイアウト/IME（ロケール）、`clientTimeZone`（タイムゾーン）、画面解像度。

## ログ

ログは Serilog（`Serilog` セクション、Console＋File シンク）。**ホットパス（毎パケット転送）にログは無く**、全て接続単位です。ログ量は `Serilog:MinimumLevel:Default` で調整します。

- **`Information`（既定）**: スタートアップ設定とエラー/警告のみ。成功接続は無出力（＝低ボリューム、常駐向き）。
- **`Debug`**: 接続ごとに各ステップが出る。
  ```
  CredSSP 認証成功 (user=.\Administrator, impl=handroll)
  serverSelectedProtocol 書換: SSL -> 0x2 (MCS Connect Initial)
  clientRequestedProtocols 書換: 0x3 -> 0xB (MCS Connect Response)
  clientAddress 書換: 192.168.100.9 -> 192.168.50.254
  ```

## 常駐運用

**1 インスタンスで複数ターゲットを捌けます**（`Proxy:Maps` に複数 map・ターゲット別資格情報を記載）。常駐は Windows サービス / systemd / Docker のいずれかで。

### Windows サービス
```pwsh
# 発行
dotnet publish Raccoon.RdpProxy/Raccoon.RdpProxy.csproj -c Release -r win-x64 --self-contained false -o publish

# 登録(要管理者。binPath= の後ろのスペースは必須)
sc.exe create Raccoon.RdpProxy binPath= "C:\path\to\publish\Raccoon.RdpProxy.exe" start= auto
sc.exe start Raccoon.RdpProxy

# 解除
sc.exe stop Raccoon.RdpProxy
sc.exe delete Raccoon.RdpProxy
```
サービス起動時はカレントが実行ファイルの場所に固定され、`appsettings.json` / `proxy.pfx` / `Log/` はそこから解決されます。

### systemd（Linux）
```bash
sudo mkdir -p /opt/raccoon-rdpproxy
sudo cp publish/aot-linux-x64/Raccoon.RdpProxy /opt/raccoon-rdpproxy/
sudo cp Raccoon.RdpProxy/appsettings.json /opt/raccoon-rdpproxy/   # 複数 map をここに記載
sudo chmod 600 /opt/raccoon-rdpproxy/appsettings.json             # 資格情報を含むため権限を絞る
sudo cp raccoon-rdpproxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now raccoon-rdpproxy
journalctl -u raccoon-rdpproxy -f                                 # ログ確認
```
（同梱 [raccoon-rdpproxy.service](raccoon-rdpproxy.service)。`Type=notify` で待受確立まで待機。`proxy.pfx` は初回に自動生成され `/opt/raccoon-rdpproxy` に保存。）

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
（同梱 [Dockerfile](Dockerfile) / [docker-compose.yml](docker-compose.yml)。同じ NativeAOT バイナリをソースからビルドするので事前のローカルビルドは不要。`/cfg` の `appsettings.json` / `proxy.pfx` / `Log/` が使われる。）

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
中継経由で接続後、ここが **192.168.50.254** なら書き換え成功。

**参考**: イベントビューア(Security 4624 / TerminalServices 1149)の「ソース ネットワーク アドレス」は **TCP 送信元由来**で、`Source` バインドだけで 192.168.50.254 になります（パケット内書き換えとは別系統）。

## 証明書
- `Cert` 未指定なら起動時に自己署名(10 年)を動的生成。`Cert = proxy.pfx` を指定してファイルが無ければ **初回に 10 年 PFX＋.CER を生成**し、以後は同じファイルを読む（証明書が毎回同じ）。
- `--make-cert proxy.pfx` で単体生成も可。`.CER` をクライアントの「信頼されたルート」に入れれば mstsc の証明書警告が消えます。

## 診断ツール（CLI モード）

ホストを立てずに実行して終了する診断/ユーティリティモード:

- **`--credssp-probe HOST:PORT`**: mstsc 不要で **CredSSP 認証だけを検証**（TCP→X.224→TLS→CredSSP）。資格情報の妥当性・接続性の切り分けに。
  ```bash
  ./Raccoon.RdpProxy --credssp-probe 192.168.50.31:3389 --user Administrator --password 'pw' --domain ''
  ```
  `★ CredSSP 認証成功` か `× … errorCode=0xC000006D`(=パスワード不一致) 等で判定。
- **`--credssp-impl handroll|negotiate`**: 既定は依存なしの `handroll`。`negotiate` は .NET 標準 SSPI（Linux は `gss-ntlmssp` 要）。ハンドロールが SSPI と等価であることは検証済みなので通常は既定でよい。
- **`--make-cert PATH`**: 10 年 PFX/.CER を生成して終了。
- **`--selftest`**: 自己テスト（プロトコル書き換え・NTLM 暗号ベクタ・CredSSP DER）。
- **`--e2etest`**: 結合テスト（疑似クライアント↔実サービス↔疑似バックエンドで clientAddress 書き換えを全経路検証）。

## 検証状況
- **実 Windows NLA サーバで CredSSP 認証成功・RDP 接続確立を確認済み**（handroll 実装、複数ホスト）。
- 自動テスト `--selftest`（全緑）:
  - clientAddress 書き換え（長さ再計算・末尾保全）
  - MCS `serverSelectedProtocol` / `clientRequestedProtocols` 書き換え（オフセット検証）
  - clientName/productId マスク・clientDir マスク
  - **NTLM 暗号を MS-NLMP 4.2.4 公式ベクタで検証**（MD4/NTOWFv2/NTProofStr/SessionBaseKey/鍵交換/封印）
  - CredSSP DER 往復
- `--e2etest`: TLS 終端＋clientAddress 書き換えの全経路。

## 制限・セキュリティ
- RDP を復号して中継する実質的な MITM です。**自身のインフラでの利用**が前提。
- **接続元 IP 制限（`Allow`）**で受付を絞れます（許可外は TLS 前に即拒否）。ファイアウォールと併用推奨。
- 資格情報は `appsettings.json` に置きます。`chmod 600` で権限を絞るか `NtHash` の使用を推奨。
- Kerberos は対象外（IP 接続で NTLM に倒れる前提）。標準 RDP セキュリティ(RC4)も対象外。
- クライアント脚は NLA を SSL に落とします。mstsc 側の「サーバ認証」ポリシーが厳格だと接続不可の場合あり（既定は接続可）。

## 実装メモ
- **CredSSP の pubKeyAuth は PKCS#1 RSAPublicKey**（.NET `GetRSAPublicKey().ExportRSAPublicKey()`、OpenSSL `i2d_PublicKey`、pyspnego `PublicFormat.PKCS1` 相当）を使う。**SubjectPublicKeyInfo ではない**（間違えると NEGOTIATE/CHALLENGE は通るが AUTHENTICATE 後にサーバが切断）。`CredSspKey.FromCertificate` に集約。
- PDU パース/再構築は `ReadOnlySpan<byte>` + `BinaryPrimitives`、出力は単一バッファへ直書き。
- 転送・フレーミングは `ArrayPool<byte>`、DER/NTLM/ネゴ PDU 生成は `stackalloc`。X.224 署名判定は `Unsafe`+`MemoryMarshal`。GC はワークステーション同時 GC＋TieredPGO。
- NTLMv2/RC4/MD4/CredSSP は外部依存なしのハンドロール実装。
