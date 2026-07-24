# 仮想サービスを実装する

Juneau の仮想サービスプレーンは、Pod から Subnet ローカルの仮想 IP に向かう L7 トラフィックを、daemon のユーザ空間で終端する仕組みです。最初の組み込みサービスとして per-Subnet DNS resolver が実装されていますが、基盤は DNS 専用ではありません。NTP・syslog 転送・カスタム HTTP プロキシなど、VPC 内側のミドルウェアを後から同じ仕組みで追加できます。

このガイドは、新しい仮想サービスを実装する開発者向けの手順書です。共通基盤が提供している機能、自分で実装する範囲、設計上守るべきルールをまとめています。

## なぜ仮想サービスプレーンが必要か

カスタム VPC では Pod IP が VPC 間でオーバーラップし得るため、ホスト OS のルーティングテーブルだけでは応答を正しい Pod に戻せません。応答先の特定には (vpc_id, pod_ifindex, pod_mac) の組が必要で、この情報は BPF が egress パケットを捕捉した時点でしか取得できません。

仮想サービスプレーンは、この復路情報を BPF map と Go 側のフローテーブルにフロー単位で保持し、応答を AF_PACKET で Pod の host 側 veth に直接配送します。ホストルーティングテーブルは経由しません。

## アーキテクチャ概要

```
[Pod]
  │ (Pod が 仮想 VIP:port に送信)
  ▼
[host 側 veth] — TC eBPF (pod_egress.c)
                    ├─ 5-tuple で virtual_service_map を引く
                    ├─ ヒットすれば return-path を virtual_service_flow_map に記録
                    ├─ iph->id に subnet_id を埋め込む
                    └─ TAP デバイスに redirect
                         │
                         ▼
                  [TAP juneau-svc0]
                         │
                         ▼
              [packetplane.Dispatcher (daemon)]
                         │
                ┌────────┴────────┐
                ▼                 ▼
         UDPHandler         TCPHandler (gVisor netstack)
                │                  │
                │                  ▼
                │           gonet.Listener.Accept
                │                  │
                ▼                  ▼
            (任意の L7 ロジック)
                │                  │
                ▼                  ▼
        WriteResponse(payload)   net.Conn.Write
                │                  │
                └────────┬─────────┘
                         ▼
              [packetplane.Sender]
                         │
                         ▼
             AF_PACKET sendto(pod_ifindex)
                         │
                         ▼
               [host 側 veth] → [Pod]
```

3 層に分かれています。

1. BPF クラシファイア (`daemon/bpf/pod_egress.c`)
   Pod の egress で 5-tuple を見て該当パケットを TAP に redirect。テナント情報をマップに記録。
2. パケットプレーン (`daemon/internal/daemon/virtservice/packetplane/`)
   TAP からフレームを読み、フロー情報を BPF から復元し、AF_PACKET で応答を送る。
3. 仮想サービス API と L7 (`daemon/internal/daemon/virtservice/{types.go, registry.go}` と `dns/` などの実装)
   Registry を介して L7 サービスが (tenant, VirtualAddr) にバインドする。

## 共通基盤が提供している機能

仮想サービスを実装する側は、以下を自分で書く必要はありません。

| 機能 | 提供箇所 |
|---|---|
| TAP デバイスのライフサイクル | `packetplane/tap.go` |
| AF_PACKET 送信 socket | `packetplane/afpacket.go` |
| フロー情報の BPF map から Go 構造体への変換 | `packetplane/flowtable.go` |
| Eth + IPv4 + UDP ヘッダ生成とチェックサム計算 | `packetplane/builder.go` |
| TAP からの読み取りループと proto/port 別 dispatch | `packetplane/dispatcher.go` |
| BPF `virtual_service_map` への登録と解除 | `virtservice/registry.go` |
| gVisor netstack 経由の TCP listener | `virtservice/netstack/facade.go` |
| Subnet ローカルの仮想 IP のフィールド管理 | `controller/internal/controller/subnet_controller.go` |
| informer 駆動の reconciler 共通枠組 | `daemon/internal/daemon/runner/runner.go` |
| Pod の /etc/resolv.conf 注入 (DNS 用の参考実装) | `controller/internal/webhook/v1alpha1/pod_webhook.go` |

## 自分で実装する範囲

新しい仮想サービスを追加する場合、典型的に必要な作業は以下です。

1. Subnet API の拡張。per-Subnet 固定 IP/MAC が必要なら、Subnet.Status に新フィールド (例: `Status.NTP`, `Status.NTPMAC`) を足し、SubnetReconciler で `.3` などの予約アドレスを払い出す。
2. daemon の Subnet reconciler で BPF `arp_table` に新サービスの IP→MAC エントリを書く。
3. L7 ハンドラを `daemon/internal/daemon/virtservice/<svcname>/` に実装する。UDP は `virtservice.PacketHandler` を、TCP は net.Conn を受ける関数を書く。必要なら resolver や forwarder などの上位ロジックも追加する。
4. サービス起動コード。Subnet informer 駆動の reconciler を作り、各 Subnet に対し `Registry.RegisterUDPHandler` または `Registry.ListenTCP` を呼ぶ。
5. app.go への配線。dns.Service と同じ要領で起動・停止フックを追加する。
6. Pod 側設定の注入。Pod がそのサービスを参照するように設定する必要があれば、Mutating Webhook や InitContainer で注入する。DNS は dnsConfig を注入する例が `pod_webhook.go` にある。
7. テスト。L7 ハンドラの単体テスト、Webhook や Subnet status の envtest、Pod から実際に到達できることを確認する E2E。

## ステップバイステップ: UDP 仮想サービスを追加する

例として、Subnet の `.3` をリッスン IP とする per-Subnet 仮想 NTP サービス (udp/123) を追加するシナリオで進めます。

### Step 1. Subnet API に NTP VIP / MAC を足す

`controller/api/v1alpha1/subnet_types.go`:

```go
type SubnetStatus struct {
    // ... 既存
    DNS    string `json:"dns,omitempty"`
    DNSMAC string `json:"dnsMAC,omitempty"`

    NTP    string `json:"ntp,omitempty"`
    NTPMAC string `json:"ntpMAC,omitempty"`
}
```

`controller/internal/controller/subnet_controller.go` で次を行います。

- `nextNTPAddress(cidr)` を `nextDNSAddress` と同じ形で実装し `.3` を返す。
- Reconcile 内で MAC を `newLAA()` で初回生成し Status に保持。
- `computeSubnetExcluded` の予約リストに `.3` を加える。

`make controller-manifests controller-generate` で CRD と DeepCopy を再生成します。

### Step 2. daemon の Subnet reconciler で ARP エントリを書く

`daemon/internal/daemon/dataplane/reconciler/subnet.go` の `upsertDNSARP` をモデルに `upsertNTPARP` を追加します。subnetSnapshot にも `ntpIP uint32` を持たせ、削除時に古いエントリを掃除します。

これにより Pod が `.3` の MAC を ARP したとき、既存の `pod_egress.c` の `handle_arp` が `arp_table` から MAC を返答できるようになります。BPF C コードに変更は不要です。DNS と同じ理由です。

### Step 3. L7 ハンドラを書く

`daemon/internal/daemon/virtservice/ntp/handler.go`:

```go
type Handler struct {
    // 上流 NTP サーバ、レイヤ別オフセット計算など
}

// virtservice.PacketHandler を実装。
func (h *Handler) HandlePacket(ctx context.Context, req virtservice.PacketRequest, resp virtservice.Responder) error {
    // req.Payload は UDP ペイロードのみ (IP/UDP ヘッダ無し)
    // req.Tenant は VPC ID + Subnet ID
    // req.ClientIP / req.ClientPort は Pod 側
    response := buildNTPReply(req.Payload)
    return resp.WriteResponse(response)
}
```

ハンドラは payload のみを扱います。IP / UDP / Ethernet ヘッダ生成、チェックサム計算、Pod ifindex の解決はパケットプレーン側の責務です。Responder の実体は `udpResponder` (`registry.go`) で、`packetplane.BuildUDPResponse` を呼びます。

### Step 4. Subnet informer 駆動の binding reconciler

`daemon/internal/daemon/virtservice/ntp/service.go` を `dns.Service` (`dns/service.go`) を雛形にして実装します。要点は次のとおりです。

- Subnet informer 駆動。Reconcile キーは Subnet 名。
- Subnet の `Status.NTP` / `Status.NTPMAC` / `Status.VNI` が揃っていれば `Registry.RegisterUDPHandler` を呼ぶ。
- Subnet の所属 Vpc を確認し、`Vpc.Status.VpcID` を Tenant に入れる。
- 戻ってきた Unregister 関数を保持し、Subnet 削除や VIP 変更時に呼ぶ。
- bindings\[subnetName\] で snapshot を持ち、equality 判定で no-op か rebind を分ける。

default Vpc の扱いは個別に判断します。DNS は default Vpc 配下の Subnet をスキップしていますが、新サービスでは要件次第です。`subnet.Spec.Vpc == "default"` のガードで切り替えます。

### Step 5. app.go への配線

`daemon/internal/daemon/app.go` の `startDNSService` を真似て `startNTPService` を追加します。

```go
ntpService, ntpRunner, err := startNTPService(ctx, cl, vsMgr.Registry(), bpfManager, ntpUpstream)
if err != nil { ... }
defer func() {
    _ = ntpService.Stop()
    _ = ntpRunner.Stop()
}()
```

サービス固有の設定 (上流サーバなど) は `cli.StringFlag` で追加します。

### Step 6. Pod 側の設定注入

NTP の場合、Pod が chrony や systemd-timesyncd で参照する設定ファイルを書き換える必要があります。仮想サービスごとに事情が異なるため、選択肢を挙げます。

- InitContainer + EmptyDir: Pod 起動時に `/etc/chrony/chrony.conf` を Subnet の `.3` 参照に書き換える InitContainer を Mutating Webhook で挿入する。
- DaemonSet + hostPath: Node 全体で chrony を動かす場合に使う。仮想サービスではなく Pod 内 NTP を使うパターンと相性がよい。
- 環境変数: アプリ依存。

DNS は dnsPolicy=None と dnsConfig という Pod の標準フィールドがあるため Webhook で完結しました。Pod に対応する標準フィールドが無いサービスは、Webhook と InitContainer 注入の組み合わせを使います。`controller/internal/webhook/v1alpha1/pod_webhook.go` の `PodDNSDefaulter` を雛形にしてください。

## ステップバイステップ: TCP 仮想サービスを追加する

`Registry.ListenTCP(spec)` が net.Listener を返します。受け取り側は通常の Go の TCP サーバを書くのと同じです。

```go
listener, unregister, err := registry.ListenTCP(virtservice.ServiceSpec{
    ID:         virtservice.ServiceID(<新サービス用 ID>),
    Tenant:     virtservice.TenantID{VPCID: vpcID, SubnetID: vni},
    Addr:       virtservice.VirtualAddr{IP: vip, Port: 8080, Proto: virtservice.ProtocolTCP},
    ServiceMAC: serviceMAC,
})
if err != nil { return err }
defer unregister()

go func() {
    for {
        conn, err := listener.Accept()
        if err != nil { return }
        go handleConn(conn)
    }
}()
```

net.Conn の中身は gVisor の gonet.Conn ですが、ABI は標準の net.Conn と互換です。Read/Write/Close/Deadline はすべて使えます。

DNS の TCP 実装 (`dns/tcp_handler.go`) が参考になります。長さプリフィックス DNS メッセージのストリーム処理、idle timeout、shared resolver の呼び出しが含まれています。

注意点。

- ServiceID の衝突。`virtservice/types.go` で ServiceIDDNS = 1 が定義済み。新サービスは新しい uint32 を割り当て、定数として export してください。BPF map の値として記録されるため、後から番号を変更すると map のライブマイグレーションが必要になります。
- DNS resolver と仮想サービス管理は Node 内で共有しますが、TCP の gVisor stack は VPC ごとに分けます。gVisor の単一 stack では device-bind した listener の `VIP:port` は分離できても、別 NIC に同じ 4-tuple の接続が存在すると transport demux が正しい listener へフォールバックしません。各 VPC を独立した stack + NIC + route に分け、endpoint も対象 NIC へ device-bind することで、同一 CIDR・同一 `VIP:port`・同一 4-tuple を持つ VPC を同時に扱います。

## 設計上の不変条件

新サービスを実装する際、以下を守らないとフロー追跡や VPC 隔離が壊れます。

### 1. テナント情報を IP 単独から推測しない

Pod IP は VPC 間で衝突し得ます。(subnet_id, ip) または (vpc_id, ip) のペアが最低限必要です。`PacketRequest.Tenant` (UDP) と gonet.Conn.RemoteAddr() および listener の Tenant (TCP) の両方で取得できます。

### 2. 復路はホストルーティングテーブルに頼らない

UDP の `Responder.WriteResponse` と TCP の gonet.Conn.Write は、内部で AF_PACKET 経由で Pod の host 側 veth に直接送ります。普通の net.Dial で Pod に向かって書いてはいけません。host のルーティングテーブルには Pod IP の経路が無いか、別 VPC の Pod に届く可能性があります。

### 3. L7 コードから BPF / TAP / AF_PACKET を直接触らない

これらは packetplane 配下に閉じ込めてあります。新サービスの実装が `packetplane.Sender.SendTo` を直接呼んだり `golang.org/x/sys/unix` を import したりする必要はありません。必要になった場合は、Registry か Responder の API を拡張する方が長期的には保守しやすくなります。

### 4. BPF map のキーバイト境界

`virtual_service_map` と `virtual_service_flow_map` の Go 構造体 (`bpf.PodEgressVirtualServiceKey` など) は cilium/ebpf の reflection ベースのデコーダを通ります。すべてのフィールドは export されている必要があります。BPF C 側で `_pad` や暗黙の構造体パディングがあれば、Go 側でも Pad / AlignPad のように export 名で揃える必要があります。実例は `packetplane/flowtable.go` の `FlowKey.Pad` と `FlowVal.AlignPad` を参照してください。

### 5. iph->id への subnet_id 埋め込み

BPF の `handle_virtual_service` (`pod_egress.c`) が TAP redirect 直前に IPv4 ヘッダの id フィールドを subnet_id (16bit) に書き換えています。これは TAP 越しに subnet 情報を運ぶための仕組みです。Dispatcher は iph->id を読んで subnet を特定します。

新サービスでフラグメント化した IPv4 を扱う場合、この設計は使えません。代替案。

- 別 TAP デバイスを per-subnet で作る (ifindex で subnet を判別)
- BPF 側で metadata を skb_adjust_room でプリペンドする (大きな BPF 改修が必要)
- IP fragment を BPF 側で再構成する

現状の Juneau は短い UDP / TCP 制御プレーン用途を想定しているため、フラグメント化はサポート対象外です。

### 6. 仮想 VIP の払い出し位置

DNS は Subnet の `.2` を予約しています。次のサービスが `.3` を使う場合、`subnet_controller.go` の `computeSubnetExcluded` で予約済みかを確認してください。現在は将来予約として除外済みです。`/29` 以上でないと `.3` は使用可能領域に入りません。`/30` だと DNS で枯渇するため、新サービスを足す場合は最小 prefix 要件を見直す必要があります。

## ポリシーは svcpolicy に集約する

DNS resolver の VPC 越え resolution の許可判定 (`ResolvableFrom`) は `daemon/internal/daemon/svcpolicy/` に切り出してあります。BPF backend reconciler (Service) と DNS resolver の両方が同じ関数を使うことで、データプレーンと DNS の挙動が一致します。

新サービスでも tenant 横断ポリシーを判定する場面 (例: NTP は default Vpc 配下のみ許可、cross-VPC は拒否) があれば、判定ロジックは svcpolicy パッケージに置いてください。L7 ハンドラ内に inline で書くと、後から別レイヤで同じ判定をしたくなったときにズレが生じます。

## テスト戦略

各レイヤごとの想定テスト。

| レイヤ | テストの種類 | 例 |
|---|---|---|
| L7 ハンドラ単体 | Go unit test | `dns/handler_test.go` (stub Resolver / VPCResolver / Responder) |
| Resolver / Zone | Go unit test + fake k8s client | `dns/zone_test.go` |
| Subnet API | controller envtest | `controller/internal/controller/vpc_subnet_controller_test.go` |
| Pod webhook | controller webhook envtest | `controller/internal/webhook/v1alpha1/pod_webhook_test.go` |
| パケットプレーン (フレーム生成) | Go unit test | `packetplane/builder_test.go` |
| End-to-end (TAP/BPF/AF_PACKET 含む) | kind ベースの e2e | `test/e2e/dns_test.go` |

packetplane 自体の TAP / AF_PACKET / netstack を単体テストするのは難しく、root + Linux カーネル + gVisor が必要です。代わりに次のように分担します。

- 純粋ロジック (`builder.go`、`flowtable.go` のキー生成、`dispatcher.go` のパース) に単体テストを書く。
- Registry を NetstackFacade インタフェースで切り離してあるため、新サービスの「Registry に登録される側」のテストではモックを差し込める。
- 結合は e2e で確認する。
- TCP サービスの e2e は `dig +tcp` など、UDP fallback を許さないクライアントで実際の transport を固定する。
- VPC 分離の e2e では、同一 CIDR と同一 `VIP:port` を持つ 2 つの VPC を同時に作り、両方から応答できることを確認する。

## 参考実装

DNS が現状唯一の実例です。新サービスを書くときに参照するファイル。

- 設計仕様 (実装決定の背景): `/tmp/juneau-virtual-service-plane-dns-handoff.md`
- 実装サマリ: `/tmp/juneau-virtual-service-plane-implementation.md`
- L7 ハンドラ雛形: `daemon/internal/daemon/virtservice/dns/handler.go` (UDP) / `dns/tcp_handler.go` (TCP)
- Subnet 駆動 binding reconciler: `daemon/internal/daemon/virtservice/dns/service.go`
- Subnet API 拡張: `controller/api/v1alpha1/subnet_types.go` の DNS / DNSMAC フィールドと `subnet_controller.go` の `nextDNSAddress`
- daemon Subnet reconciler ARP 書き込み: `daemon/internal/daemon/dataplane/reconciler/subnet.go` の `upsertDNSARP`
- Pod 設定注入 Webhook: `controller/internal/webhook/v1alpha1/pod_webhook.go`
- E2E パターン: `test/e2e/dns_test.go`

## ペイロード長の制限と truncation

UDP は IP データグラムのサイズ制限を受けます。DNS は EDNS0 ハンドシェイクと TC bit によるサイズネゴが標準で定義されているため、`dns/handler.go` で 512 / EDNS0 buffer サイズ超過時に truncate して TC を立てています。新サービスの UDP プロトコルが大きなペイロードを返す可能性があるなら、TCP fallback の経路を最初から設計してください。

TAP の MTU は `--virtservice-tap-mtu` (デフォルト 1450) で、underlay の VXLAN オーバーヘッドを差し引いてあります。VPN 経由でさらに小さい MTU が必要な環境では下げてください。

## チェックリスト

新サービスを実装する PR を出す前の確認項目。

- [ ] Subnet.Status に新フィールドを追加し、CRD と DeepCopy を再生成した
- [ ] `nextXxxAddress` で予約 IP を計算し、`computeSubnetExcluded` で IP プールから除外した
- [ ] daemon の `dataplane/reconciler/subnet.go` で BPF `arp_table` に新サービスの ARP エントリを書く
- [ ] `Registry.RegisterUDPHandler` または `Registry.ListenTCP` を呼ぶ Subnet 駆動 reconciler を実装した
- [ ] サービス固有の ServiceID を `virtservice/types.go` に追加した (DNS=1 と衝突しない番号)
- [ ] app.go で起動・停止フックを追加した
- [ ] svcpolicy に新ポリシーを追加した (BPF レイヤと L7 レイヤで判定が共有される必要があれば)
- [ ] 必要なら Pod webhook で設定注入を実装した
- [ ] L7 ハンドラに単体テストを書いた
- [ ] e2e テストに最低 1 シナリオ追加した (resolve / connect が成功するハッピーパス)
- [ ] `make daemon-generate-bpf` と `make controller-manifests controller-generate` で生成物を更新した
