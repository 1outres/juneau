# Phase 4b: NATGateway / eBPF NAPT / hostGateway 撤去

NATGateway リソースの一般機能化、eBPF 内 N:1 NAPT 実装、cni_host / iptables MASQUERADE の完全撤去を行うフェーズの実装計画。本ドキュメントは新規セッションで引き継げる self-contained な仕様書として書かれており、実装はここに記載されている内容で完結する。

## 前提

以下の前提フェーズは完了済み:

- **Phase 4b-0**: AllocationPool / AllocationClaim を IP 型に拡張、AddressPool / ElasticIP を AllocationClaim 経由に移植、IPLease を廃止し NetworkInterface に AllocationClaim を統合。詳細は `phase4b-allocationpool.md`
- **Phase 4b-0.5**: `Subnet.spec.routeTable` 追加 (Subnet 単位 RouteTable)。詳細はコミット `feat(controller): allow Subnet to override its RouteTable`

## 設計の確定事項

### NATGateway リソース

cluster-scoped CRD。VPC 単位の概念で、Subnet スコープにはしない (NAPT 経路の戻り情報に Subnet 情報を要さないため)。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: NATGateway
metadata:
  name: nat-prod
spec:
  vpc: default
  externalNetwork: foo
status:
  gatewayID: 1234         # uint32, AllocationPool から確保
  conditions:
    - type: Ready
      status: "True"
```

「どの Subnet から使うか」は RouteTable 側に `0.0.0.0/0 via natGateway: <name>` を書くか否かで表現する。

### IP 確保戦略

- per-(ExternalNetwork, Node) で 1 IP を確保する (NATGateway 単位ではない)
- AllocationClaim パターン (Phase 4b-0 で整備済み) で取得
- 同じ ExternalNetwork を複数 NATGateway が参照する場合、IP は共有 (各ノード上で port 空間で区別)
- 異なる ExternalNetwork を参照すれば IP は別 (テナント分離)
- 結果として IP 消費は `ノード数 × ExternalNetwork 数` (NATGW 数に依らない)
- Attachment 作成トリガー: NATGateway が ExternalNetwork を参照したら、ExternalNetwork reconciler が全 Node × ExternalNetwork で `ExternalNetworkAttachment` を自動生成 (preallocate)
- OwnerRef は **ExternalNetwork に張る** (個別 NATGW ではない)。これにより複数 NATGW で共有される ExternalNetwork において、片方の NATGW を削除してもその IP / Attachment は失われない。Attachment / 配下の AllocationClaim / BGPAdvertisement が GC されるのは ExternalNetwork 自体が削除されたタイミングのみ
- ElasticIP との IP 排他: 同じ AddressPool を ExternalNetwork (NATGW 経由) と ElasticIP の両方が参照しても、AddressPool 1:1 対応の `addr-<name>` AllocationPool により AllocationClaim 機構で IP の二重確保は防がれる

### per-node /32 BGP 広告

各ノードは自分用の `host_napt_ip` を `/32` で BGP 広告する。上流ルータは正解ノードへ deterministic にルーティングするため、戻りパケットは常に owner ノードに直接届く。

実現方法: `BGPAdvertisement` に以下のオプションフィールドを追加 (Phase 4b-1.5):

- `spec.nodeName` (optional, string): 指定時はそのノードの bgp-speaker のみが advertise を発出
- `spec.prefix` (optional, CIDR string): 指定時は AddressPool の全 CIDR ではなく当該 prefix だけを広告

`ExternalNetworkAttachment` 1 つにつき OwnerRef 付き BGPAdvertisement (両フィールド指定) を 1 つ併設する。

ノード障害時: bgp-speaker 停止 → bird セッション切断 → 上流から /32 が消える。当該 IP の owner ノードが死んでいるため、その IP に向かう既存セッションは切断される。pod は別ノードへ rescheduled され、移動先ノードの `host_napt_ip` で新規セッションが張られる。AWS NAT Gateway の AZ 障害時と同等の挙動として受け入れる。

### NAT マップの 2 層分離 (Rule / State)

NAT 系のデータパスを以下の 2 層に分離する。実装の追加・変更時にもこの境界を尊重する。

| 層 | 役割 | 性質 | マップ |
|---|---|---|---|
| Rule | 「このパケットにはこの変換を適用せよ」 | 制御面が書く、低カーディナリティ、種別ごとに分離 | `service_map` + `backend_map`, `napt_src`, `nat_dnat_map`, `nat_snat_map` |
| State | 「このアクティブフローにはこの変換が記録済み」 | データ面が書く、高カーディナリティ、GC 必要、1:N 種別が共有 | `ct_map` |

ElasticIP (1:1 NAT) は Rule 層で完結する (state 不要なため `nat_dnat_map` / `nat_snat_map` は ct_map に統合しない)。Service と NAPT (どちらも 1:N の stateful NAT) は Rule + State の 2 層構成、State 層は ct_map を共有する。

### ct_map スキーマ

State 層の中核となる conntrack マップ。

```c
struct ct_key {
  __u32 scope;       // CT_SCOPE_HOST = 0 (host-facing keyspace) / 非 0 = vpc_id
  __u32 saddr;
  __u32 daddr;
  __u16 sport;
  __u16 dport;
  __u8 proto;
  __u8 _pad[3];
};

struct ct_val {
  __u32 new_saddr, new_daddr;
  __u16 new_sport, new_dport;
  __u32 next_subnet_id;   // 書換後の fdb 配送用 VNI
                          //   Service forward: backend の VNI
                          //   NAPT reverse:    pod の VNI
  __u8 action;            // CT_ACTION_DNAT | _SNAT | _NAPT_OUT | _NAPT_IN
  __u8 state;             // CT_STATE_NEW | _ESTABLISHED | _FIN_WAIT | _CLOSED
  __u8 flags_seen;        // OR-累積された TCP flags
  __u8 _pad;
  __u64 last_seen_ns;
};
```

- マップ型: `BPF_MAP_TYPE_HASH` (LRU ではない)
- `MAX_CT_MAP = 524288`
- scope の使い分け:

| scope | 用途 |
|---|---|
| `CT_SCOPE_HOST = 0` | NAPT reverse (戻りパケット、underlay 視点で keying) |
| 非 0 (vpc_id) | Service DNAT/SNAT (caller の VPC), NAPT forward (pod の VPC) |

- forward 系の keyspace 衝突: NAPT_OUT は `daddr = internet IP`、Service DNAT は `daddr = ClusterIP` (cluster service CIDR 内) で値域が排他的なので衝突しない
- `daemon/bpf/ct.h:ct_build_opposite_key` を NAPT_OUT/NAPT_IN ペア対応に拡張 (CLOSED 状態での双方向エントリ削除を維持)

### conntrack GC の idle timeout

`BPF_MAP_TYPE_HASH` 化により LRU eviction がなくなるため、idle timeout ベースの GC が必須。

| プロトコル | state | timeout |
|---|---|---|
| TCP | NEW | 120 秒 |
| TCP | ESTABLISHED | 1 時間 |
| TCP | FIN_WAIT | 60 秒 |
| TCP | CLOSED | (即削除、`ct_observe_tcp` 内で対処) |
| UDP | (state なし) | 60 秒 |
| ICMP | (state なし) | 30 秒 |

`last_seen_ns` ベースで判定、定期的に走査して削除する。

### NAPT データパス

#### Forward (pod → internet, `pod_egress.c`)

`handle_l3()` で `FIB_ROUTE_TYPE_NAPT` 分岐を追加:

1. `fib_val.subnet_id` (= NATGWID, NAPT 型のみ overload) を取得
2. `napt_src[NATGWID]` で自ノードの `host_napt_ip` を引く
3. `ct_map` lookup (key=(scope=vpc_id, pod, internet, sp, dp, proto)) で既存エントリがあれば再利用
4. なければポートを線形プローブで確保 (アトミックに):
   - 5-tuple をハッシュして候補ポートを生成
   - `ct_map` reverse key (`scope=HOST, internet, host_napt_ip, dp, candidate_port, proto`) への install を `bpf_map_update_elem(BPF_NOEXIST)` で試行
   - 失敗 (= 既存エントリと衝突) したら候補を +1 して再試行 (最大 8 回、限界に達したら drop)
   - `BPF_NOEXIST` を使うことで複数 CPU が同じ tuple を並行処理しても read-modify-write の race を排除する
5. forward 側の `ct_map` エントリも install:
   - reverse install 成功後、forward: `scope=vpc_id`, key=(pod, internet, sp, dp, proto), `action=NAPT_OUT`, `new_saddr=host_napt_ip`, `new_sport=alloc_port` を install
   - 確保済み reverse の値: `scope=HOST`, key=(internet, host_napt_ip, dp, alloc_port, proto), `action=NAPT_IN`, `new_daddr=pod`, `new_dport=sp`, `next_subnet_id=pod の VNI`
6. パケットの src_ip / src_port を rewrite (`nat.h` ヘルパー流用)
7. `bpf_fib_lookup` で next-hop 解決 → underlay iface へ送出 (既存 `handle_snat` と同形)

#### Reverse (internet → pod, `node_ingress.c`)

`handle_l3()` で:

1. `bgp_address_pools` 引き (既存) — pool 内の IP かどうかゲート
2. `ct_map` 引き (key=(scope=CT_SCOPE_HOST, internet_src, host_napt_ip, sport, alloc_port, proto)) — ヒットすれば NAPT 戻り:
   - `new_daddr` / `new_dport` で書換
   - `next_subnet_id` をキーに `subnet_map` / `arp_table` 引いて pod の MAC を解決
   - fdb 経由で pod の veth へ配送 (既存 `handle_dnat` と同形)
3. `ct_map` miss なら `nat_dnat_map` (ElasticIP 1:1 NAT) にフォールスルー (既存パス)

### NATGateway / ExternalNetwork 削除時の挙動

#### NATGateway 削除

NATGW 自体は IP / Attachment を保有しない (それらは ExternalNetwork 配下の preallocated リソース)。NATGW 削除時に行うのは以下のみ:

- daemon: 自ノードの `napt_src[NATGWID]` エントリ削除 (NATGateway watch)

`ExternalNetworkAttachment` / `BGPAdvertisement` / `AllocationClaim` は ExternalNetwork が owner であり残存する。同 ExternalNetwork を参照する別 NATGW があれば IP は引き続き有効。

`ct_map` のエントリは能動的に cleanup しない (NATGWID から ct_map エントリへの逆引きを持たない)。当該 NATGW を経由していた既存 active flow は次パケットで `napt_src` miss → drop、または GC の idle timeout で自然消滅。NATGW 削除で既存 TCP セッションが切断されることを許容する。

#### ExternalNetwork 削除

ExternalNetwork webhook は「自身を参照する NATGateway / ElasticIP が存在する間は削除拒否」とする。全ての参照が消えてから ExternalNetwork を削除すると、OwnerRef 連鎖で以下が GC される:

- `ExternalNetworkAttachment` (全 Node × 当該 ExternalNetwork)
- 各 Attachment が併設していた `BGPAdvertisement` (per-node /32)
- 各 Attachment が発行していた `AllocationClaim` (host_napt_ip)

daemon は Attachment 削除を watch して `bgp_address_pools` から当該 /32 を削除する。

### juneau_node iface

default VPC/Subnet からの host stack 通信 (kubelet probe、host CoreDNS 等) のために、各ノードに「pseudo-pod」として振る舞う veth ペアを 1 個用意する。

- default Subnet の CIDR から各ノード用に 1 個ずつ予約 IP を確保 (AllocationClaim パターン)
- 既存 `cni_host` veth ペアの仕組みを継承し、`juneau_node` 命名にリネーム
- iptables MASQUERADE と関連 sysctl は撤去 (Phase 4b-5)
- BPF attach (TCX):
  - **ingress** に `pod_egress.c` (kernel-stack 側 = "pseudo-pod" から出ていくパケット)
  - **egress** に `pod_ingress.c` (kernel-stack 側に届くパケット)
- daemon が `ifindex_subnet[juneau_node の ifindex] = default Subnet の VNI` を登録
- daemon が「自ノードの予約 IP」を `arp_table` (subnet_id=default, ipaddr=予約IP, mac=`juneau_node` の host 側 MAC) と `fdb` (subnet_id=default, mac=同 MAC, ifindex=`juneau_node`, vtep_ip=自ノードの underlay IP) に登録
- host netns に `ip route add <default_subnet_CIDR> dev juneau_node` を投入 (probe 経路)
- 非 default Subnet では `juneau_node` iface を作らない

### host stack 通信のサポート範囲

`juneau_node` iface 経由の host → pod 到達は **default VPC/Subnet 限定**でサポートする。VPC 跨ぎで pod IP が重複しうる以上、kubelet が host netns から `pod_ip:port` に直接接続する probe は OS レベルで構造的に解決不可能 (kubelet に VPC 概念が無く、host stack のルーティングテーブルは 1 つしか持てない)。

非 default VPC の pod に対しては:

- `exec` probe (pod の netns 内で実行されるため host stack を経由しない) を使う、または
- `livenessProbe` / `readinessProbe` を無効化する

### IPv4 only

Phase 4b は IPv4 専用 (`ct_key.saddr/daddr` が `__u32`)。IPv6 対応は将来 Phase で `ct_key v2` を切る (本 Phase の対象外)。

## マップ / 構造体リファレンス

### ct_map (Phase 4b-3 で改訂)

State 層、Service と NAPT が共有する conntrack マップ。詳細は「設計の確定事項 / ct_map スキーマ」参照。

### napt_src (新設、Phase 4b-3)

NAPT forward 用の rule 層マップ。

```c
struct napt_src_key {
  __u32 nat_gateway_id;
};

struct napt_src_val {
  __u32 host_ip;     // network byte order
};
```

- `BPF_MAP_TYPE_HASH`、max_entries は適当な値 (例: 4096)
- pod_egress が NATGWID から自ノードの host_napt_ip を引く
- 各ノードの daemon が自ノード分の `ExternalNetworkAttachment.status.assignedIP` を見て登録

### bgp_address_pools (既存マップ、Phase 4b-2 で利用拡大)

LPM trie。AddressPool の全 CIDR が登録されているのに加え、各ノードが自分の `host_napt_ip` を /32 でも登録する。

- 用途: `node_ingress.c` が「戻りパケットの daddr が pool 内 IP か」のゲート判定に使用
- 4b-2 で daemon が `ExternalNetworkAttachment.status.assignedIP` を /32 として登録するロジックを追加

### fib_val (`maps.h`、Phase 4b-1 で意味拡張)

```c
struct fib_val {
  __u8 type;
  __u8 dmac[6];
  __u8 smac[6];
  __u32 subnet_id;
  __u32 oif;
};
```

`FIB_ROUTE_TYPE_NAPT` 時の解釈:

- `type = FIB_ROUTE_TYPE_NAPT`
- `subnet_id` フィールドを **NATGWID として overload** (この型のときのみ)
- dmac / smac / oif は使わない (kernel FIB lookup で解決)

他の型は既存と同じ (subnet_id は subnet の VNI として解釈)。

### nat_dnat_map / nat_snat_map (既存、ElasticIP 用)

ElasticIP 1:1 NAT の rule 層マップ。Phase 4b で構造変更なし。

`ct_map` に統合しない理由: 1:1 NAT は変換が決定的 (eip ↔ pod_ip) で state 不要。state 層に押し込むと per-flow メモリオーバヘッドと GC コストが発生するだけで利得がない。

## 段階分け

各段階で `make test` / `make manifests` / `make generate` / `make generate-bpf` がクリーンに通り、`E2E_KEEP_CLUSTER=true make e2e` の既存テストを維持してから次へ進む。

### Phase 4b-1: NATGateway CRD と RouteViaType=natGateway

NATGateway リソースの基盤と、RouteTable から NATGateway を参照する経路を確立する。

**新規ファイル**:

- `controller/api/v1alpha1/natgateway_types.go`
- `controller/internal/controller/natgateway_controller.go`
- `controller/internal/webhook/v1alpha1/natgateway_webhook.go`

**修正ファイル**:

- `controller/api/v1alpha1/routetable_types.go` — `RouteViaType` enum に `natGateway` を追加、`RouteVia.NATGateway` (string, JSON タグ `natGateway`) を per-type フィールドとして追加 (既存 `Endpoint`/`endpointName` と並列)。Discriminated union 風で type ごとに有効フィールドが切り替わる設計
- `controller/internal/webhook/v1alpha1/routetable_webhook.go` — `case ViaNATGateway` を追加 (`via.natGateway` 必須チェック)
- `controller/internal/controller/routetable_controller.go` — `via natGateway` のレコード解決
- `controller/internal/controller/bootstrap/defaults.go` (or 同等) — NATGWID 用 AllocationPool `nat-gateway-id` (`number` 型) を bootstrap で作成
- `daemon/internal/daemon/dataplane/reconciler/fib.go` — `buildNATGatewayFibVal()` を追加、`subnet_id` に NATGWID を埋める
- `daemon/bpf/maps.h` — `FIB_ROUTE_TYPE_NAPT = 6` 定義追加

**要点**:

- NATGateway は cluster-scoped、spec=`(vpc, externalNetwork)`
- `status.gatewayID` を NATGWID 用 AllocationPool から確保 (`RouteTable.tableID` と同じ `ensureNumberClaim` パターン)
- NATGateway webhook:
  - `ValidateCreate/Update`: 参照先 Vpc / ExternalNetwork が存在、参照先 `ExternalNetwork.spec.type` は `bgp` 必須 (`arp` は拒否)
  - `ValidateDelete`: `via.type == natGateway && via.natGateway == this.name` の `RouteTable.spec.routes` が存在するなら削除拒否
- RouteTable webhook: `via.type == natGateway` のとき `via.natGateway` フィールド必須、それ以外の type で `via.natGateway` が指定されていれば拒否

**e2e**:

- NATGateway 作成 → `status.gatewayID` が割り当たる、Ready=True
- RouteTable に `0.0.0.0/0 via natGateway: <name>` を書ける
- NATGateway 削除しようとすると、参照中の RouteTable があれば webhook で拒否

### Phase 4b-1.5: BGPAdvertisement の per-node /32 拡張

per-node /32 advertise の器を整える。Phase 4b-2 でこの仕組みを使う。

**修正ファイル**:

- `controller/api/v1alpha1/bgpadvertisement_types.go` — `spec.nodeName` (optional, string), `spec.prefix` (optional, CIDR string) を追加
- `controller/internal/webhook/v1alpha1/bgpadvertisement_webhook.go` — `prefix` 指定時は AddressPool のいずれかの CIDR に包含されることを検証
- `bgp-speaker/internal/speaker/reconcile.go`:
  - `buildPrefixes` を `nodeName` フィルタ + `prefix` override 対応に拡張
  - `buildAdvertisementsIntent` も同様 (BGPNodeState への projection で per-node /32 を可視化)
  - `nodeName` / `prefix` 未指定時の挙動は既存の AddressPool-wide flat advertisement のまま (後方互換)

**要点**:

- `nodeName` 指定時は当該ノードの bgp-speaker のみが advertise を発出
- `prefix` 指定時は当該 prefix だけを広告 (AddressPool 名は依然として参照妥当性検査と pool 整合に使う)
- `nodeName` のバリデーションは省略 (typo は実害なく無視されるだけ)

**e2e**:

- 単一の BGPAdvertisement (`nodeName=node-1, prefix=192.0.2.5/32`) を投入 → node-1 のみが /32 を bird から advertise すること (他ノードは pool 全 CIDR のみ)
- `nodeName` / `prefix` 未指定の既存 BGPAdvertisement は従来通り全ノードから AddressPool 全 CIDR を発出

### Phase 4b-2: per-Node ExternalNetwork IP 確保

`ExternalNetworkAttachment` CRD と reconciler を実装し、各ノードに NATGW 用 IP を割り当てて per-node /32 advertise を仕込む。

**新規ファイル**:

- `controller/api/v1alpha1/externalnetworkattachment_types.go`
- `controller/internal/controller/externalnetworkattachment_controller.go`
- `controller/internal/webhook/v1alpha1/externalnetworkattachment_webhook.go`
- `daemon/internal/daemon/dataplane/reconciler/napt.go` (or 同等) — `napt_src` / `bgp_address_pools` /32 書込み

**修正ファイル**:

- `controller/internal/controller/externalnetwork_controller.go` — それを参照する NATGateway が存在するとき、全 Node × ExternalNetwork で Attachment を **ExternalNetwork を OwnerRef とした上で** 自動生成 (preallocate)。NATGateway 削除では消えず、ExternalNetwork 削除時にのみ GC される
- `daemon/internal/daemon/dataplane/manager.go` — NAPT reconciler を起動

**`ExternalNetworkAttachment` スキーマ**:

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetworkAttachment
spec:
  externalNetwork: foo
  nodeName: node-1
status:
  assignedIP: 192.0.2.5
  conditions:
    - type: Ready
      status: "True"
```

**要点**:

- Attachment の OwnerRef は ExternalNetwork に張る (前述「設計の確定事項 / IP 確保戦略」参照)
- Attachment reconciler が `AllocationClaim` を発行 (Phase 4b-0 で整備済み、`AddressPoolAllocationPoolName(addressPool.Name)` を pool ref に)。AllocationClaim の OwnerRef は Attachment に張り、Attachment 削除で連鎖 GC させる
- Attachment reconciler が `status.assignedIP` 取得後、per-node `BGPAdvertisement` (`spec.nodeName=spec.nodeName`, `spec.prefix=<assignedIP>/32`) を Attachment OwnerRef 付きで併設
- Attachment webhook: `spec.externalNetwork`, `spec.nodeName` を immutable に。`spec.externalNetwork` が指す ExternalNetwork の `spec.type` は `bgp` 必須 (`arp` は拒否、保険として NATGW webhook と二重に防ぐ)
- daemon の NAPT reconciler は自ノードの Attachment を watch:
  - `status.assignedIP` を取得 → `napt_src[NATGWID]` に書込み (NATGWID は Attachment が間接参照する NATGateway の `status.gatewayID` から)
  - 同 IP を `bgp_address_pools` に /32 で登録 (戻りパケット judgment 用)

**e2e**:

- NATGateway を ExternalNetwork 経由で参照 → 全ノードで Attachment が作成され IP が確保される
- 各ノードが自分の IP を /32 で advertise、他ノードからは advertise されない
- NATGateway を削除すると Attachment / BGPAdvertisement / AllocationClaim が GC される

### Phase 4b-3: ct_map リファクタ + eBPF NAPT 実装

ct_map の field 改名 + 容量・型変更と、NAPT 機能を一気に実装する。

**修正ファイル (BPF)**:

- `daemon/bpf/maps.h`:
  - `BPF_MAP_TYPE_LRU_HASH` → `BPF_MAP_TYPE_HASH`、`MAX_CT_MAP` 131072 → 524288 (~32MB/ノード)
  - `ct_key.vpc_id` → `ct_key.scope`、`#define CT_SCOPE_HOST 0` を追加
  - `ct_val.backend_subnet_id` → `ct_val.next_subnet_id`
  - `CT_ACTION_NAPT_OUT`, `CT_ACTION_NAPT_IN` を追加
  - `napt_src` map を新設

**永続化境界**: ct_map は `LIBBPF_PIN_BY_NAME` で pinned だが、daemon は起動時に `manager.go:Start()` で `os.RemoveAll(pinPath)` を実行するため、再起動で旧フォーマットの残骸は wipe される (本 Phase は開発段階扱い、再起動で治る破壊的変更を許容)。
- `daemon/bpf/ct.h`:
  - `ct_build_opposite_key` を NAPT_OUT/NAPT_IN ペア対応に拡張
- `daemon/bpf/pod_egress.c`:
  - `handle_l3()` に `FIB_ROUTE_TYPE_NAPT` 分岐を追加 (forward NAPT 実装)
  - 既存 Service コードの `vpc_id` 参照を `scope` に機械的書換
  - `backend_subnet_id` 参照を `next_subnet_id` に機械的書換
- `daemon/bpf/node_ingress.c`:
  - `handle_l3()` に NAPT reverse 分岐を追加 (`ct_map` (scope=HOST) lookup → 書換 → fdb 配送)
  - 既存 ElasticIP パス (`nat_dnat_map`) は `ct_map` miss 時のフォールスルーとして残す
- `daemon/bpf/pod_ingress.c` / `daemon/bpf/vxlan_ingress.c`:
  - `vpc_id` → `scope` の機械的書換 (semantic 変更なし)

**修正ファイル (Go)**:

- `daemon/internal/daemon/dataplane/reconciler/conntrack_gc.go` (or 同等):
  - HASH 化により LRU eviction がなくなる前提で、idle timeout ベース GC を追加
  - timeout 値: TCP NEW=120s, TCP ESTABLISHED=1h, TCP FIN_WAIT=60s, UDP=60s, ICMP=30s
- `daemon/internal/daemon/dataplane/reconciler/service.go` (or 該当箇所) — 既存 Service コードの field 名追従 (`backend_subnet_id` → `next_subnet_id` など)
- `daemon/internal/daemon/bpf/gen.go` — bpf2go 再生成

**要点**:

- ポート確保ロジックは `pod_egress.c` 内で線形プローブ (5-tuple ハッシュベースの初期候補、`bpf_map_update_elem(BPF_NOEXIST)` で reverse key install を試行してアトミックに衝突回避、最大 8 回試行で失敗時は drop)
- `#pragma unroll` でループ展開し、verifier の instruction count / stack 上限内に収める
- 既存 Service flow は `scope=vpc_id` でそのまま動く (semantic 変更なし、フィールド名書換のみ)
- cilium の `bpf_lxc.c:snat_v4_track_local` が参考になる

**e2e**:

- NATGateway 経由で外部疎通できる (curl から外部 HTTP)
- 1000 並列 curl で port 衝突しない
- TCP セッション FIN で `ct_map` エントリが GC される
- UDP / ICMP の idle timeout 後 `ct_map` エントリが GC される
- HASH 化前後で Service flows が回帰なく動く
- 既存 ElasticIP の 1:1 NAT が引き続き動く

### Phase 4b-4: juneau_node iface 化と host pseudo-pod IP

cni_host を eBPF data plane に組み込んで `juneau_node` にリネームし、各ノードに pseudo-pod IP を割り当てる。

**修正ファイル (bootstrap)**:

- `daemon/internal/daemon/bootstrap/hostiface.go`:
  - `SetupDefaultGatewayIface` 相当を `juneau_node` 命名に書換、予約 IP の解決ロジック (Subnet CRD 参照ではなく AllocationClaim 経由) に変更
- `daemon/internal/daemon/bootstrap/sysctl.go`:
  - `cni_host` 関連 sysctl を `juneau_node` 側のパスへ書き換え
- `daemon/internal/daemon/app.go`:
  - bootstrap 呼び出しの整理

**修正ファイル (controller)**:

- `controller/internal/controller/bootstrap/defaults.go` — default Subnet 用予約 IP の AllocationPool を bootstrap (`subnet-ip-default` 等の既存パターンを再利用)
- `controller/internal/controller/node_controller.go` (or 同等) — Node × default Subnet の AllocationClaim を発行する reconciler ロジック

**修正ファイル (BPF attach)**:

- `daemon/internal/daemon/dataplane/manager.go` — `juneau_node` iface に対する `pod_egress` / `pod_ingress` の attach を追加 (TCX ingress / egress)
- `daemon/internal/daemon/dataplane/reconciler/junode.go` (or 同等) — 自ノードの予約 IP を `arp_table` / `fdb` / `ifindex_subnet` に登録する reconciler

**要点**:

- iptables MASQUERADE と関連 sysctl の残骸は次の Phase 4b-5 で完全撤去
- 各ノードの予約 IP は default Subnet CIDR の中から AllocationClaim で取得
- host netns に `ip route add <default_subnet_CIDR> dev juneau_node` を投入して probe 経路を確保
- 他ノードから当該 IP に到達したい場合は VXLAN encap で送られる (subnet_id=default の VNI、fdb で `juneau_node` の MAC → 該当 vtep_ip)

**e2e**:

- kubelet readiness/liveness probe が動く (default Subnet pod 限定)
- CoreDNS の host からのアクセスが動く
- 既存 e2e が回帰なし

### Phase 4b-5: hostGateway 撤去と default VPC auto-inject 切替

最終形に向けて残骸を撤去する。

**default VPC の auto-inject 切替**:

- `controller/internal/controller/routetable_controller.go` の default VPC main RT への `0.0.0.0/0 via hostGateway` 自動投入を `0.0.0.0/0 via natGateway: <default-natgw>` に切替
- bootstrap で default ExternalNetwork (type=bgp) と default 用 NATGateway リソースを auto-create (NATGW が default ExternalNetwork を参照する形)

**削除対象 (BPF)**:

- `daemon/bpf/host_egress.c` (ファイル削除)
- `daemon/bpf/host_egress.c.md` (ファイル削除)
- `daemon/bpf/maps.h` の `host_iface_val`, `host_iface` map 定義
- `daemon/bpf/maps.h` の `#define FIB_ROUTE_TYPE_HOST_GATEWAY 5`
- `daemon/bpf/pod_egress.c` の `FIB_ROUTE_TYPE_HOST_GATEWAY` 分岐
- `daemon/bpf/pod_egress.c.md` の関連項目

**削除対象 (Go loader / Manager)**:

- `daemon/internal/daemon/dataplane/program/host_egress.go` (ファイル削除)
- `daemon/internal/daemon/bpf/gen.go` の bpf2go 定義から HostEgress を削除
- `daemon/internal/daemon/dataplane/manager.go` の `hostEgress` フィールド + 初期化 + 各 reconciler への注入を削除
- 各 reconciler (`arp.go`, `fdb.go`, `subnet.go`) の `hostEgress.Objs.*` 参照を `podEgress.Objs.*` に置換 (`arp_table` / `fdb` / `subnet_map` は `LIBBPF_PIN_BY_NAME` で全 BPF 間共有)

**削除対象 (bootstrap)**:

- `daemon/internal/daemon/bootstrap/iptables.go` (ファイル削除)
- `daemon/internal/daemon/bootstrap/sysctl.go` の `cni_host` sysctl 関連行
- `daemon/internal/daemon/app.go` の `EnsureMasqueradeRule` 呼び出しを削除
- `daemon/internal/daemon/app.go` の `--masquerade-iface` flag を削除

**削除対象 (controller / CRD)**:

- `controller/api/v1alpha1/routetable_types.go` の `ViaHostGateway` 定数 + コメント
- 同上 kubebuilder enum から `hostGateway` を外す
- `controller/internal/controller/routetable_controller.go` の `via hostGateway` 自動投入 + skip 処理を削除
- `controller/internal/webhook/v1alpha1/routetable_webhook.go` の `case ViaHostGateway` を削除
- `daemon/internal/daemon/dataplane/reconciler/fib.go` の `fibRouteTypeHostGateway`, `buildHostGatewayFibVal()`, switch case を削除

**削除対象 (docs)**:

- `docs/resources/routetable.md` から `hostGateway` の説明
- `docs/CLAUDE.md` のスタイルガイドに kube-proxy / iptables 依存撤廃を反映

**要点**:

- 開発中段階のため、ノード上に残った旧 iptables MASQUERADE rule の自動 cleanup は行わない (daemon 再起動 → 新ルール適用、旧ルールは手動で消すかノード再構築)
- 撤去後、host_egress.c 関連シンボルが完全に消えていることを `nm` / `bpftool prog list` 等で確認

**e2e**:

- ノードに `host_egress` 関連の BPF プログラムが残っていない (`bpftool prog list`)
- 既存 e2e すべて維持

## 関連ファイル一覧

実装着手時の touch list (一望)。

### controller/api/v1alpha1/

- 新規: `natgateway_types.go` (4b-1)
- 新規: `externalnetworkattachment_types.go` (4b-2)
- 修正: `routetable_types.go` — `natGateway` enum 追加 + `RouteVia.NATGateway` (4b-1)、`hostGateway` 削除 (4b-5)
- 修正: `bgpadvertisement_types.go` — `spec.nodeName`, `spec.prefix` 追加 (4b-1.5)

### controller/internal/controller/

- 新規: `natgateway_controller.go` (4b-1)
- 新規: `externalnetworkattachment_controller.go` (4b-2)
- 修正: `externalnetwork_controller.go` — Attachment ファンアウト追加 (4b-2)
- 修正: `routetable_controller.go` — `via natGateway` 解決追加 (4b-1)、default VPC への `via hostGateway` 自動投入を `via natGateway` 自動投入に変更 (4b-5)
- 修正: `node_controller.go` (or 同等) — default Subnet 予約 IP の per-Node Claim 発行 (4b-4)
- 修正: `bootstrap/defaults.go` — NATGWID 用 AllocationPool `nat-gateway-id` (4b-1)、default Subnet 予約 IP 用 AllocationPool (4b-4)、default ExternalNetwork + default NATGateway auto-create (4b-5)

### controller/internal/webhook/v1alpha1/

- 新規: `natgateway_webhook.go` (4b-1)
- 新規: `externalnetworkattachment_webhook.go` (4b-2)
- 修正: `routetable_webhook.go` — `case ViaNATGateway` 追加 (4b-1)、`case ViaHostGateway` 削除 (4b-5)
- 修正: `bgpadvertisement_webhook.go` — `prefix` 包含検証 (4b-1.5)

### bgp-speaker/internal/speaker/

- 修正: `reconcile.go` — `nodeName` フィルタ + `prefix` override (4b-1.5)

### daemon/bpf/

- 修正: `maps.h` — `FIB_ROUTE_TYPE_NAPT` 追加 (4b-1)、`napt_src` map 新設・ct_map リファクタ (4b-3)、`host_iface` 系削除 + `FIB_ROUTE_TYPE_HOST_GATEWAY` 削除 (4b-5)
- 修正: `ct.h` — `ct_build_opposite_key` 拡張 (4b-3)
- 修正: `pod_egress.c` — `FIB_ROUTE_TYPE_NAPT` 分岐追加 (4b-3)、`vpc_id` → `scope` / `backend_subnet_id` → `next_subnet_id` 機械書換 (4b-3)、`FIB_ROUTE_TYPE_HOST_GATEWAY` 分岐削除 (4b-5)
- 修正: `node_ingress.c` — NAPT reverse 分岐追加 (4b-3)
- 修正: `pod_ingress.c`, `vxlan_ingress.c` — `vpc_id` → `scope` 機械書換 (4b-3)
- 削除: `host_egress.c`, `host_egress.c.md` (4b-5)

### daemon/internal/daemon/

- 修正: `bpf/gen.go` — bpf2go 再生成 (4b-3, 4b-5)
- 修正: `bootstrap/hostiface.go` — `juneau_node` iface 化 (4b-4)
- 修正: `bootstrap/sysctl.go` — sysctl パス更新 (4b-4)、不要部削除 (4b-5)
- 削除: `bootstrap/iptables.go` (4b-5)
- 修正: `dataplane/manager.go` — NAPT reconciler 起動 (4b-2)、`juneau_node` iface への attach 追加 (4b-4)、hostEgress 撤去 (4b-5)
- 削除: `dataplane/program/host_egress.go` (4b-5)
- 修正: `dataplane/reconciler/arp.go`, `fdb.go`, `subnet.go` — hostEgress 参照を podEgress に置換 (4b-5)
- 新規: `dataplane/reconciler/napt.go` (or 同等) — `napt_src` / `bgp_address_pools` /32 書込み (4b-2)
- 新規: `dataplane/reconciler/junode.go` (or 同等) — `juneau_node` iface の arp_table / fdb / ifindex_subnet 登録 (4b-4)
- 修正: `dataplane/reconciler/fib.go` — `buildNATGatewayFibVal` 追加 (4b-1)、`buildHostGatewayFibVal` 削除 (4b-5)
- 修正: `dataplane/reconciler/conntrack_gc.go` (or 同等) — idle timeout ベース GC 追加 (4b-3)
- 修正: `app.go` — bootstrap 呼び出し整理 (4b-4, 4b-5)、`--masquerade-iface` flag 削除 (4b-5)

### docs/

- 修正: `docs/resources/routetable.md` — `hostGateway` 説明削除、`natGateway` 追記 (4b-5)
- 修正: `docs/CLAUDE.md` — kube-proxy / iptables 依存撤廃の反映 (4b-5)
- 新規: `docs/resources/natgateway.md`, `docs/resources/externalnetworkattachment.md` (実装と並行)

## 検証

各段階で以下を満たすこと:

- `make test` (controller 単体テスト) が通る
- `make manifests` / `make generate` / `make generate-bpf` がクリーン (差分なし)
- `E2E_KEEP_CLUSTER=true make e2e` で既存テスト維持 (Phase 4b-0.5 までで 20/20、bringup smoke を含めて 21)
- 段階固有の e2e は各段階セクション参照

## 残された論点 (実装中・実装後の確認事項)

### conntrack のスケール監視

- 1 ノードあたり想定 1000 active connection × 数十ノードクラスタで `MAX_CT_MAP=524288` に余裕あり
- 実運用負荷で `ct_map` の使用率を bpftool 等でモニタ、必要なら max_entries の見直し

### NATGateway を default VPC 以外で使うときの UX

- ユーザーは NATGateway を作って ExternalNetwork を参照、その後 RouteTable に `0.0.0.0/0 via natGateway: <name>` を書く (default VPC は controller が auto-inject)
- 「private subnet を作りたい」場合は NATGW を参照しない alt RouteTable を作って `Subnet.spec.routeTable` で指定

### 将来の拡張余地 (本 Phase の対象外)

- per-pod IP-per-flow の NATGW (現在は per-node IP)
- NAPT の hairpin support
- IPv6 NAT (`ct_key v2`)

## 開発スタイル

`CLAUDE.md` に従う:

- TDD (探索 → Red → Green → Refactoring)
- e2e は `E2E_KEEP_CLUSTER=true make e2e`
- 各段階で既存テストを維持してから次段階へ
- 不明瞭な指示は質問して明確にする
- 「エラーが出たときに fallback」のような実装は避け、やむを得ないときは許可を取る
