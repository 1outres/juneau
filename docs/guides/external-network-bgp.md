# BGPを使ってExternalNetworkを構築する

Juneauでは、Podに外部到達可能なIPアドレス（ElasticIP）を割り当て、その経路をBGPで上流ルータに広報することで、クラスター外部からPodへの直接疎通を実現できます。このガイドはその一連のリソースをゼロから組み立てる手順を示します。

## このガイドで構築するもの

- 外部へ広報するアドレス範囲 `10.225.51.0/24` を持つAddressPool
- 外部ルータ (AS 65002, `10.225.32.1`) とのBGPピアリング
- EIP対象Pod用の専用Vpc/Subnet (`10.60.0.0/24`) とInternetGateway経路
- ElasticIPをnginx Podに割り当て、クラスター外から `curl http://<elasticIP>/` で到達確認

## 前提条件

- Juneauのcontroller/daemon/bgp-speakerが動作しているクラスター
- クラスターのAS番号（本ガイドでは **65001**）
- 上流BGPルータ側でJuneauクラスターを受け入れる設定（AS **65002**、Juneauノード各IPとのピアリング）
- 広報に使うCIDRが上流ネットワークで未使用であること（本ガイドでは `10.225.51.0/24`）

## 手順

### 1. AddressPoolを作成

外部広報に使うCIDR範囲を定義します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: ext-pool
spec:
  advertiseMode: bgp
  addresses:
    - 10.225.51.0/24
```

`advertiseMode: bgp` は変更不可です。詳細は[AddressPool](../resources/addresspool.md)を参照してください。

### 2. BGPPeerを作成

上流ルータを宣言します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: BGPPeer
metadata:
  name: upstream
spec:
  myASN: 65001
  peerASN: 65002
  peerAddress: 10.225.32.1
```

この時点で各Nodeのbgp-speakerが `10.225.32.1` にBGPセッションを張りに行きます。詳細は[BGPPeer](../resources/bgppeer.md)を参照してください。

### 3. BGPAdvertisementを作成

どのAddressPoolを広報するかを指定します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: BGPAdvertisement
metadata:
  name: ext-adv
spec:
  addressPools:
    - ext-pool
```

詳細は[BGPAdvertisement](../resources/bgpadvertisement.md)を参照してください。

### 4. BGPセッションの確立を確認

BGPNodeStateでセッションの状態を確認します。

```console
$ kubectl get bgpnodestate
NAME       READY   BIRD   BMP    AGE
worker-1   True    True   True   2m
worker-2   True    True   True   2m
```

すべての列が`True`なら、birdが走っていてBMPに接続し、直近のreconcileも成功している状態です。詳細は以下で確認します。

```console
$ kubectl get bgpnodestate worker-1 -o yaml
...
status:
  bgpSessions:
    - peerAddress: 10.225.32.1
      peerName: upstream
      state: Up
      upSince: "2026-04-24T10:00:00Z"
  advertisements:
    - addressPool: ext-pool
      prefixes: ["10.225.51.0/24"]
      lastSyncedAt: "2026-04-24T09:59:58Z"
  conditions:
    - type: Ready
      status: "True"
      reason: Healthy
    ...
```

`bgpSessions[0].state`が`Up`にならない場合は、上流ルータ側のピア設定や経路の疎通を疑ってください。`bgpSessions[0].lastError`に直近のPeerDown理由が出ます。詳細は[BGPNodeState](../resources/bgpnodestate.md)を参照してください。

### 5. ExternalNetworkを作成

AddressPoolを1つの論理的な外部ネットワークとしてまとめます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: ext-net
spec:
  type: bgp
  addressPools:
    - ext-pool
```

`type: bgp`の場合、参照するAddressPoolは`advertiseMode: bgp`である必要があります。詳細は[ExternalNetwork](../resources/externalnetwork.md)を参照してください。

### 6. EIP対象Pod用のVpc/Subnetを作成

ElasticIPを付与するPodは、**default以外のSubnetに配置する必要があります**。専用Vpcとそこに属するSubnetを用意します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: ext-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: ext-subnet
spec:
  vpc: ext-vpc
  cidr: 10.60.0.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 7. RouteTableにInternetGatewayルートを追加

VpcのメインRouteTableは自動生成されますが、EIP egress (Pod → 外部) に必要な**InternetGateway向けデフォルトルートはデフォルトでは含まれません**。手動で追記します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: ext-vpc
spec:
  vpc: ext-vpc
  routes:
    - dst: 0.0.0.0/0
      via:
        type: internetGateway
```

RouteTableのメタ名はVpc名と同じです。このルートがないと、Podから外部への通信経路が成立しません。詳細は[RouteTable](../resources/routetable.md)を参照してください。

### 8. ElasticIPを作成

ExternalNetworkから1つのアドレスを払い出します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIP
metadata:
  name: nginx-eip
spec:
  externalNetwork: ext-net
```

```console
$ kubectl get elasticip nginx-eip
NAME        EXTERNALNETWORK   ADDRESS        ATTACHMENT   PHASE       ALLOCATED   ATTACHED
nginx-eip   ext-net           10.225.51.5                 Available   True        False
```

`PHASE: Available`で`ADDRESS`が埋まればアドレス確保完了です。この時点ではまだどのPodにもひもづいていません。

### 9. Podをデプロイ

対象のPodを、手順6で作ったSubnetに配置します。`juneau.loutres.me/subnet` annotationで明示します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
  annotations:
    juneau.loutres.me/subnet: ext-subnet
spec:
  containers:
    - name: nginx
      image: nginx:1.27
```

```console
$ kubectl get networkinterface
NAME         ...
nginx.eth0   ...
```

NetworkInterface名はデフォルトで `<Pod名>.eth0` です。

### 10. ElasticIPAttachmentでひもづけ

ElasticIPをPodのNetworkInterfaceに関連付けます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIPAttachment
metadata:
  name: nginx-eip-attach
spec:
  elasticIPRef:
    name: nginx-eip
  targetRef:
    networkInterfaceName: nginx.eth0
```

```console
$ kubectl get elasticipattachment
NAME               ELASTICIP    NETWORKINTERFACE   EIP            PODIP        NODE       PHASE      READY
nginx-eip-attach   nginx-eip    nginx.eth0         10.225.51.5    10.16.0.12   worker-1   Attached   True
```

`PHASE: Attached`かつ`READY: True`になれば、該当Node上でElasticIPがPodに関連付けられた状態です。詳細は[ElasticIPAttachment](../resources/elasticipattachment.md)を参照してください。

### 11. 外部からの疎通を確認

上流ルータ側、または上流ルータから到達可能な任意のホストから：

```console
$ curl -sS http://10.225.51.5/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

レスポンスが返れば、BGP広報 → 上流ルータの経路学習 → Nodeへの転送 → Pod、の経路が通っています。

## うまくいかないとき

1. **`kubectl get bgpnodestate`のREADYが`False`**
    - `BirdRunning: False`ならbgp-speaker Podが起動していないか、birdプロセスが落ちている。Pod ログを確認
    - `BMPConnected: False`ならbgp-speaker内のBMP接続が切れている。bird設定の再読み込み待ちか、ポート競合の可能性
2. **`bgpSessions[].state`が`Up`にならない**
    - `lastError`を確認。`administrative-shutdown`系なら対向側の設定、`remote-system-no-notification`系なら対向へのTCP到達性を疑う
    - `spec.peerAddress`と上流ルータのIPが一致しているか、AS番号が両側で揃っているかを確認
3. **`advertisements[]`が空、または期待CIDRが無い**
    - BGPAdvertisementの`spec.addressPools`の綴りとAddressPool名が一致しているか
    - 参照先AddressPoolの`spec.advertiseMode: bgp`か
    - `status.errors[]`にreconcile時の不整合が記録されていないか
4. **BGPは張れているのにcurlが通らない**
    - `elasticipattachment.status.conditions[?(@.type=="Ready")].status`が`True`になっているか。関連付けがまだ完了していない可能性
    - 上流ルータで経路が学習されているか（`show ip route 10.225.51.0/24`）
    - 対象Podが**default以外のSubnet**に属しているか。default SubnetのPodはElasticIPの対象にできません
    - Podが属するVpcのRouteTableに`type: internetGateway`のルートがあるか。無いと外部疎通が成立しません
    - NodeとPodの間はクラスター内通信と同じ経路なので、通常のPod到達性テストで切り分け可能

## 参照

- [AddressPool](../resources/addresspool.md)
- [BGPAdvertisement](../resources/bgpadvertisement.md)
- [BGPPeer](../resources/bgppeer.md)
- [BGPNodeState](../resources/bgpnodestate.md)
- [ExternalNetwork](../resources/externalnetwork.md)
- [ElasticIP](../resources/elasticip.md)
- [ElasticIPAttachment](../resources/elasticipattachment.md)
