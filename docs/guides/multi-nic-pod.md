# PodにNICを追加する

Podは既定でeth0を1枚だけ持ちます。`juneau.loutres.me/networks`アノテーションを書くと、別のSubnetやL2Networkに繋がるNICや、ElasticIPを持つNICを追加することができます。eth0自体もこのアノテーションで書けます。
このガイドでは、アプリ用のSubnetに置いたPodへ管理用のSubnetのNICをもう1枚生やし、管理用Subnetの側からだけ届く経路を作ります。

## このガイドで構築するもの

- 専用Vpc (`multi-vpc`) とSubnet 2つ
    - `app-subnet` (`10.90.0.0/24`): Podのeth0を置くSubnet
    - `mgmt-subnet` (`10.90.1.0/24`): 追加NICを置くSubnet
- eth0が`app-subnet`、eth1が`mgmt-subnet`のPod
- `mgmt-subnet`にいる運用ツールのPodから、追加NICのアドレスへ到達できること

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと

## 手順

### 1. Vpcと2つのSubnetを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: multi-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: multi-vpc
  cidr: 10.90.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: mgmt-subnet
spec:
  vpc: multi-vpc
  cidr: 10.90.1.0/24
```

### 2. 2枚のNICを持つPodを作成

`juneau.loutres.me/subnet`はこれまで通りeth0の指定です。追加のNICは`juneau.loutres.me/networks`にJSONの配列で書きます。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
  annotations:
    juneau.loutres.me/subnet: app-subnet
    juneau.loutres.me/networks: |
      [
        {"interface": "eth1", "subnet": "mgmt-subnet"}
      ]
spec:
  containers:
    - name: app
      image: nginx:1.27
```

配列の要素は次のフィールドを取ります。`subnet`、`l2Network`、`elasticIP`はNICの接続先で、どれか1つだけを書きます。

| フィールド | 必須 | 意味 |
|---|---|---|
| `interface` | ○ | Podの中でのNICの名前。DNS-1123ラベルで8文字以内 |
| `subnet` | 接続先のどれか1つ | 接続先のSubnet。eth0と別のVpcでも構いません |
| `l2Network` | 接続先のどれか1つ | 接続先の[L2Network](../resources/l2network.md) |
| `elasticIP` | 接続先のどれか1つ | NICに直接持たせる、Podと同じnamespaceの[ElasticIP](../resources/elasticip.md) |
| `address` | | 要求するIPv4アドレス。未指定ならSubnetやL2Networkのプールから割り当てます。`elasticIP`のエントリには書けません |
| `securityGroups` | | このNICに適用するSecurityGroup。2つまで。`elasticIP`のエントリには書けません |

`interface`が8文字までなのは、ホスト側のvethに`<interface>+<コンテナID>`という名前を付けるからです。Linuxのインターフェース名は15文字までなので、コンテナIDを識別できるだけ残すと8文字が上限になります。

Podが起動したら、NICごとにNetworkInterfaceとNetworkEndpointができていることを確認します。名前は`<Pod名>.<interface>`です。

```console
$ kubectl get networkinterface
NAME       NODE       SUBNET        L2NETWORK   ELASTICIP   ADDRESS         PHASE
app.eth0   worker-1   app-subnet                            10.90.0.5/24    Ready
app.eth1   worker-1   mgmt-subnet                           10.90.1.4/24    Ready
```

### 3. 追加NICへの到達を確認

`mgmt-subnet`にPodをもう1つ置いて、eth1のアドレスへ通信します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ops
  annotations:
    juneau.loutres.me/subnet: mgmt-subnet
spec:
  containers:
    - name: ops
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "3600"]
```

```console
$ kubectl exec ops -- curl -sS http://10.90.1.4 | head -1
<!DOCTYPE html>
```

## 注意点

### eth0の書き方は3通りです

コンテナランタイムはCNIの結果にeth0という名前のNICとそのアドレスがあることを要求します。ないとRunPodSandboxが失敗するので、どのPodにもeth0は必ずあります。eth0は次のどれか1つで書きます。

| 書き方 | eth0の接続先 |
|---|---|
| `networks`に`interface: eth0`のエントリを書く | エントリの`subnet`、`l2Network`、`elasticIP` |
| `juneau.loutres.me/elastic-ip`にElasticIPの名前を書く | そのElasticIP |
| どちらも書かない | `juneau.loutres.me/subnet`のSubnet。未指定なら`default`。`juneau.loutres.me/address`と`juneau.loutres.me/security-groups`もeth0に効きます |

書き方を混ぜるとwebhookが拒否します。`networks`にeth0のエントリがあるときは、`juneau.loutres.me/subnet`、`juneau.loutres.me/address`、`juneau.loutres.me/security-groups`、`juneau.loutres.me/elastic-ip`のどれも書けません。値が空でも、キーがあるだけで拒否します。`juneau.loutres.me/elastic-ip`を書いたときは、`juneau.loutres.me/subnet`、`juneau.loutres.me/address`、`juneau.loutres.me/security-groups`を書けません。

eth0をSubnetに置くPodは、`networks`でも従来のアノテーションでも同じように動きます。

```yaml
annotations:
  juneau.loutres.me/networks: |
    [
      {"interface": "eth0", "subnet": "app-subnet"},
      {"interface": "eth1", "subnet": "mgmt-subnet"}
    ]
```

### eth0で決まるもの

eth0はPodのアドレスそのものでもあります。次のものはすべてeth0だけを見ます。

- `pod.status.podIP`とServiceのバックエンド
- kubeletのプローブ
- DNSの設定

eth0をSubnet以外に置くと、これらの扱いが変わります。

| | eth0がSubnet | eth0がL2Network | eth0がElasticIP |
|---|---|---|---|
| dnsPolicy | Subnetの仮想DNSを注入 | `Default`に書き換え | `Default`に書き換え |
| NodeからPodへの経路 | これまで通り | 作りません | `<ElasticIP>/32`をPodのvethへ |
| kubeletのプローブ | これまで通り | `--enable-probe-rewrite`で書き換え | Nodeの経路で届きます |
| Serviceのバックエンド | なれる | なれない | なれない |
| ClusterIP Serviceへ | これまで通り | gatewayを跨いで届く | 届かない |

SubnetのPodには、Subnetごとの仮想DNSを注入しています。L2NetworkとElasticIPのNICにはその仮想DNSが無いので、Nodeの`resolv.conf`のDNSサーバを使う`Default`にします。そのNICからDNSサーバに届く経路が要ります。

書き換えるのは、作成時のdnsPolicyが未指定、`ClusterFirst`、`ClusterFirstWithHostNet`のときだけです。`None`と`Default`はそのまま残します。`juneau.loutres.me/dns-inject-skip: "true"`を付けたPodは書き換えません。

### eth0をL2Networkに置く

eth0に使えるのは、`spec.cidr`と`spec.gateway`の両方を持つL2Networkだけです。どちらかが無いとwebhookが拒否します。eth0にはアドレスが要り、Podのデフォルトルートの行き先としてgatewayが要るからです。

```yaml
annotations:
  juneau.loutres.me/networks: |
    [
      {"interface": "eth0", "l2Network": "lab-net"}
    ]
```

デフォルトルートはL2Networkの`status.gateway`に向きます。

dnsPolicyは`Default`になり、kubeletがNodeに渡している`resolv.conf`のDNSサーバを使います。そのDNSサーバには、eth0のアドレスからgateway経由で届く必要があります。kindのNodeが使うdockerの内蔵DNSのように、Nodeの中でしか使えないDNSサーバだと名前解決ができません。

NodeからPodへの経路は作りません。L2Networkは必ずcustom Vpcに属していて、Vpc同士でアドレスが重なってよいので、Nodeに経路を入れると別のVpcのPodとぶつかります。kubeletのhttpGetやtcpSocketのプローブを使うなら、custom VpcのSubnetのPodと同じく、controllerの`--enable-probe-rewrite`を有効にしてください。プローブがPodのnetwork namespaceの中から実行されるように書き換わります。

### ElasticIPを持つNIC

`elasticIP`のエントリや`juneau.loutres.me/elastic-ip`で、NICにElasticIPのアドレスをそのまま持たせることができます。NICはどのVpcにも属さず、SecurityGroupもNetworkACLも効きません。1つのElasticIPを持てるのは1つのNICだけで、1つのPodの2枚のNICに同じElasticIPを書くとwebhookが拒否します。

詳しい手順と制限は[PodのNICにElasticIPを直接持たせる](elastic-ip-direct.md)を参照してください。

### NIC同士のCIDRは重ならないこと

追加NICのSubnetは別のVpcのものでも構いませんが、Pod内の2枚のNICのCIDRが重なる指定はwebhookが拒否します。重なっているとPodの中にオンリンク経路が2本並び、どちらに出ていくかが不定になります。

### デフォルトルートは1本だけです

SubnetとL2Networkの追加NICにはデフォルトルートを入れません。mainテーブルのデフォルトルートはeth0の1本だけで、追加NICから出ていくのは、そのNICのSubnetやL2Networkの中に閉じた通信になります。追加NICのVpcの他のSubnetへ届かせたい場合は、Podの中で経路を足してください。

ElasticIPの追加NICだけは、専用のルートテーブルにデフォルトルートを入れ、送信元がそのElasticIPのパケットをそのテーブルへ向けるルールを足します。mainテーブルには何も足さないので、eth0のデフォルトルートはそのままです。仕組みは[NetworkInterface](../resources/networkinterface.md)を参照してください。

### NICを減らすとNetworkInterfaceも消えます

`networks`から要素を消してPodを更新すると、PodControllerが余ったNetworkInterfaceを削除します。動いているPodからNICが抜けるわけではありませんが、NetworkEndpointが一緒に消えてデータプレーンの設定が外れるので、そのNICの通信は止まります。NICの増減はPodを作り直して反映させてください。

### 全部のNICが揃うまでPodは起動しません

CNIのADDは、Podが要求したNICのアドレスがすべて確定してからvethを作ります。追加NICのSubnetが存在しない、あるいはアドレスが枯渇しているときは、eth0の分も含めてPodがContainerCreatingのまま止まります。`kubectl get networkinterface`でどのNICがPendingかを見てください。
