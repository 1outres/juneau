# PodにNICを追加する

Podは既定でeth0を1枚だけ持ちます。`juneau.loutres.me/networks`アノテーションを書くと、別のSubnetに繋がるNICを追加することができます。
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

配列の要素は次の4つのフィールドを取ります。

| フィールド | 必須 | 意味 |
|---|---|---|
| `interface` | ○ | Podの中でのNICの名前。DNS-1123ラベルで8文字以内 |
| `subnet` | ○ | 接続先のSubnet。eth0と別のVpcでも構いません |
| `address` | | 要求するIPv4アドレス。未指定ならSubnetのプールから割り当てます |
| `securityGroups` | | このNICに適用するSecurityGroup。2つまで |

`interface`が8文字までなのは、ホスト側のvethに`<interface>+<コンテナID>`という名前を付けるからです。Linuxのインターフェース名は15文字までなので、コンテナIDを識別できるだけ残すと8文字が上限になります。

Podが起動したら、NICごとにNetworkInterfaceとNetworkEndpointができていることを確認します。名前は`<Pod名>.<interface>`です。

```console
$ kubectl get networkinterface
NAME       NODE       SUBNET        ADDRESS         PHASE
app.eth0   worker-1   app-subnet    10.90.0.5/24    Ready
app.eth1   worker-1   mgmt-subnet   10.90.1.4/24    Ready
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

### eth0は特別扱いです

コンテナランタイムはCNIの結果にeth0という名前のNICとそのアドレスがあることを要求します。ないとRunPodSandboxが失敗するので、eth0を`networks`に書くとwebhookが拒否します。eth0の設定は今まで通り`juneau.loutres.me/subnet`と`juneau.loutres.me/address`と`juneau.loutres.me/security-groups`で行います。

eth0はPodのアドレスそのものでもあります。次の3つはすべてeth0だけを見ます。

- `pod.status.podIP`とServiceのバックエンド
- kubeletのプローブ
- DNSの注入先Subnet

### デフォルトルートは1本だけです

追加NICにはデフォルトルートを入れません。Podが持つデフォルトルートはeth0のSubnetのゲートウェイに向かう1本だけで、追加NICから出ていくのは、そのNICのSubnetの中に閉じた通信になります。追加NICのVpcの他のSubnetへ届かせたい場合は、Podの中で経路を足してください。

### NICを減らすとNetworkInterfaceも消えます

`networks`から要素を消してPodを更新すると、PodControllerが余ったNetworkInterfaceを削除します。動いているPodからNICが抜けるわけではありませんが、NetworkEndpointが一緒に消えてデータプレーンの設定が外れるので、そのNICの通信は止まります。NICの増減はPodを作り直して反映させてください。

### 全部のNICが揃うまでPodは起動しません

CNIのADDは、Podが要求したNICのアドレスがすべて確定してからvethを作ります。追加NICのSubnetが存在しない、あるいはアドレスが枯渇しているときは、eth0の分も含めてPodがContainerCreatingのまま止まります。`kubectl get networkinterface`でどのNICがPendingかを見てください。
