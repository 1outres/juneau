# SecurityGroupでPodの通信を制限する

Juneauでは、SecurityGroupを使ってPod単位でステートフルな許可ルールを記述し、不要な通信を遮断できます。
このガイドでは、最小構成のWebアプリケーションを題材に、

1. backend Podへの受信を許可するクライアントだけを絞る
2. それ以外のPodからは到達できないことを確認する
3. SecurityGroup同士の参照で「同じロールを持つPod群」をまとめて許可する

までの一連の手順を示します。

## このガイドで構築するもの

- 専用Vpc (`app-vpc`) と Subnet 2つ
    - `app-subnet` (`10.80.0.0/24`): backend Pod配置先
    - `client-subnet` (`10.80.1.0/24`): クライアントPod配置先
- backend用のSecurityGroup (`web-sg`)
- 許可されたクライアント用のSecurityGroup (`client-sg`)
- backend Pod (nginx) に`web-sg`を付与
- 許可されたクライアントPodに`client-sg`を付与
- `client-sg`を付与したクライアントからbackendへの通信が成立し、付与していないクライアントからは遮断されること

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと

## 手順

### 1. Vpcと2つのSubnetを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: client-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.1.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 2. クライアント側のSecurityGroupを作成

backendへの到達を許可したいクライアントに付ける目印として、ルールを持たない空のSecurityGroupを作ります。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: client-sg
spec:
  vpc: app-vpc
```

`spec.ingress`を空にすると、`client-sg`を付けたPodは何も受信できなくなります。
このガイドではクライアント側は受信を許可する必要が無い (送信のみ) ため、空のままで問題ありません。

### 3. backend用のSecurityGroupを作成

`client-sg`を付けたPodからのTCP/80だけを受信可能にします。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: web-sg
spec:
  vpc: app-vpc
  ingress:
    - from:
        - securityGroupRef:
            name: client-sg
      protocol: tcp
      ports:
        - port: 80
```

`securityGroupRef`に同じVpcのSecurityGroupを指定すると、そのSecurityGroupを付けた任意のPodからのトラフィックがマッチします。CIDRと違いPodのIPアドレスが入れ替わっても動作するので、Podが再作成される環境でも安定して使えます。

```console
$ kubectl get securitygroup
NAME        VPC       GROUPID   INGRESS   EGRESS   READY
client-sg   app-vpc   1         0                  True
web-sg      app-vpc   2         1                  True
```

`READY: True`になればSecurityGroupは反映済みです。`INGRESS`列はspec.ingressを許可エントリに展開したあとの件数です。
詳細は[SecurityGroup](../resources/securitygroup.md)を参照してください。

### 4. backend Podをデプロイ

`web-sg`を`juneau.loutres.me/security-groups` annotationで付与します。

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
      annotations:
        juneau.loutres.me/subnet: app-subnet
        juneau.loutres.me/security-groups: web-sg
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
```

### 5. 許可されたクライアントPodをデプロイ

`client-sg`を付けたクライアントPodを別Subnetに配置します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl-allowed
  annotations:
    juneau.loutres.me/subnet: client-subnet
    juneau.loutres.me/security-groups: client-sg
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 6. 許可されていないクライアントPodをデプロイ

比較対象として、SecurityGroupを付けていないクライアントPodも用意します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl-denied
  annotations:
    juneau.loutres.me/subnet: client-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 7. 通信を確認

backend PodのIPアドレスを取得して、両方のクライアントから到達を試みます。

```console
$ BACKEND=$(kubectl get pod -l app=nginx -o jsonpath='{.items[0].status.podIP}')
$ kubectl exec curl-allowed -- curl -sS --max-time 5 http://$BACKEND/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>

$ kubectl exec curl-denied -- curl -sS --max-time 5 http://$BACKEND/
curl: (28) Connection timed out after 5001 milliseconds
```

`client-sg`を付与した`curl-allowed`からは応答が返り、付与していない`curl-denied`からは到達できません。

## 別のパターン: CIDRで許可する

ピアのSecurityGroupではなく、IPレンジで受信を許可したい場合は`securityGroupRef`の代わりに`cidr`を指定します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: web-sg
spec:
  vpc: app-vpc
  ingress:
    - from:
        - cidr: 10.80.1.0/24
      protocol: tcp
      ports:
        - port: 80
```

このルールを持つbackendは、`10.80.1.0/24`のいずれかのアドレスから来たTCP/80を受信します。

特定のクライアントレンジに絞れる反面、Podの再スケジューリングでアドレスが変わる前提のクラスタでは`securityGroupRef`の方が扱いやすいです。両者は同じルール内に混在させることもできます。

## 別のパターン: 送信側を制限する

`spec.egress`を明示すると送信が制限されます (省略時は全許可)。
たとえば「クライアントPodは`web-sg`を付けたbackendにしか送信できない」ようにするには、`client-sg`を次のように書き換えます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: client-sg
spec:
  vpc: app-vpc
  egress:
    - to:
        - securityGroupRef:
            name: web-sg
      protocol: tcp
      ports:
        - port: 80
```

`spec.egress`を一度でも書くと、明示していない宛先への送信は全て遮断されます。クラスタ内DNSや外部APIに到達したい場合は、必要なピアもルールに追加してください。

## Vpcで強制する

「このVpcのPodには必ずSecurityGroupを付ける」運用を徹底したい場合、Vpcに`spec.enforceSecurityGroups: true`を設定します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
spec:
  enforceSecurityGroups: true
```

この設定が有効な間、Vpc配下のSubnetに作成しようとするPodで`juneau.loutres.me/security-groups` annotationが空 (または無効なSecurityGroupしか含まない) 場合、Podの作成は拒否されます。
有効化はVpc単位なので、本番系Vpcのみに適用するなどの使い分けができます。

## うまくいかないとき

1. **Podの作成が拒否される (`enforceSecurityGroups`)**
    - 対象Vpcの`spec.enforceSecurityGroups`が`true`の場合、Pod annotationで少なくとも1つの有効なSecurityGroupを付ける必要があります
    - 指定したSecurityGroupが存在し、かつPodのSubnetと同じVpcに属しているか確認してください
2. **許可したはずのPodから到達しない**
    - `kubectl get securitygroup <name>`の`READY: True`を確認
    - `status.ingressRuleCount` / `status.egressRuleCount`が想定通りの件数になっているかを確認 (0件なら全遮断 / 全許可のデフォルト動作になります)
    - `securityGroupRef`で参照しているSecurityGroupとbackendの両方が同じVpcに属しているか確認
    - クライアントPodのannotationでSecurityGroupが正しく付いているかを`kubectl get pod <name> -o yaml`で確認
3. **遮断したいPodからも通ってしまう**
    - 許可ルールはOR評価です。複数SecurityGroupを付与した場合は、いずれか1つでも許可すれば通ります。意図せず広すぎる`cidr`を指定していないか確認してください
    - SecurityGroupを付与していないPodはSecurityGroupによる制限を受けません。全Podに付与を強制したい場合は`spec.enforceSecurityGroups: true`を検討
4. **`securityGroupRef`が見つからない旨のエラー**
    - 参照先のSecurityGroupがまだ作られていない、もしくは別のVpcに属しています。`spec.vpc`を揃えて作り直してください

## 参照

- [SecurityGroup](../resources/securitygroup.md)
- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [NetworkACLとSecurityGroupの評価を追う](../developer/policy-data-plane.md) (データプレーン側の解説)
