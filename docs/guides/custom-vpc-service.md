# VPCでServiceを利用する

Juneauでは、Vpcごとに独立したServiceを利用できます。default以外のVpcでServiceを扱うには、Vpc側で機能を有効化したうえで、Serviceの所属Vpcをアノテーションで宣言します。このガイドはその一連の手順をゼロから組み立てる流れを示します。

## このガイドで構築するもの

- Service機能を有効化したVpc (`app-vpc`)
- 同一Vpcに属する2つのSubnet
    - `app-subnet` (`10.80.0.0/24`): backend Pod配置先
    - `client-subnet` (`10.80.1.0/24`): client Pod配置先
- nginxによるbackend Deployment (replicas: 2) とそれに対応するService
- 別Subnetに居るclient Podから、Serviceの名前解決経由でnginxに疎通

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと
- クラスターでServiceの仮想IP (ClusterIP) 用のCIDRが設定されていること

## 手順

### 1. Service機能を有効化したVpcを作成

default以外のVpcでServiceを扱うには、`spec.service` を設定します。自 Vpc のPod が同じVpc 内のService にだけ到達できれば良いケースでは `spec.service.consume: true` だけ指定すれば十分です。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
spec:
  service:
    consume: true
```

`spec.service` を一切設定していないVpcをServiceの所属先として指定すると、Serviceの作成は拒否されます。詳細は[Vpc](../resources/vpc.md)を参照してください。

### 2. Subnetを2つ作成

同じVpcに属するSubnetを2つ作成します。backendとclientを別々のSubnetに置くことで、同一Vpc内の異なるSubnet間でServiceが利用できることを確認します。

```yaml
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

詳細は[Subnet](../resources/subnet.md)を参照してください。

### 3. RouteTableにService経路が注入されていることを確認

`spec.service` でService 関連の opt-in が設定されたVpcでは、そのVpcのメインRouteTableにService CIDR向けのルートが自動で注入されます。ユーザが手動で追加する必要はありません。

```console
$ kubectl get routetable app-vpc -o yaml
...
status:
  routes:
    - dst: 10.80.0.0/24
      subnet: app-subnet
      via:
        type: connected
    - dst: 10.80.1.0/24
      subnet: client-subnet
      via:
        type: connected
    - dst: 10.96.0.0/12        # クラスターのService CIDR
      via:
        type: service
```

`via.type: service`のエントリがService CIDRに対して入っていれば準備完了です。詳細は[RouteTable](../resources/routetable.md)を参照してください。

### 4. backend Deploymentを作成

backendのnginxを2レプリカで`app-subnet`に配置します。Pod templateの`juneau.loutres.me/subnet`アノテーションでSubnetを指定します。

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
      annotations:
        juneau.loutres.me/subnet: app-subnet
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
```

### 5. Serviceを作成

ServiceにはどのVpcに属するServiceかを示す`juneau.loutres.me/vpc`アノテーションを付けます。

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/vpc: app-vpc
spec:
  selector:
    app: nginx
  ports:
    - port: 80
      targetPort: 80
```

```console
$ kubectl get service nginx
NAME    TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
nginx   ClusterIP   10.96.123.45    <none>        80/TCP    5s
```

`juneau.loutres.me/vpc`アノテーションを省略すると、Serviceはdefault Vpcに属するものとして扱われます。default以外のVpcでServiceを扱うときは必ず明示してください。

### 6. 別Subnetにclient Podをデプロイ

`client-subnet`にcurl用のPodを配置します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl
  annotations:
    juneau.loutres.me/subnet: client-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 7. ClusterIPへの疎通を確認

clientからService名でnginxに到達することを確認します。

```console
$ kubectl exec curl -- curl -sS http://nginx/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

`app-subnet` (10.80.0.0/24) のbackendと`client-subnet` (10.80.1.0/24) のclientは異なるSubnetですが、同じVpcに属しているためServiceを経由して疎通できます。

## うまくいかないとき

1. **Serviceのapplyが拒否される**
    - 対象Vpcに`spec.service.consume: true` (もしくは `spec.service.provider.natSourceSubnet`) が設定されているか
    - `juneau.loutres.me/vpc`で指定したVpcが実在するか
2. **RouteTableに`via.type: service`のルートが入らない**
    - 対象Vpcの `spec.service` でService ルーティングが有効になっているか
    - クラスター側でService CIDRが設定されているか
3. **client PodからClusterIPに到達しない**
    - client Podが対象Vpcに属するSubnetに配置されているか (`juneau.loutres.me/subnet`アノテーション)
    - backend Podも同じVpcに属するSubnetに配置されているか
    - `kubectl get endpointslice -l kubernetes.io/service-name=nginx`でbackendのPod IPが登録されているか

## 参照

- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [RouteTable](../resources/routetable.md)
