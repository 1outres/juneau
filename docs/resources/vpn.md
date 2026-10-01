# VPN

VPNは、1つのVpcと1つのオンプレ拠点をIPv4のIKEv2/IPsecとeBGPで接続します。VPNはnamespaceスコープです。VpcとSubnetはクラスタースコープで、同じVpcに複数のVPNを作成できます。Cisco IOS XE向けの設定例は[IOS XEガイド](../guides/vpn-ios-xe.md)にあります。

## 管理者の準備

インターネットから到達できるExternalNetworkと、その公開IPv4アドレス用AddressPoolを準備してください。UDP 500/4500をゲートウェイのElasticIPまで通します。ゲートウェイPodにはVpc側Subnetの`eth0`と、ElasticIPを直接持つ外部側`ext0`が付きます。hostNetworkは使いません。

トンネル内アドレスには、Subnetと共有しない専用のIPv4 AllocationPoolが必要です。管理者はcontroller managerのDeploymentへ`--vpn-tunnel-pool=<AllocationPool名>`と`--vpn-gateway-image=<ノードが取得できるイメージ>`を設定します。プールにはVPNごとに異なる2つのIPv4アドレスを確保できる空きが必要です。例:

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AllocationPool
metadata:
  name: vpn-tunnels
spec:
  type: ip
  ip:
    cidrs:
      - 169.254.51.0/24
```

`controller/config/manager/manager.yaml`のイメージ指定は`vpn-gateway:latest`です。ローカルで使う場合は`make image-vpn-gateway`で作成し、各ノードから取得できるようにしてください。本番環境では配布したイメージを指定します。どちらかのフラグが未設定ならVPNのReadyはFalseとなり、ゲートウェイは起動しません。別のプールやイメージへ自動的に切り替わることはありません。

## PSKとVPN

先にVPNと同じnamespaceへPSKのSecretを作ります。以下はコマンドに鍵を直接書かず、ローカルのファイルから作る例です。ファイルの読み取り権限にも注意してください。

```console
$ kubectl -n default create secret generic branch-psk --from-file=psk=./branch.psk
```

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: VPN
metadata:
  name: branch
  namespace: default
spec:
  vpc: production
  subnet: gateway
  externalNetwork: public
  localASN: 65001
  remoteASN: 65002
  peerIKEID: branch.example.com
  pskSecretRef:
    name: branch-psk
    key: psk
```

`spec.subnet`はゲートウェイPodを配置する、`spec.vpc`内のReadyなSubnetです。`spec.externalNetwork`のAddressPoolから専用ElasticIPを払い出します。特定の公開IPが必要なら`spec.requestedPublicIP`をIPv4アドレスで指定できます。`localASN`はJuneau側、`remoteASN`は対向側のAS番号で、異なる値を指定してください。`peerIKEID`はNAT外側のIPではなく対向の固定IKE識別子です。CiscoがNAT配下にいてもCisco側から接続を開始します。

PSKの値はVPNのspec/statusやPodの環境変数に入れず、Secretの指定キーをPodの読み取り専用ファイルとしてマウントします。Secret更新時にはPodを交換するため、通信が一時的に切れます。`vpc`、`subnet`、`externalNetwork`、`requestedPublicIP`は作成後に変更できません。

`status.publicIP`はElasticIPの払い出し後、`status.localTunnelIP`と`status.remoteTunnelIP`はトンネルアドレスの払い出し後に表示されます。ゲートウェイの停止中も払い出し済みの値は保持し、解放された値は消えます。いずれもVPNのReady以前に表示されることがあります。`status.conditions`の`Ready=True`はゲートウェイのIKE SA、child SA、BGPセッションをヘルスチェックで確認できた状態です。BGPの成立だけで往復の疎通を保証するものではありません。

## 経路

Juneauは対象Vpc内のReadyなSubnetをCiscoへBGP広報します。ゲートウェイSubnetの有効なRouteTableから実際に到達できる、直接ピアリングしたVpcとTransitGatewayの先のSubnet、許可されたServiceの個別のIPv4アドレスも対象です。default route、InternetGateway、NATGateway、他のVPN向けの経路は広報しません。二段先のVpcPeeringも対象外です。Ciscoから受け取るBGP経路はJuneauのRouteTableにもデータプレーンにも取り込みません。

**オンプレCIDRへの戻り経路は手動で設定してください。** たとえば`production`のSubnetがメインRouteTableを使うなら、次の経路を追加します。個別のRouteTableを使うSubnetにも、受信するオンプレ送信元IPに対する経路が必要です。VPNから入るパケットの送信元IPはSNATせず、宛先Subnetの有効なRouteTableで同じVPNへの戻り経路が見つかったときだけ通します。Vpc側Podからオンプレ宛に通信を開始する場合も同じ経路を使います。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: production
spec:
  vpc: production
  routes:
    - dst: 192.0.2.0/24
      via:
        type: vpn
        vpn:
          namespace: default
          name: branch
```

必要なら`dst: 0.0.0.0/0`を明示できます。別の許可フラグや障害時の暗黙の迂回先はありません。同じRouteTableに同じ宛先を2回書くことはできません。経路と到達可能なSubnetやServiceなどが重複する場合も拒否します（明示したdefault routeを除きます）。

直接ピアリングしたVpcからオンプレへ返す場合は、そのVpcのRouteTableにも同じCIDRで`via.type: vpcPeering`とピアリング名を指定します。たとえば`peer-vpc`のSubnetから`production`のVPNへ返す経路は次のとおりです。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: peer-vpc
spec:
  vpc: peer-vpc
  routes:
    - dst: 192.0.2.0/24
      via:
        type: vpcPeering
        vpcPeering: direct-peering
```

TransitGatewayの先から返す場合は、先方VpcのRouteTableに`via.type: transitGateway`の同CIDRを追加します。先方VpcのアタッチメントがassociationするTransitGatewayRouteTableには、VPN側Vpcのアタッチメントを指す同CIDRのstatic routeが必要です。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: spoke-vpc
spec:
  vpc: spoke-vpc
  routes:
    - dst: 192.0.2.0/24
      via:
        type: transitGateway
        transitGateway: corp-tgw
---
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayRouteTable
metadata:
  name: spoke-associated-table
spec:
  transitGateway: corp-tgw
  routes:
    - dst: 192.0.2.0/24
      attachment: production-attachment
```

ここで`production-attachment`はVPNを接続したVpcのTransitGatewayAttachmentです。いずれの構成でも、VPN側VpcのRouteTableには上記の`via.type: vpn`を残してください。個別のRouteTableを使うSubnetには経路をそれぞれ追加します。他VpcのRouteTableをVPNが自動変更することはありません。往路だけをBGPで広報しても復路がなければ疎通しません。

SecurityGroupとNetworkACLの設定はVPN経由でも適用されます。ServiceへのアクセスもVpcで許可されている範囲だけです。同じVpcのVPN同士は中継しません。

## 運用上の制限

VPNごとにゲートウェイPodは1つです。障害、Secret更新、経路変更によるPodの交換時には同じElasticIPで張り直しますが、再接続まで通信が途切れます。無停止の待機系はありません。ゲートウェイイメージだけでノード側の送信元検証やVpcPeering/TransitGatewayの戻り経路が設定されるわけではありません。

RouteTableから参照中のVPNは削除できません。先にすべての参照経路を外してください。ゲートウェイPodとElasticIPを削除した後にトンネルアドレスを解放します。IPv6とpolicy-based VPNは対象外です。Cisco IOS XE実機との相互接続は未検証です。
