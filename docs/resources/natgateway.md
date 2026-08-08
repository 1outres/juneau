# NATGateway

NATGatewayは、Vpcに属するPodがVpc外へ通信する際のNAPT (N:1のソースNAT) 出口を表すリソースです。
Vpc内の複数のPodが共通のソースIPアドレスで外部に出ていく構成を作るときに利用します。

`spec.vpc`はこのNATGatewayが属するVpcの名前です。
`spec.externalNetwork`は出口となるExternalNetworkの名前です。
NAPT時のソースIPアドレスは、参照したExternalNetworkに紐づくAddressPoolから払い出されます。

`spec.vpc`と`spec.externalNetwork`は作成後に変更できません。

## RouteTable との連携

NATGatewayをVpc外への経路として利用するには、対象VpcのRouteTableに`via.type: natGateway`のルートを追加し、`via.natGateway`でNATGateway名を参照します。
たとえば`0.0.0.0/0`のデフォルトルートをこのNATGateway経由に向けることで、Vpc内のPodがクラスタ外へ通信できるようになります。

詳しくは[RouteTable](routetable.md)を参照してください。

## Node ごとのソースIP

NATGatewayを作成すると、対象ExternalNetworkに紐づくNodeごとの[ExternalNetworkAttachment](externalnetworkattachment.md)が自動的に作成され、Nodeごとに1つずつNAPTソースIPアドレスが払い出されます。
Pod がVpc外へ出るとき、そのPodが配置されているNodeに対応するソースIPアドレスが利用されます。

## 対応プロトコル

NAPTの対象はTCP、UDP、ICMPの3つです。それ以外のプロトコルはNATGateway経由で外部に出ることができません。

ICMPで扱うのはEcho Requestとその応答であるEcho Replyです。ICMPにはポートが無いため、ICMPヘッダのIdentifierをポート相当として払い出します。Echo ReplyはRequestと同じIdentifierを返すので、払い出した値から元のPodを引き当てることができます。これによりNATGateway配下のPodやVMから`ping`が通ります。

Echo以外では、Destination Unreachable、Time Exceeded、Source Quench、Redirect、Parameter Problemの5種類のICMPエラーメッセージを扱います。これらは経路上のルータが送るものなので、外側のIPヘッダを見てもどのフローに対する応答なのか分かりません。ICMPエラーメッセージが内包している元パケットのヘッダからconntrackのエントリを引き当て、外側と内包の両方を書き換えます。Podのカーネルは内包されたヘッダを見て対応するソケットを探すため、この書き換えが無いとエラーメッセージは捨てられます。NATGateway配下で`traceroute`とPath MTU Discoveryが動くのはこの仕組みによります。Pod側から外部に向けて送るICMPエラーメッセージも、同じように内包ヘッダごと書き換えます。

EchoとICMPエラーメッセージ以外のICMPタイプ (Timestampなど) は破棄されます。IPフラグメントも対象外です。

ICMPのconntrackエントリは、最後にパケットが通ってから30秒でGCの対象になります。TCPのように終了を示すものが無いためです。

ICMPエラーメッセージの書き換えは`kubectl juneau trace`で`icmp error translated`として記録されます。表示されるタプルは、ICMPエラーメッセージ自体ではなく、そのエラーが報告している元のフローです。

## default NATGateway

`default`という名前のNATGatewayが存在し、Readyになっている場合、`default` Vpcのメインルートテーブルには`0.0.0.0/0`へのルートが`via.type: natGateway`として自動的に追加されます。
これにより明示的にRouteTableを構成しなくても、default Vpc内のPodがクラスタ外へ通信できるようになります。

## status

`status.conditions`の`Ready`は、NATGatewayが正常に利用可能かを表します。
`Ready=True`になるまでは、このNATGatewayを参照するRouteTableのルートも有効にはなりません。
