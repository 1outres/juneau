# TransitGatewayRouteTable

TransitGatewayRouteTableは、TransitGatewayに届いたトラフィックの宛先を解決するルートテーブルです。

`spec.transitGateway`は、このルートテーブルが属するTransitGatewayの名前です。作成後に変更することができません。

## 経路の作られ方

解決済みの経路は`status.routes`に現れます。中身は2種類の経路から作られます。

- propagated route: このルートテーブルを`spec.propagations`に含む[TransitGatewayAttachment](transitgatewayattachment.md)が、自分のVpcのSubnetを広報したもの
- static route: `spec.routes`に書いたもの

同じ`dst`が両方に現れた場合はstatic routeが優先されます。

propagated route同士で`dst`が衝突した場合は、どちらかを黙って選ぶのではなく`Ready=False` (`AmbiguousRoute`) になります。CIDRの重複はwebhookで防いでいるため、通常は起きません。

## spec.routes

`spec.routes[].dst`は宛先のCIDRです。同じ`dst`を2つ書くことはできません。

`spec.routes[].attachment`は、その宛先のトラフィックを渡すTransitGatewayAttachmentの名前です。

`spec.routes[].blackhole`を`true`にすると、その宛先のトラフィックを破棄します。`blackhole: true`のときは`attachment`を指定できません。逆に`blackhole`を指定しない場合は`attachment`が必須です。

`blackhole`ではないstatic routeの`dst`は、指定したアタッチメントのVpcに存在するSubnetのCIDRと完全に一致している必要があります。データプレーンは1つの宛先SubnetのVNIへ転送するため、複数のSubnetにまたがるスーパーネットでは転送先が定まりません。一致するSubnetが無い場合は`Ready=False`になります。

## status

`status.tableID`は、データプレーンがこのルートテーブルを識別するためのIDです。

`status.routes[]`は解決済みの経路で、`dst`の昇順に並びます。`origin`は`static`か`propagated`のどちらかで、その経路がどちらの経路から来たかを表します。`blackhole: true`のエントリでは`subnet`が空になります。

`status.conditions`の`Ready`は、`tableID`が払い出され、すべてのstatic routeを解決できたことを表します。

## 削除

TransitGatewayAttachmentから`spec.association`または`spec.propagations`で参照されている間は削除できません。

TransitGatewayのdefault route table (TransitGatewayと同じ名前のもの) を単独で削除することはできません。TransitGatewayを削除すると一緒に削除されます。
