# NetworkInterfaceAttachment

NetworkInterfaceAttachmentは、永続的なNetworkInterfaceと、現在動作している
Podのインターフェースを結びつける一時リソースです。

PodControllerが作成し、PodのownerReferenceを持ちます。Podが再作成されると
Attachmentも新しいUIDで作り直されます。IPアドレスはAttachmentではなく
NetworkInterfaceが保持するため、Podの世代交代では変わりません。

## spec

- `spec.networkInterfaceRef`: 実体化するNetworkInterface
- `spec.podRef`: Podの名前、UID、インターフェース名
- `spec.nodeName`: Podが配置されたNode

specは作成後に変更できません。

## Binding

NetworkInterfaceの`spec.attachmentRef`にはAttachmentの名前とUIDを設定します。
CNIは両方が一致するときだけNetworkEndpointを作成します。

旧AttachmentのNetworkEndpointが残っている間は別Attachmentへの更新が拒否されるため、
同じIPアドレスが複数のPodへ同時に割り当てられることはありません。
