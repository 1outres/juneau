# IPLease

IPLeaseは、IPアドレスの所有権を表すリソースです。
NetworkInterfaceが削除されたあと一定時間存在し、同じ名前でPodが作成された際に同じIPアドレスが割り当てられるようにします。

通常はユーザーが直接作成するのではなく、NetworkInterfaceの割り当て時に自動作成されます。

## phase

- Active:`spec.ownerDeletionTimestamp`が未設定で、IPアドレスを所有中の状態
- Released:`spec.ownerDeletionTimestamp`が設定され、TTL経過待ちの状態
- Expired:TTLが経過し、このIPLeaseが失効した状態
