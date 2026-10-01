#!/usr/bin/env python3
import json
import sys

required = {
    "TestVPNBPFMapLayout",
    "TestVPNIngressUsesDestinationSubnetLongestPrefixReturnRoute",
    "TestVPNTransitRequiresTargetReturnRouteToSameGateway",
    "TestVPNMultipleIdentitiesInSameVpc",
    "TestVPNRejectsMoreSpecificReturnRouteAndTransit",
    "TestVPNDoesNotAuthorizeOrdinaryPodSpoofing",
    "TestVPNIngressStillPassesNetworkACLAndSecurityGroup",
}

results = {}
skipped = []
for line in sys.stdin:
    event = json.loads(line)
    test = event.get("Test", "")
    action = event.get("Action")
    if test and action in {"pass", "fail", "skip"}:
        results[test] = action
        if action == "skip":
            skipped.append(test)

missing = sorted(name for name in required if results.get(name) != "pass")
if skipped or missing:
    print(f"VPN kernel test gate failed; not passed: {missing}; skipped: {skipped}", file=sys.stderr)
    sys.exit(1)

print(f"VPN kernel test gate passed: {len(required)} required tests ran without skips")
