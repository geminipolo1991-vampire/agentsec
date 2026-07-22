from __future__ import annotations

import json
import unittest
from pathlib import Path


class DeploymentFoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(
            Path("deploy/ec2-tokyo/foundation.json").read_text(encoding="utf-8")
        )
        self.resources = self.template["Resources"]

    def test_foundation_creates_an_isolated_vpc(self) -> None:
        self.assertEqual(self.resources["Vpc"]["Type"], "AWS::EC2::VPC")
        self.assertEqual(self.template["Parameters"]["VpcCidr"]["Default"], "10.42.0.0/16")
        self.assertFalse(
            self.resources["PrivateSubnet"]["Properties"]["MapPublicIpOnLaunch"]
        )
        self.assertTrue(
            self.resources["PublicSubnet"]["Properties"]["MapPublicIpOnLaunch"]
        )

    def test_private_subnet_uses_new_nat_gateway(self) -> None:
        route = self.resources["PrivateDefaultRoute"]["Properties"]
        self.assertEqual(route["NatGatewayId"], {"Ref": "NatGateway"})
        self.assertEqual(route["DestinationCidrBlock"], "0.0.0.0/0")

    def test_template_does_not_accept_existing_network_ids(self) -> None:
        parameters = self.template["Parameters"]
        self.assertNotIn("VpcId", parameters)
        self.assertNotIn("SubnetId", parameters)
        serialized = json.dumps(self.template, sort_keys=True)
        self.assertNotIn("vpc-", serialized)
        self.assertNotIn("subnet-", serialized)

    def test_ecr_repository_is_immutable_encrypted_and_scanned(self) -> None:
        repository = self.resources["ContainerRepository"]["Properties"]
        self.assertEqual(repository["ImageTagMutability"], "IMMUTABLE")
        self.assertEqual(repository["EncryptionConfiguration"], {"EncryptionType": "AES256"})
        self.assertEqual(repository["ImageScanningConfiguration"], {"ScanOnPush": True})
        self.assertFalse(repository["EmptyOnDelete"])

    def test_all_tagged_resources_use_project_boundary(self) -> None:
        tagged = [
            resource["Properties"]["Tags"]
            for resource in self.resources.values()
            if "Tags" in resource.get("Properties", {})
        ]
        self.assertTrue(tagged)
        for tags in tagged:
            tag_map = {item["Key"]: item["Value"] for item in tags}
            self.assertEqual(tag_map["Project"], "ai-agent-security")
            self.assertEqual(tag_map["ManagedBy"], "cloudformation")


if __name__ == "__main__":
    unittest.main()
