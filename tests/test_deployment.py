from __future__ import annotations

import json
import unittest
from pathlib import Path


class DeploymentArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(
            Path("deploy/ec2-tokyo/cloudformation.json").read_text(encoding="utf-8")
        )
        self.instance = self.template["Resources"]["AgentSecurityInstance"]["Properties"]
        self.security_group = self.template["Resources"]["InstanceSecurityGroup"][
            "Properties"
        ]

    def test_instance_has_no_public_ip_or_inbound_rules(self) -> None:
        interface = self.instance["NetworkInterfaces"][0]

        self.assertFalse(interface["AssociatePublicIpAddress"])
        self.assertNotIn("SecurityGroupIngress", self.security_group)
        self.assertEqual(
            self.security_group["SecurityGroupEgress"],
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "CidrIp": "0.0.0.0/0",
                    "Description": "HTTPS egress; use VPC endpoints and egress proxy for production",
                }
            ],
        )

    def test_imdsv2_encryption_and_ssm_are_required(self) -> None:
        metadata = self.instance["MetadataOptions"]
        volume = self.instance["BlockDeviceMappings"][0]["Ebs"]
        role = self.template["Resources"]["InstanceRole"]["Properties"]

        self.assertEqual(metadata["HttpTokens"], "required")
        self.assertEqual(metadata["HttpPutResponseHopLimit"], 2)
        self.assertTrue(volume["Encrypted"])
        self.assertIn(
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            role["ManagedPolicyArns"],
        )

    def test_bootstrap_uses_scoped_secret_name_and_hardened_container(self) -> None:
        user_data = self.instance["UserData"]["Fn::Base64"]["Fn::Sub"]
        role = self.template["Resources"]["InstanceRole"]["Properties"]
        statements = role["Policies"][0]["PolicyDocument"]["Statement"]
        secret_read = next(item for item in statements if item["Sid"] == "ReadOneRuntimeSecret")

        self.assertIn("${RuntimeSecretName}", user_data)
        self.assertEqual(
            secret_read["Resource"]["Fn::Sub"],
            "arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:${RuntimeSecretName}-??????",
        )
        self.assertIn("chmod 0600", user_data)
        self.assertIn("--read-only", user_data)
        self.assertIn("--cap-drop=ALL", user_data)
        self.assertIn("127.0.0.1:8080:8080", user_data)
        self.assertNotIn("OPENAI_API_KEY=", user_data)
        self.assertNotIn("ANTHROPIC_API_KEY=", user_data)

    def test_documented_deployment_region_is_tokyo(self) -> None:
        documentation = Path("deploy/ec2-tokyo/README.md").read_text(encoding="utf-8")

        self.assertIn("ap-northeast-1", documentation)
        self.assertIn("billable", documentation)

    def test_container_runs_as_non_root_with_healthcheck(self) -> None:
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

        self.assertIn("FROM ${PYTHON_IMAGE}", dockerfile)
        self.assertIn("apk upgrade --no-cache", dockerfile)
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertIn("HEALTHCHECK", dockerfile)
        self.assertIn('CMD ["serve"', dockerfile)
        self.assertIn("requirements.lock", dockerfile)
        self.assertIn("--no-deps .", dockerfile)

    def test_compose_and_service_use_same_ingest_token_contract(self) -> None:
        compose = Path("deploy/ec2-tokyo/compose.yaml").read_text(encoding="utf-8")
        env_example = Path("deploy/ec2-tokyo/.env.example").read_text(
            encoding="utf-8"
        )

        self.assertIn("AGENTSEC_INGEST_TOKEN", compose)
        self.assertIn("AGENTSEC_INGEST_TOKEN", env_example)
        self.assertNotIn("AGENTSEC_SERVICE_TOKEN", compose)


if __name__ == "__main__":
    unittest.main()
