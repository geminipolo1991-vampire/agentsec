from __future__ import annotations

import unittest
from unittest.mock import patch

from agentsec.contracts import AiMode
from agentsec.cli import main
from agentsec.runtime import build_pipeline_from_environment


class RuntimeAssemblyTests(unittest.TestCase):
    def test_default_runtime_is_model_independent(self) -> None:
        pipeline = build_pipeline_from_environment({})

        self.assertEqual(pipeline.ai_mode, AiMode.OFF)
        self.assertIsNone(pipeline.reasoner)

    def test_recorded_codex_is_current_shadow_profile(self) -> None:
        pipeline = build_pipeline_from_environment(
            {
                "AGENTSEC_AI_MODE": "shadow",
                "AGENTSEC_MODEL_PROFILE": "codex-recorded-shadow",
            }
        )

        self.assertEqual(pipeline.ai_mode, AiMode.SHADOW)
        self.assertEqual(pipeline.reasoner.provider, "codex")

    def test_disabled_live_profile_uses_declared_codex_fallback(self) -> None:
        pipeline = build_pipeline_from_environment(
            {
                "AGENTSEC_AI_MODE": "shadow",
                "AGENTSEC_MODEL_PROFILE": "openai-api-tokyo",
                "OPENAI_MODEL_ID": "not-activated",
                "OPENAI_API_KEY": "not-used",
            }
        )

        self.assertEqual(pipeline.reasoner.provider, "codex")

    def test_invalid_ai_mode_fails_startup(self) -> None:
        with self.assertRaisesRegex(ValueError, "AI_MODE"):
            build_pipeline_from_environment({"AGENTSEC_AI_MODE": "unsafe-auto"})

    def test_serve_command_assembles_selected_runtime_pipeline(self) -> None:
        environment = {
            "AGENTSEC_INGEST_TOKEN": "runtime-test-token-at-least-thirty-two-characters",
            "AGENTSEC_AI_MODE": "shadow",
            "AGENTSEC_MODEL_PROFILE": "codex-recorded-shadow",
        }
        with patch.dict("os.environ", environment, clear=True), patch(
            "agentsec.cli.serve"
        ) as serve_mock:
            result = main(["serve", "--host", "127.0.0.1", "--port", "18080"])

        self.assertEqual(result, 0)
        application = serve_mock.call_args.kwargs["application"]
        self.assertEqual(application.pipeline.ai_mode, AiMode.SHADOW)
        self.assertEqual(application.pipeline.reasoner.provider, "codex")


if __name__ == "__main__":
    unittest.main()
