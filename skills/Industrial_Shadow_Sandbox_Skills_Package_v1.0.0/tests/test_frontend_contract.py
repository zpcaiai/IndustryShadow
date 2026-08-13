from __future__ import annotations

import unittest

from shadow_sandbox.api.router import API_ROUTE_CONTRACT

from tools.generate_frontend_client import TARGET, render


class FrontendContractTests(unittest.TestCase):
    def test_generated_route_client_is_current_and_complete(self) -> None:
        self.assertEqual(render(), TARGET.read_text(encoding="utf-8"))
        generated = render()
        self.assertIn(f"API_ROUTE_COUNT = {len(API_ROUTE_CONTRACT)}", generated)
        self.assertIn('export type GetPath =', generated)
        self.assertIn('export type PostPath =', generated)
        self.assertIn('export type PatchPath =', generated)
        self.assertIn('"/auth/config"', generated)


if __name__ == "__main__":
    unittest.main()
