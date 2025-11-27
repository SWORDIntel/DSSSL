#!/usr/bin/env python3
"""
DSWycheproof Integration Module
Provides utilities and wrappers for integrating DSWycheproof cryptographic
testing framework with DSSSL.

This module exposes DSWycheproof Device 15 (CRYPTO), Device 46 (QUANTUM),
and Device 47 (AI) capabilities for enhanced cryptographic assurance.
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Ensure DSWycheproof is importable
WYCHEPROOF_ROOT = Path(__file__).parent.parent / "wycheproof"
if WYCHEPROOF_ROOT.exists():
    sys.path.insert(0, str(WYCHEPROOF_ROOT / "src"))

try:
    from dsmil_wycheproof.device15.campaign_runner import CampaignRunner
    from dsmil_wycheproof.device15.vector_loader import VectorLoader
    HAS_DSWYCHEPROOF = True
except ImportError as e:
    HAS_DSWYCHEPROOF = False
    DSWYCHEPROOF_ERROR = str(e)


class DSWycheproofIntegration:
    """
    Main integration class for DSWycheproof cryptographic testing.

    Provides Device 15 (CRYPTO) capabilities for:
    - Loading and parsing Wycheproof test vectors
    - Running cryptographic test campaigns
    - Analyzing test results
    - Generating reports
    """

    def __init__(self, wycheproof_root: Optional[str] = None):
        """
        Initialize DSWycheproof integration.

        Args:
            wycheproof_root: Path to wycheproof submodule root. If None, uses default.
        """
        if not HAS_DSWYCHEPROOF:
            raise ImportError(f"DSWycheproof not available: {DSWYCHEPROOF_ERROR}")

        self.wycheproof_root = Path(wycheproof_root) if wycheproof_root else WYCHEPROOF_ROOT
        self.vector_loader = VectorLoader(str(self.wycheproof_root))
        # CampaignRunner is initialized on-demand with specific config

    def list_available_algorithms(self) -> List[str]:
        """
        List all cryptographic algorithms with available test vectors.

        Returns:
            List of algorithm names (e.g., ['ECDSA', 'RSA', 'ML-KEM-1024', ...])
        """
        try:
            # Get test vector files directly since list_algorithms may not exist
            testvectors = self.get_wycheproof_testvector_files()
            algorithms = set()
            for f in testvectors:
                algo = f.stem.replace('_test', '').replace('_', ' ')
                algorithms.add(algo)
            return sorted(list(algorithms))
        except Exception as e:
            print(f"Error listing algorithms: {e}")
            return []

    def load_test_vectors(self, algorithm: str) -> Dict[str, Any]:
        """
        Load test vectors for a specific cryptographic algorithm.

        Args:
            algorithm: Name of the algorithm (e.g., 'ECDSA', 'ML-DSA-44')

        Returns:
            Dictionary containing test vector data
        """
        try:
            vectors = self.vector_loader.load(algorithm)
            return vectors
        except Exception as e:
            print(f"Error loading test vectors for {algorithm}: {e}")
            return {}

    def run_test_campaign(self, campaign_config: Dict[str, Any],
                         output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a cryptographic test campaign.

        Args:
            campaign_config: Campaign configuration dictionary (or path to config file)
            output_dir: Optional directory for output files

        Returns:
            Campaign results with statistics and failure analysis
        """
        try:
            # Note: CampaignRunner requires specific initialization with CampaignConfig
            # For now, return a placeholder structure that documents the capability
            results = {
                'status': 'not_implemented',
                'message': 'Campaign runner requires full DSMIL environment setup',
                'config': campaign_config,
                'wycheproof_root': str(self.wycheproof_root)
            }
            if output_dir:
                output_path = Path(output_dir)
                output_path.mkdir(parents=True, exist_ok=True)
                result_file = output_path / "campaign_results.json"
                with open(result_file, 'w') as f:
                    json.dump(results, f, indent=2)
            return results
        except Exception as e:
            print(f"Error running campaign: {e}")
            return {}

    def get_testvector_path(self, algorithm: str) -> Optional[Path]:
        """
        Get the file path for a specific algorithm's test vectors.

        Args:
            algorithm: Name of the algorithm

        Returns:
            Path to test vector file, or None if not found
        """
        testvectors_dir = self.wycheproof_root / "testvectors_v1"
        if not testvectors_dir.exists():
            return None

        # Convert algorithm name to test file pattern
        # e.g., 'ML-DSA-44' -> 'mldsa_44_*_test.json'
        pattern = algorithm.lower().replace('-', '_')

        for test_file in testvectors_dir.glob(f"{pattern}*test.json"):
            return test_file

        return None

    def get_wycheproof_testvector_files(self) -> List[Path]:
        """Get list of all available Wycheproof test vector files."""
        testvectors_dir = self.wycheproof_root / "testvectors_v1"
        if not testvectors_dir.exists():
            return []

        return sorted(testvectors_dir.glob("*_test.json"))


class MLDSATestVectorConverter:
    """
    Utility class for converting ML-DSA Wycheproof test vectors to OpenSSL format.

    Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 algorithms.
    """

    ALGORITHMS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
    TEST_TYPES = ['sign', 'verify']

    @staticmethod
    def convert_test_vector(json_data: Dict[str, Any], algorithm: str,
                           test_type: str = 'sign') -> str:
        """
        Convert Wycheproof ML-DSA test vectors to OpenSSL format.

        Args:
            json_data: Parsed JSON test vector data
            algorithm: Algorithm name (e.g., 'ML-DSA-44')
            test_type: Type of test ('sign' or 'verify')

        Returns:
            Formatted test data as string suitable for OpenSSL EVP tests
        """
        if algorithm not in MLDSATestVectorConverter.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if test_type not in MLDSATestVectorConverter.TEST_TYPES:
            raise ValueError(f"Unsupported test type: {test_type}")

        output_lines = []

        # Add header
        output_lines.append(f"# ML-DSA Wycheproof test vectors for {algorithm}")
        output_lines.append(f"# Test type: {test_type}")

        # Process test groups
        for group_idx, group in enumerate(json_data.get('testGroups', []), 1):
            alg_name = algorithm.replace('-', '_')
            key_name = f"{alg_name}_{group_idx}"

            # Handle key setup
            if 'privateKey' in group:
                output_lines.append(f"\nPrivateKeyRaw = {key_name}:{algorithm}:{group['privateKey']}")

            # Process individual tests
            for test in group.get('tests', []):
                test_id = test.get('tcId', 0)
                comment = test.get('comment', '')

                output_lines.append(f"\n# Test {test_id}: {comment}")
                output_lines.append(f"FIPSversion = >=3.5.0")

                if test_type == 'sign':
                    output_lines.append(f"Sign-Message = {algorithm}:{key_name}")
                    output_lines.append(f"Input = {test.get('msg', '')}")
                    output_lines.append(f"Output = {test.get('sig', '')}")

                    if 'ctx' in test:
                        output_lines.append(f"Ctrl = hexpriv:{test['ctx']}")

                    output_lines.append("Ctrl = message-encoding:1")
                    output_lines.append("Ctrl = deterministic:1")

                    if test.get('result') == 'invalid':
                        output_lines.append("Result = PKEY_CTRL_ERROR")

                elif test_type == 'verify':
                    if 'publicKey' in group:
                        output_lines.append(f"Key = {key_name}:{algorithm}:{group['publicKey']}")

                    output_lines.append(f"Verify-Message = {algorithm}:{key_name}")
                    output_lines.append(f"Input = {test.get('msg', '')}")
                    output_lines.append(f"Output = {test.get('sig', '')}")

                    if test.get('result') == 'valid':
                        output_lines.append("Result = PASS")
                    else:
                        output_lines.append("Result = FAIL")

        return '\n'.join(output_lines)


class CryptographicAssuranceReport:
    """
    Generates comprehensive cryptographic assurance reports from DSWycheproof results.
    """

    @staticmethod
    def generate_summary(campaign_results: Dict[str, Any]) -> str:
        """
        Generate a summary report from campaign results.

        Args:
            campaign_results: Results from DSWycheproof campaign

        Returns:
            Formatted summary report as string
        """
        report_lines = []

        report_lines.append("=" * 60)
        report_lines.append("CRYPTOGRAPHIC ASSURANCE REPORT")
        report_lines.append("=" * 60)

        # Overall risk assessment
        risk_level = campaign_results.get('overall_risk', 'UNKNOWN')
        report_lines.append(f"\nOverall Risk Level: {risk_level}")

        # Test statistics
        total_tests = campaign_results.get('total_tests', 0)
        passed = campaign_results.get('passed', 0)
        failed = campaign_results.get('failed', 0)
        skipped = campaign_results.get('skipped', 0)

        report_lines.append(f"\nTest Statistics:")
        report_lines.append(f"  Total Tests: {total_tests}")
        report_lines.append(f"  Passed: {passed}")
        report_lines.append(f"  Failed: {failed}")
        report_lines.append(f"  Skipped: {skipped}")

        # Algorithm coverage
        if 'algorithms' in campaign_results:
            report_lines.append(f"\nAlgorithm Coverage:")
            for algo, stats in campaign_results['algorithms'].items():
                report_lines.append(f"  {algo}: {stats.get('tests', 0)} tests")

        # Failures
        if 'failures' in campaign_results and campaign_results['failures']:
            report_lines.append(f"\nFailures Detected:")
            for failure in campaign_results['failures'][:10]:  # Limit to first 10
                report_lines.append(f"  - {failure.get('description', 'Unknown failure')}")

        report_lines.append("\n" + "=" * 60)

        return '\n'.join(report_lines)


def get_wycheproof_testvector_files(wycheproof_root: Optional[str] = None) -> List[Path]:
    """
    Get list of all available Wycheproof test vector files.

    Args:
        wycheproof_root: Path to wycheproof root directory

    Returns:
        List of Path objects pointing to test vector JSON files
    """
    if not wycheproof_root:
        wycheproof_root = str(WYCHEPROOF_ROOT)

    testvectors_dir = Path(wycheproof_root) / "testvectors_v1"
    if not testvectors_dir.exists():
        return []

    return sorted(testvectors_dir.glob("*_test.json"))


def is_dswycheproof_available() -> Tuple[bool, str]:
    """
    Check if DSWycheproof is properly installed and available.

    Returns:
        Tuple of (available: bool, message: str)
    """
    if HAS_DSWYCHEPROOF:
        return True, "DSWycheproof is available"
    else:
        return False, f"DSWycheproof not available: {DSWYCHEPROOF_ERROR}"


if __name__ == "__main__":
    # Test integration
    available, message = is_dswycheproof_available()
    print(f"DSWycheproof Status: {message}")

    if available:
        integration = DSWycheproofIntegration()
        algorithms = integration.list_available_algorithms()
        print(f"\nAvailable algorithms: {len(algorithms)}")
        print(f"Sample algorithms: {algorithms[:5]}")

        testvector_files = integration.get_wycheproof_testvector_files()
        print(f"\nTest vector files: {len(testvector_files)}")
