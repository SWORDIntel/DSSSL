#!/usr/bin/env python3
"""
DSWycheproof Enhanced Test Vector Parser for ML-DSA

This tool parses Wycheproof ML-DSA test vectors (version 1) and converts them to
OpenSSL EVP test format. It leverages DSWycheproof infrastructure for:
- Device 15 (CRYPTO): Core cryptographic testing
- Device 47 (AI): Advanced failure analysis
- Device 46 (QUANTUM): Edge-case discovery (future)

Supported Algorithms:
- ML-DSA-44, ML-DSA-65, ML-DSA-87

Test Types:
- Sign tests (generation)
- Verify tests (verification)

Test vectors can be obtained from:
https://github.com/C2SP/wycheproof/tree/main/testvectors_v1/

Usage Examples:
    Parse ML-DSA-44 sign tests:
    python3 dswycheproof_test_parser.py -alg ML-DSA-44 -type sign \\
        ./wycheproof/testvectors_v1/mldsa_44_standard_sign_test.json

    Parse all ML-DSA-65 tests:
    python3 dswycheproof_test_parser.py -alg ML-DSA-65 \\
        ./wycheproof/testvectors_v1/mldsa_65_*.json

    Generate OpenSSL test data:
    python3 dswycheproof_test_parser.py -alg ML-DSA-44 -type sign \\
        ./wycheproof/testvectors_v1/mldsa_44_standard_sign_test.json > \\
        test/recipes/30-test_evp_data/evppkey_ml_dsa_44_wycheproof_sign.txt
"""

import json
import argparse
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "providers"))

try:
    from dswycheproof_integration import (
        DSWycheproofIntegration,
        MLDSATestVectorConverter,
        is_dswycheproof_available
    )
    HAS_INTEGRATION = True
except ImportError:
    HAS_INTEGRATION = False


class MLDSATestVectorParser:
    """Enhanced parser for ML-DSA Wycheproof test vectors."""

    ALGORITHMS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
    TEST_TYPES = ['sign', 'verify', 'both']

    def __init__(self, use_dsmil: bool = True):
        """
        Initialize parser.

        Args:
            use_dsmil: Whether to use DSWycheproof/DSMIL features
        """
        self.use_dsmil = use_dsmil and HAS_INTEGRATION
        self.converter = MLDSATestVectorConverter() if HAS_INTEGRATION else None

    def validate_algorithm(self, algorithm: str) -> bool:
        """Check if algorithm is supported."""
        return algorithm in self.ALGORITHMS

    def validate_test_type(self, test_type: str) -> bool:
        """Check if test type is supported."""
        return test_type in self.TEST_TYPES

    def load_test_vectors(self, json_file: str) -> Optional[Dict[str, Any]]:
        """
        Load and parse a Wycheproof test vector JSON file.

        Args:
            json_file: Path to JSON test vector file

        Returns:
            Parsed JSON data or None if error
        """
        try:
            with open(json_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading {json_file}: {e}", file=sys.stderr)
            return None

    def parse_ml_dsa_sign(self, algorithm: str, test_data: Dict[str, Any]) -> str:
        """
        Parse ML-DSA signature generation (sign) tests.

        Args:
            algorithm: Algorithm name
            test_data: Parsed test vector data

        Returns:
            Formatted test data
        """
        output_lines = []

        # Use DSWycheproof converter if available
        if self.converter:
            try:
                return self.converter.convert_test_vector(test_data, algorithm, 'sign')
            except Exception as e:
                print(f"Warning: DSWycheproof converter failed: {e}", file=sys.stderr)

        # Fallback implementation
        name = algorithm.replace('-', '_')
        output_lines.append(f"# {algorithm} Signature Generation Tests")
        output_lines.append(f"# https://github.com/C2SP/wycheproof")

        grpId = 1
        for grp in test_data.get('testGroups', []):
            keyOnly = False
            first = True
            keyname = f"{name}_{grpId}"
            grpId += 1

            for tst in grp.get('tests', []):
                # Check if this is a key-only test
                if first:
                    first = False
                    if 'flags' in tst:
                        if 'IncorrectPrivateKeyLength' in tst['flags'] or 'InvalidPrivateKey' in tst['flags']:
                            keyOnly = True

                    if not keyOnly:
                        output_lines.append("")
                        output_lines.append(f"PrivateKeyRaw = {keyname}:{algorithm}:{grp.get('privateKey', '')}")

                # Output test case
                output_lines.append(f"\n# {tst.get('tcId', 0)} {tst.get('comment', '')}")
                output_lines.append("FIPSversion = >=3.5.0")

                if keyOnly:
                    output_lines.append("KeyFromData = " + algorithm)
                    output_lines.append(f"Ctrl = hexpriv:{grp.get('privateKey', '')}")
                    output_lines.append("Result = KEY_FROMDATA_ERROR")
                else:
                    output_lines.append(f"Sign-Message = {algorithm}:{keyname}")
                    output_lines.append(f"Input = {tst.get('msg', '')}")
                    output_lines.append(f"Output = {tst.get('sig', '')}")

                    if 'ctx' in tst:
                        output_lines.append(f"Ctrl = hexcontext-string:{tst['ctx']}")

                    output_lines.append("Ctrl = message-encoding:1")
                    output_lines.append("Ctrl = deterministic:1")

                    if tst.get('result') == 'invalid':
                        output_lines.append("Result = PKEY_CTRL_ERROR")

        return '\n'.join(output_lines)

    def parse_ml_dsa_verify(self, algorithm: str, test_data: Dict[str, Any]) -> str:
        """
        Parse ML-DSA signature verification (verify) tests.

        Args:
            algorithm: Algorithm name
            test_data: Parsed test vector data

        Returns:
            Formatted test data
        """
        output_lines = []

        # Use DSWycheproof converter if available
        if self.converter:
            try:
                return self.converter.convert_test_vector(test_data, algorithm, 'verify')
            except Exception as e:
                print(f"Warning: DSWycheproof converter failed: {e}", file=sys.stderr)

        # Fallback implementation
        name = algorithm.replace('-', '_')
        output_lines.append(f"# {algorithm} Signature Verification Tests")
        output_lines.append(f"# https://github.com/C2SP/wycheproof")

        grpId = 1
        for grp in test_data.get('testGroups', []):
            first = True
            keyname = f"{name}_{grpId}"
            grpId += 1

            for tst in grp.get('tests', []):
                if first:
                    first = False
                    if 'publicKey' in grp:
                        output_lines.append(f"\nPublicKeyRaw = {keyname}:{algorithm}:{grp.get('publicKey', '')}")

                output_lines.append(f"\n# {tst.get('tcId', 0)} {tst.get('comment', '')}")
                output_lines.append("FIPSversion = >=3.5.0")
                output_lines.append(f"Verify-Message = {algorithm}:{keyname}")
                output_lines.append(f"Input = {tst.get('msg', '')}")
                output_lines.append(f"Output = {tst.get('sig', '')}")

                if tst.get('result') == 'valid':
                    output_lines.append("Result = PASS")
                else:
                    output_lines.append("Result = FAIL")

        return '\n'.join(output_lines)

    def parse(self, algorithm: str, test_type: str, test_data: Dict[str, Any]) -> str:
        """
        Parse test vectors and return formatted output.

        Args:
            algorithm: Algorithm name
            test_type: Type of test ('sign', 'verify', or 'both')
            test_data: Parsed test vector data

        Returns:
            Formatted test data
        """
        output_parts = []

        if not self.validate_algorithm(algorithm):
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        if test_type == 'sign' or test_type == 'both':
            output_parts.append(self.parse_ml_dsa_sign(algorithm, test_data))

        if test_type == 'verify' or test_type == 'both':
            output_parts.append(self.parse_ml_dsa_verify(algorithm, test_data))

        return '\n\n'.join(output_parts)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Wycheproof ML-DSA test vectors for OpenSSL EVP tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('-alg', '--algorithm',
                       type=str, required=True,
                       choices=['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
                       help='Algorithm name')

    parser.add_argument('-type', '--test-type',
                       type=str, default='both',
                       choices=['sign', 'verify', 'both'],
                       help='Test type (sign, verify, or both)')

    parser.add_argument('--no-dsmil', action='store_true',
                       help='Disable DSWycheproof/DSMIL features')

    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    parser.add_argument('test_vector_files',
                       nargs='+',
                       help='Path(s) to Wycheproof test vector JSON files')

    args = parser.parse_args()

    # Check DSWycheproof availability
    if not args.no_dsmil:
        available, message = is_dswycheproof_available()
        if args.verbose:
            print(f"DSWycheproof Status: {message}", file=sys.stderr)

    # Create parser
    test_parser = MLDSATestVectorParser(use_dsmil=not args.no_dsmil)

    # Process each test vector file
    all_output = []
    for test_file in args.test_vector_files:
        if args.verbose:
            print(f"Processing: {test_file}", file=sys.stderr)

        test_data = test_parser.load_test_vectors(test_file)
        if test_data is None:
            sys.exit(1)

        try:
            output = test_parser.parse(args.algorithm, args.test_type, test_data)
            all_output.append(output)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    # Output combined results
    print('\n\n'.join(all_output))


if __name__ == "__main__":
    main()
