// Modified from https://github.com/appliedzkp/semaphore/blob/master/contracts/sol/verifier.sol
pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

import "./Pairing.sol";
import {Constants} from "./Constants.sol";

contract Verifier2 is Constants {
    using Pairing for *;

    // The G1 generator
    Pairing.G1Point SRS_G1_0 = Pairing.G1Point({
        X: Constants.SRS_G1_X[0],
        Y: Constants.SRS_G1_Y[0]
    });

    // The G2 generator
    Pairing.G2Point g2Generator = Pairing.G2Point({
        X: [Constants.SRS_G2_X_0[0], Constants.SRS_G2_X_1[0]],
        Y: [Constants.SRS_G2_Y_0[0], Constants.SRS_G2_Y_1[0]]
    });

    Pairing.G2Point SRS_G2_1 = Pairing.G2Point({
        X: [Constants.SRS_G2_X_0[1], Constants.SRS_G2_X_1[1]],
        Y: [Constants.SRS_G2_Y_0[1], Constants.SRS_G2_Y_1[1]]
    });

    function verify(
        Pairing.G1Point memory _commitment,
        Pairing.G1Point memory _proof,
        uint256 _index,
        Pairing.G1Point memory _value,
        Pairing.G2Point memory _pk2
    ) public view returns (bool) {
        // Make sure each parameter is less than the prime q
        require(
            _commitment.X < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.X is out of range"
        );
        require(
            _commitment.Y < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.Y is out of range"
        );
        require(
            _proof.X < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X is out of range"
        );
        require(
            _proof.Y < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y is out of range"
        );
        require(
            _index < BABYJUB_P,
            "Verifier.verifyKZG: _index is out of range"
        );
        require(
            _value.X < BABYJUB_P,
            "Verifier.verifyKZG: _value.X is out of range"
        );
        require(
            _value.Y < BABYJUB_P,
            "Verifier.verifyKZG: _value.Y is out of range"
        );

        // Compute proof * index - value
        Pairing.G1Point memory proofMulIndexMinusValue = Pairing.plus(
            Pairing.mulScalar(_proof, _index),
            Pairing.negate(_value)
        );

        // Negate the proof
        Pairing.G1Point memory negProof = Pairing.negate(_proof);

        // Returns true if and only if
        // e(commitment, pk2) * e(-proof, g2^\alpha) * e((proof * index - value), g2) == 1
        return
            pairing2(
                _commitment,
                _pk2,
                negProof,
                SRS_G2_1,
                proofMulIndexMinusValue,
                g2Generator
            );
    }

    function pairing2(
        Pairing.G1Point memory a1,
        Pairing.G2Point memory a2,
        Pairing.G1Point memory b1,
        Pairing.G2Point memory b2,
        Pairing.G1Point memory c1,
        Pairing.G2Point memory c2
    ) internal view returns (bool) {
        Pairing.G1Point[3] memory p1 = [a1, b1, c1];
        Pairing.G2Point[3] memory p2 = [a2, b2, c2];

        uint256 inputSize = 18;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 3; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas, 2000),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
                case 0 {
                    invalid()
                }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }

    /*
     * Verifies the evaluation of multiple points of a polynominal using the
     * KZG commitment scheme.
     *    - p(X) is a polynominal
     *    - commitment = commit(p)
     *    - For each y in _values and each x in _indices, y = p(x)
     *    - proof = genMultiProof(p, _indices)
     * Returns true if and only if the following holds, and returns false
     * otherwise:
     *     e(-commit(zPoly), proof) * e(commitment - commit(iPoly), g) == 1
     * @param _commitment The polynominal commitment.
     * @param _proof The proof.
     * @param _indices The x-values at which to evaluate the polynominal.
     * @param _values The evaluation of the polynominal at each index.
     * @param _iCoeffs The coefficients of a polynominal which interpolates
     *                 each index and corresponding y-value.
     * @param _zCoeffs The coefficients of a polynominal which intersects y=0
     *                 for each index.
     */
    function verifyMulti(
        Pairing.G1Point memory _commitment,
        Pairing.G2Point memory _proof,
        uint256[] memory _indices,
        uint256[] memory _values,
        uint256[] memory _iCoeffs,
        uint256[] memory _zCoeffs
    ) public view returns (bool) {
        // Perform range checks
        require(
            _commitment.X < BABYJUB_P,
            "Verifier.verifyMultiKZG: _commitment.X is out of range"
        );
        require(
            _commitment.Y < BABYJUB_P,
            "Verifier.verifyMultiKZG: _commitment.Y is out of range"
        );
        require(
            _proof.X[0] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X[0] is out of range"
        );
        require(
            _proof.X[1] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X[1] is out of range"
        );
        require(
            _proof.Y[0] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y[0] is out of range"
        );
        require(
            _proof.Y[1] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y[1] is out of range"
        );

        for (uint256 i = 0; i < _iCoeffs.length; i++) {
            require(
                _iCoeffs[i] < BABYJUB_P,
                "Verifier.verifyKZG: an _iCoeffs value is out of range"
            );
        }

        for (uint256 i = 0; i < _zCoeffs.length; i++) {
            require(
                _zCoeffs[i] < BABYJUB_P,
                "Verifier.verifyKZG: an _zCoeffs value is out of range"
            );
        }

        // Check whether _iCoeffs and _zCoeffs are valid
        for (uint256 i = 0; i < _indices.length; i++) {
            uint256 index = _indices[i];
            uint256 value = _values[i];
            require(
                index < BABYJUB_P,
                "Verifier.verifyKZG: an index is out of range"
            );
            require(
                value < BABYJUB_P,
                "Verifier.verifyKZG: a value is out of range"
            );

            uint256 zEval = evalPolyAt(_zCoeffs, _indices[i]);
            require(zEval == 0, "Verifier.verifyMulti: invalid _zCoeffs");

            uint256 iEval = evalPolyAt(_iCoeffs, _indices[i]);
            require(
                iEval == _values[i],
                "Verifier.verifyMulti: invalid _iCoeffs"
            );
        }

        // Generate the KZG commitments to the i and z polynominals
        Pairing.G1Point memory zCommit = commit(_zCoeffs);
        Pairing.G1Point memory iCommit = commit(_iCoeffs);

        // Compute commitment - commit(iPoly)
        Pairing.G1Point memory commitmentMinusICommit = Pairing.plus(
            _commitment,
            Pairing.negate(iCommit)
        );

        // Perform the pairing check
        return
            Pairing.pairing(
                Pairing.negate(zCommit),
                _proof,
                commitmentMinusICommit,
                g2Generator
            );
    }

    function verifyMultiBenchmark(
        Pairing.G1Point memory _commitment,
        Pairing.G2Point memory _proof,
        uint256[] memory _indices,
        uint256[] memory _values,
        uint256[] memory _iCoeffs,
        uint256[] memory _zCoeffs
    ) public {
        verifyMulti(_commitment, _proof, _indices, _values, _iCoeffs, _zCoeffs);
    }

    function verifyBenchmark(
        Pairing.G1Point memory _commitment,
        Pairing.G1Point memory _proof,
        uint256 _index,
        Pairing.G1Point memory _value,
        Pairing.G2Point memory _pk2
    ) public {
        verify(_commitment, _proof, _index, _value, _pk2);
    }

    /*
     * @return A KZG commitment to a polynominal
     * @param coefficients The coefficients of the polynomial to which to
     *                     commit.
     */
    function commit(uint256[] memory coefficients)
        public
        view
        returns (Pairing.G1Point memory)
    {
        Pairing.G1Point memory result = Pairing.G1Point(0, 0);

        for (uint256 i = 0; i < coefficients.length; i++) {
            result = Pairing.plus(
                result,
                Pairing.mulScalar(
                    Pairing.G1Point({
                        X: Constants.SRS_G1_X[i],
                        Y: Constants.SRS_G1_Y[i]
                    }),
                    coefficients[i]
                )
            );
        }
        return result;
    }

    /*
     * @return The polynominal evaluation of a polynominal with the specified
     *         coefficients at the given index.
     */
    function evalPolyAt(uint256[] memory _coefficients, uint256 _index)
        public
        pure
        returns (uint256)
    {
        uint256 m = Constants.BABYJUB_P;
        uint256 result = 0;
        uint256 powerOfX = 1;

        for (uint256 i = 0; i < _coefficients.length; i++) {
            uint256 coeff = _coefficients[i];
            assembly {
                result := addmod(result, mulmod(powerOfX, coeff, m), m)
                powerOfX := mulmod(powerOfX, _index, m)
            }
        }
        return result;
    }
}
