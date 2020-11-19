// Modified from https://github.com/appliedzkp/semaphore/blob/master/contracts/sol/verifier.sol
pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

import "./Pairing.sol";
import {Constants} from "./Constants.sol";

contract Verifier is Constants {
    using Pairing for *;

    // The G1 generator
    Pairing.G1Point SRS_G1_0 = Pairing.G1Point({
        X: Constants.SRS_G1_X[0],
        Y: Constants.SRS_G1_Y[0]
    });
    Pairing.G1Point SRS_G1_1 = Pairing.G1Point({
        X: Constants.SRS_G1_X[1],
        Y: Constants.SRS_G1_Y[1]
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
        Pairing.G2Point memory _proof,
        uint256 _index,
        Pairing.G2Point memory _value,
        Pairing.G2Point memory _pk
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
            _proof.X[0] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X0 is out of range"
        );
        require(
            _proof.X[1] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X1 is out of range"
        );
        require(
            _proof.Y[0] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y0 is out of range"
        );
        require(
            _proof.Y[1] < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y1 is out of range"
        );
        require(
            _index < BABYJUB_P,
            "Verifier.verifyKZG: _index is out of range"
        );
        require(
            _value.X[0] < BABYJUB_P,
            "Verifier.verifyKZG: _value.X0 is out of range"
        );
        require(
            _value.X[1] < BABYJUB_P,
            "Verifier.verifyKZG: _value.X1 is out of range"
        );
        require(
            _value.Y[0] < BABYJUB_P,
            "Verifier.verifyKZG: _value.Y0 is out of range"
        );
        require(
            _value.Y[1] < BABYJUB_P,
            "Verifier.verifyKZG: _value.Y1 is out of range"
        );
        require(
            _pk.X[0] < BABYJUB_P,
            "Verifier.verifyKZG: _pk.X0 is out of range"
        );
        require(
            _pk.X[1] < BABYJUB_P,
            "Verifier.verifyKZG: _pk.X1 is out of range"
        );
        require(
            _pk.Y[0] < BABYJUB_P,
            "Verifier.verifyKZG: _pk.Y0 is out of range"
        );
        require(
            _pk.Y[1] < BABYJUB_P,
            "Verifier.verifyKZG: _pk.Y1 is out of range"
        );

        // Compute g1r - g1Aplha
        Pairing.G1Point memory g1rMinusG1Alpha = Pairing.plus(
            Pairing.mulScalar(SRS_G1_0, _index),
            Pairing.negate(SRS_G1_1)
        );

        // Negate the g1
        Pairing.G1Point memory negG1Generator = Pairing.negate(SRS_G1_0);

        // Returns true if and only if
        // e(commitment, pk) * e(proof, g1r - g1Alpha) * e(value, -g1) == 1
        return
            pairing2(
                _commitment,
                _pk,
                g1rMinusG1Alpha,
                _proof,
                negG1Generator,
                _value
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

    function verifyBenchmark(
        Pairing.G1Point memory _commitment,
        Pairing.G2Point memory _proof,
        uint256 _index,
        Pairing.G2Point memory _value,
        Pairing.G2Point memory _pk
    ) public {
        verify(_commitment, _proof, _index, _value, _pk);
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
