// Modified from https://github.com/appliedzkp/semaphore/blob/master/contracts/sol/verifier.sol
pragma experimental ABIEncoderV2;
pragma solidity ^0.5.0;

import "./Pairing.sol";
import "./BN256G2.sol";
import {Constants} from "./Constants.sol";

contract Verifier is Constants {
    using Pairing for *;
    using BN256G2 for *;

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
    Pairing.G2Point SRS_G2_0 = Pairing.G2Point({
        X: [Constants.SRS_G2_X_0[0], Constants.SRS_G2_X_1[0]],
        Y: [Constants.SRS_G2_Y_0[0], Constants.SRS_G2_Y_1[0]]
    });

    Pairing.G2Point SRS_G2_1 = Pairing.G2Point({
        X: [Constants.SRS_G2_X_0[1], Constants.SRS_G2_X_1[1]],
        Y: [Constants.SRS_G2_Y_0[1], Constants.SRS_G2_Y_1[1]]
    });

    function verify(
        Pairing.G2Point memory _commitment,
        Pairing.G1Point memory _proof,
        uint256 _index,
        Pairing.G1Point memory _value,
        Pairing.G1Point memory _pk
    ) public view returns (bool) {
        // Make sure each parameter is less than the prime q
        require(
            _proof.X < BABYJUB_P,
            "Verifier.verifyKZG: _proof.X is out of range"
        );
        require(
            _proof.Y < BABYJUB_P,
            "Verifier.verifyKZG: _proof.Y is out of range"
        );
        require(
            _value.X < BABYJUB_P,
            "Verifier.verifyKZG: _value.X is out of range"
        );
        require(
            _value.Y < BABYJUB_P,
            "Verifier.verifyKZG: _value.Y is out of range"
        );
        require(
            _pk.X < BABYJUB_P,
            "Verifier.verifyKZG: _pk.X is out of range"
        );
        require(
            _pk.Y < BABYJUB_P,
            "Verifier.verifyKZG: _pk.Y is out of range"
        );
        require(
            _commitment.X[0] < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.X0 is out of range"
        );
        require(
            _commitment.X[1] < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.X1 is out of range"
        );
        require(
            _commitment.Y[0] < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.Y0 is out of range"
        );
        require(
            _commitment.Y[1] < BABYJUB_P,
            "Verifier.verifyKZG: _commitment.Y1 is out of range"
        );
        require(
            _index < BABYJUB_P,
            "Verifier.verifyKZG: _index is out of range"
        );

        // Compute g2r
        uint256 g2rx1;
        uint256 g2rx2;
        uint256 g2ry1;
        uint256 g2ry2;
        (g2rx1, g2rx2, g2ry1, g2ry2) = BN256G2.ECTwistMul(_index, SRS_G2_0.X[1], SRS_G2_0.X[0], SRS_G2_0.Y[1], SRS_G2_0.Y[0]);
        // g2rx2 = 10191129150170504690859455063377241352678147020731325090942140630855943625622;
        // g2rx1 = 12345624066896925082600651626583520268054356403303305150512393106955803260718;
        // g2ry2 = 16727484375212017249697795760885267597317766655549468217180521378213906474374;
        // g2ry1 = 13790151551682513054696583104432356791070435696840691503641536676885931241944;
        Pairing.G2Point memory g2r = Pairing.G2Point({
            X: [g2rx2, g2rx1],
            Y: [g2ry2, g2ry1]
        });

        // require(g2rx1 == 10191129150170504690859455063377241352678147020731325090942140630855943625622, uint2str(g2rx1));
        // require(g2rx2 == 12345624066896925082600651626583520268054356403303305150512393106955803260718, uint2str(g2rx2));
        // require(g2ry1 == 16727484375212017249697795760885267597317766655549468217180521378213906474374, uint2str(g2ry1));
        // require(g2ry2 == 13790151551682513054696583104432356791070435696840691503641536676885931241944, uint2str(g2ry2));

        // Negate the value
        Pairing.G1Point memory negValue = Pairing.negate(_value);

        Pairing.G1Point memory negProof = Pairing.negate(_proof);

        // Returns true if and only if
        // e(commitment, pk) * e(proof, g2r) * e(-proof, g2Alpha) * e(-value, g2) == 1
        return
            pairing2(
                _pk,
                _commitment,
                _proof,
                g2r,
                negProof,
                SRS_G2_1,
                negValue,
                SRS_G2_0
            );
            // true;
    }

    function pairing2(
        Pairing.G1Point memory a1,
        Pairing.G2Point memory a2,
        Pairing.G1Point memory b1,
        Pairing.G2Point memory b2,
        Pairing.G1Point memory c1,
        Pairing.G2Point memory c2,
        Pairing.G1Point memory d1,
        Pairing.G2Point memory d2
    ) internal view returns (bool) {
        Pairing.G1Point[4] memory p1 = [a1, b1, c1, d1];
        Pairing.G2Point[4] memory p2 = [a2, b2, c2, d2];

        uint256 inputSize = 24;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 4; i++) {
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
                    // require(success, "pairing-opcode-failed")
                    invalid()
                }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }

    function verifyBenchmark(
        Pairing.G2Point memory _commitment,
        Pairing.G1Point memory _proof,
        uint256 _index,
        Pairing.G1Point memory _value,
        Pairing.G1Point memory _pk
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

    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (_i != 0) {
            bstr[k--] = byte(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }
}
