require('module-alias/register')
import * as assert from 'assert'
import * as galois from '@guildofweavers/galois'
import * as bn128 from 'rustbn.js'
import * as ffjavascript from 'ffjavascript'
import { ec } from 'elliptic'

type G1Point = ec
type G2Point = ec
type Coefficient = bigint
type Polynomial = Coefficient[]
type Commitment = G2Point
type Proof = G1Point
type MultiProof = G2Point

interface PairingInputs {
    G1: G1Point;
    G2: G2Point;
}

// The number of G1 points from the SRS stored in Constants.sol
const MAX_G1_SOL_POINTS = 128

const G1 = ffjavascript.bn128.G1
const G2 = ffjavascript.bn128.G2

const FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617')

const genBabyJubField = () => {
    return galois.createPrimeField(FIELD_SIZE)
}

const srsg1DataRaw = require('@libkzg/taug1_65536.json')
const srsg2DataRaw = require('@libkzg/taug2_65536.json')

const getPKInG1 = (sk: BigInt): G1Point => {
    return G1.affine(G1.mulScalar(srsG1(1)[0], sk))
}

const getPKInG2 = (sk: BigInt): G2Point => {
    return G2.affine(G2.mulScalar(srsG2(1)[0], sk))
}

/*
 * @return Up to 65536 G1 values of the structured reference string.
 * These values were taken from challenge file #46 of the Perpetual Powers of
 * Tau ceremony. The Blake2b hash of challenge file is:
 *
 * 939038cd 2dc5a1c0 20f368d2 bfad8686 
 * 950fdf7e c2d2e192 a7d59509 3068816b
 * becd914b a293dd8a cb6d18c7 b5116b66 
 * ea54d915 d47a89cc fbe2d5a3 444dfbed
 *
 * The challenge file can be retrieved at:
 * https://ppot.blob.core.windows.net/public/challenge_0046
 *
 * The ceremony transcript can be retrieved at:
 * https://github.com/weijiekoh/perpetualpowersoftau
 *
 * Anyone can verify the transcript to ensure that the values in the challenge
 * file have not been tampered with. Moreover, as long as one participant in
 * the ceremony has discarded their toxic waste, the whole ceremony is secure.
 * Please read the following for more information:
 * https://medium.com/coinmonks/announcing-the-perpetual-powers-of-tau-ceremony-to-benefit-all-zk-snark-projects-c3da86af8377
 */
const srsG1 = (depth: number): G1Point[] => {
    assert(depth > 0)
    assert(depth <= 65536)

    const g1: G1Point[] = []
    for (let i = 0; i < depth; i++) {
        g1.push([
            BigInt(srsg1DataRaw[i][0]),
            BigInt(srsg1DataRaw[i][1]),
            BigInt(1),
        ])
    }

    assert(g1[0][0] === G1.g[0])
    assert(g1[0][1] === G1.g[1])
    assert(g1[0][2] === G1.g[2])

    return g1
}

/*
 * @return Up to 65536 G2 values of the structured reference string.
 * They were taken from challenge file #46 of the Perpetual Powers of
 * Tau ceremony as described above.
 */
const srsG2 = (depth: number): G2Point[] => {
    assert(depth > 0)
    assert(depth <= 65536)

    const g2: G2Point[] = []
    for (let i = 0; i < depth; i++) {
        g2.push([
            [srsg2DataRaw[i][0], srsg2DataRaw[i][1]].map(BigInt),
            [srsg2DataRaw[i][2], srsg2DataRaw[i][3]].map(BigInt),
            [BigInt(1), BigInt(0)],
        ])
    }
    assert(g2[0][0][0] === G2.g[0][0])
    assert(g2[0][0][1] === G2.g[0][1])
    assert(g2[0][1][0] === G2.g[1][0])
    assert(g2[0][1][1] === G2.g[1][1])
    assert(g2[0][2][0] === G2.g[2][0])
    assert(g2[0][2][1] === G2.g[2][1])

    return g2
}

/*
 * @return A KZG commitment to a polynomial.
 * @param coefficients The coefficients of the polynomial to commit. To
 *        generate these coefficients from arbitary values, use
 *        genCoefficients().
 * @param p The field size. Defaults to the BabyJub field size.
 */
const commit = (
    coefficients: bigint[],
): Commitment => {
    const srs = srsG1(coefficients.length)
    return polyCommit(coefficients, G1, srs)
}

const commit2 = (
    coefficients: bigint[],
    srs: G1Point[]
): Commitment => {
    return polyCommit(coefficients, G1, srs)
}

const polyCommit = (
    coefficients: bigint[],
    G: G1Point | G2Point,
    srs: G1Point[] | G2Point[],
): G1Point | G2Point => {
    let result = G.zero
    for (let i = 0; i < coefficients.length; i++) {
        let coeff = BigInt(coefficients[i])
        assert(coeff >= BigInt(0))

        result = G.affine(G.add(result, G.mulScalar(srs[i], coeff)))

        //if (coeff < 0) {
        //coeff = BigInt(-1) * coeff
        //result = G.affine(G.add(result, G.neg(G.mulScalar(srs[i], coeff))))
        //} else {
        //result = G.affine(G.add(result, G.mulScalar(srs[i], coeff)))
        //}
    }

    return result
}

/*
 * @return A the coefficients to the quotient polynomial used to generate a
 *         KZG proof.
 * @param coefficients The coefficients of the polynomial.
 * @param xVal The x-value for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genQuotientPolynomial = (
    coefficients: Coefficient[],
    xVal: bigint,
    p: bigint = FIELD_SIZE,
): Coefficient[] => {
    const field = galois.createPrimeField(p)
    const poly = field.newVectorFrom(coefficients)

    const yVal = field.evalPolyAt(poly, xVal)
    const y = field.newVectorFrom([yVal])

    const x = field.newVectorFrom([0, 1].map(BigInt))

    const z = field.newVectorFrom([xVal].map(BigInt))

    return field.divPolys(
        field.subPolys(poly, y),
        field.subPolys(x, z),
    ).toValues()
}

/*
 * @return A KZG commitment proof of evaluation at a single point.
 * @param coefficients The coefficients of the polynomial associated with the
 *                     KZG commitment.
 * @param index The x-value for the polynomial evaluation proof.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genProof = (
    coefficients: Coefficient[],
    index: number | bigint,
    srs: G1Point[],
    p: bigint = FIELD_SIZE,
): Proof => {
    const quotient = genQuotientPolynomial(coefficients, BigInt(index), p)
    return polyCommit(quotient, G1, srs)
}

const verifyViaEIP197 = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: G1Point,
    pk: G1Point,
) => {
    const g2Alpha = srsG2(2)[1]
    const g2r = G2.affine(G2.mulScalar(G2.g, index))

    // const inputs = [
    //     {
    //         G2: commitment,
    //         G1: pk,
    //     },
    //     {
    //         G2: G2.affine(G2.sub(g2r, g2Alpha)),
    //         G1: G1.affine(proof),
    //     },
    //     {
    //         G2: G2.affine(G2.neg(G2.g)),
    //         G1: value,
    //     },
    // ]
    const inputs = [
        {
            G2: commitment,
            G1: pk,
        },
        {
            G2: G2.affine(g2r),
            G1: proof,
        },
        {
            G2: G2.affine(g2Alpha),
            G1: G1.affine(G1.neg(proof)),
        },
        {
            G2: G2.g,
            G1: G1.affine(G1.neg(value)),
        },
    ]

    return isValidPairing(inputs)
}

const genVerifierContractParams = (
    commitment: Commitment,
    proof: Proof,
    index: number | bigint,
    value: G1Point,
    pk: G1Point
) => {
    return {
        commitment: [
            [
                '0x' + commitment[0][1].toString(16),
                '0x' + commitment[0][0].toString(16),
            ],
            [
                '0x' + commitment[1][1].toString(16),
                '0x' + commitment[1][0].toString(16),
            ]
        ],
        proof: [
            '0x' + proof[0].toString(16),
            '0x' + proof[1].toString(16),
        ],
        index: '0x' + BigInt(index).toString(16),
        value: [
            '0x' + value[0].toString(16),
            '0x' + value[1].toString(16),
        ],
        pk: [
            '0x' + pk[0].toString(16),
            '0x' + pk[1].toString(16),
        ]
    }
}

/*
 * @return The coefficient to a polynomial which intersects the points (0,
 *         values[0]) ... (n, values[n]). Each value must be less than
 *         FIELD_SIZE. Likewise, each resulting coefficient will be less than
 *         FIELD_SIZE. This is because all operations in this function work in
 *         a finite field of prime order p = FIELD_SIZE. The output of this
 *         function can be fed into commit() to produce a KZG polynomial
 *         commitment to said polynomial.
 * @param values The values to interpolate.
 * @param p The field size. Defaults to the BabyJub field size.
 */
const genCoefficients = (
    values: bigint[],
    p: bigint = FIELD_SIZE,
): Coefficient[] => {
    // Check the inputs
    for (let value of values) {
        assert(typeof (value) === 'bigint')
        assert(value < FIELD_SIZE)
    }

    // Perform the interpolation
    const field = galois.createPrimeField(p)
    const x: bigint[] = []
    for (let i = 0; i < values.length; i++) {
        x.push(BigInt(i))
    }
    const xVals = field.newVectorFrom(x)
    const yVals = field.newVectorFrom(values)
    const coefficients = field.interpolate(xVals, yVals).toValues()

    // Check the outputs
    for (let coefficient of coefficients) {
        assert(coefficient < FIELD_SIZE)
    }
    return coefficients
}

/*
 * @return The hexadecimal representation of a value, padded to have 64
 *         characters. Does not add the 0x prefix.
 */
const hexify = (value: bigint) => {
    const p = value.toString(16)
    assert(p.length <= 64)
    return p.padStart(64, '0')
}

/*
 * Performs a pairing check in the style of EIP-197.
 * See: https://eips.ethereum.org/EIPS/eip-197
 * @return True if a EIP-197 style pairing check is valid, and false otherwise.
 * @param inputs An array of PairingInputs such that
 * input[0] * input[1] * ... * input[n] = 1
 */
const isValidPairing = (
    inputs: PairingInputs[],
): boolean => {
    assert(inputs.length > 0)

    let hexStr = ''
    for (const input of inputs) {
        // Convert the points to their affine form
        const affineG1 = ffjavascript.bn128.G1.affine(input.G1)
        const affineG2 = ffjavascript.bn128.G2.affine(input.G2)

        hexStr += hexify(affineG1[0])
        hexStr += hexify(affineG1[1])

        // Note the order of the G2 point coefficients
        hexStr += hexify(affineG2[0][1])
        hexStr += hexify(affineG2[0][0])
        hexStr += hexify(affineG2[1][1])
        hexStr += hexify(affineG2[1][0])
    }

    const pairingResult = bn128.pairing(Buffer.from(hexStr, 'hex'))

    if (pairingResult.length === 0) {
        return false
    } else {
        return BigInt('0x' + pairingResult.toString('hex')) === BigInt(1)
    }
}

export {
    FIELD_SIZE,
    genBabyJubField,
    genCoefficients,
    genQuotientPolynomial,
    commit,
    commit2,
    genProof,
    verifyViaEIP197,
    genVerifierContractParams,
    isValidPairing,
    getPKInG1,
    getPKInG2,
    srsG1,
    srsG2,
    polyCommit,
    Coefficient,
    Polynomial,
    Commitment,
    Proof,
}
