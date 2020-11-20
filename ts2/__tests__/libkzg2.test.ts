import {
    FIELD_SIZE,
    genCoefficients,
    genQuotientPolynomial,
    genProof,
    verifyViaEIP197,
    isValidPairing,
    genVerifierContractParams,
    genBabyJubField,
    commit,
    getPKInG1,
    getPKInG2,
    srsG1,
    srsG2,
    polyCommit
} from '../'

import * as galois from '@guildofweavers/galois'
import { bn128 } from 'ffjavascript'
const Fr = bn128.Fr
const G1 = bn128.G1
const G2 = bn128.G2

import { ec } from 'elliptic'
type CurvePoint = ec

const mod = (n: any, m: any): BigInt => {
    return BigInt(
        ((n % m) + m) % m
    )
}

const prime = FIELD_SIZE
const field = genBabyJubField()
const coefficients = [5, 0, 2, 1].map(BigInt)

describe('libkzg', () => {
    describe('commit, prove, and verify the polynomial [5, 0, 2, 1]', () => {
        let proof
        let commitment
        const xVal = BigInt(6)
        let yVal
        const sk = field.rand()
        // const sk = BigInt(1)
        const pk = getPKInG1(sk)

        const srsForPK = srsG1(129)
        for (let i = 0; i < srsForPK.length; i++) {
            srsForPK[i] = G1.affine(G1.mulScalar(srsForPK[i], sk))
        }

        it('compute the coefficients to commit using genCoefficients()', () => {
            const p = BigInt(127)
            const field = galois.createPrimeField(p)
            const values = [5, 25, 125].map(BigInt)
            const c = genCoefficients(values, p)
            expect(c).toEqual(
                [BigInt(5), BigInt(107), BigInt(40)]
            )

            for (let i = 0; i < c.length; i++) {
                const expectedEval =
                    field.evalPolyAt(field.newVectorFrom(c), BigInt(i))
                expect(expectedEval).toEqual(values[i])
            }
        })

        it('generate a KZG commitment', () => {
            commitment = polyCommit(coefficients, G2, srsG2(coefficients.length))
            expect(commitment.length === 3).toBeTruthy()
        })

        it('generate the coefficients of a quotient polynomial', () => {
            const quotientPolyCoefficients = genQuotientPolynomial(coefficients, xVal)
            expect(quotientPolyCoefficients[0]).toEqual(BigInt(48))
            expect(quotientPolyCoefficients[1]).toEqual(BigInt(8))
            expect(quotientPolyCoefficients[2]).toEqual(BigInt(1))
        })

        it('generate a KZG proof', () => {
            yVal = field.evalPolyAt(field.newVectorFrom(coefficients), xVal)
            proof = genProof(coefficients, xVal, srsForPK)
            expect(proof.length === 3).toBeTruthy()
        })

        it('verify a KZG proof', () => {

            const value = G1.affine(G1.mulScalar(pk, yVal))

            expect(
                verifyViaEIP197(
                    commitment,
                    proof,
                    xVal,
                    value,
                    pk
                )
            ).toBeTruthy()

            expect(
                verifyViaEIP197(
                    commitment,
                    [
                        proof[0] + BigInt(1),
                        proof[1],
                        proof[2],
                    ],
                    xVal,
                    value,
                    pk
                )
            ).toBeFalsy()
        })

        describe('commit, prove, and verify a random polynomial', () => {
            it('generate a valid proof', () => {
                const degree = 128
                const values: bigint[] = []
                for (let i = 0; i < degree; i++) {
                    const value = field.rand()
                    values.push(value)
                }
                const coefficients = genCoefficients(values)
                const commitment = polyCommit(coefficients, G2, srsG2(coefficients.length))
                const xVal = BigInt(6)
                const yVal = field.evalPolyAt(field.newVectorFrom(coefficients), xVal)
                const value = G1.affine(G1.mulScalar(pk, yVal))
                const proof = genProof(coefficients, xVal, srsForPK)
                const isValid = verifyViaEIP197(commitment, proof, xVal, value, pk)
                expect(isValid).toBeTruthy()
            })
        })
    })
})
