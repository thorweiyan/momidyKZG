jest.setTimeout(90000)
const Verifier2 = require('../../compiled/Verifier2.json')
import * as ethers from 'ethers'
import * as etherlime from 'etherlime-lib'
import {
    genBabyJubField,
    genCoefficients,
    commit,
    commit2,
    genProof,
    genMultiProof,
    verify,
    verifyMulti,
    genVerifierContractParams,
    genMultiVerifierContractParams,
    srsG1,
    getPKInG1,
    getPKInG2,
    verifyViaEIP197
} from '../index1'

import { bn128 } from 'ffjavascript'
const G1 = bn128.G1

const mnemonic =
    'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'

const genTestAccounts = (
    numAccounts: number,
) => {
    const accounts: ethers.Wallet[] = []

    for (let i = 0; i < numAccounts; i++) {
        const path = `m/44'/60'/${i}'/0/0`
        const wallet = ethers.Wallet.fromMnemonic(mnemonic, path)
        accounts.push(wallet)
    }

    return accounts
}

const field = genBabyJubField()

describe('Solidity verifier', () => {
    const account = genTestAccounts(1)[0]
    const deployer = new etherlime.JSONRPCPrivateKeyDeployer(
        account.privateKey,
        'http://localhost:8545',
    )

    let verifierContract
    let values: bigint[] = []
    let commitment
    const degree = 10
    let coefficients
    let sk
    let pk1
    let pk2
    let srsForPK

    beforeAll(async () => {
        verifierContract = await deployer.deploy(
            Verifier2,
            {},
        )

        sk = field.rand()
        // sk = BigInt(1)
        pk1 = getPKInG1(sk)
        pk2 = getPKInG2(sk)
        srsForPK = srsG1(129)
        for (let i = 0; i < srsForPK.length; i++) {
            srsForPK[i] = G1.affine(G1.mulScalar(srsForPK[i], sk))
        }

        for (let i = 0; i < degree; i++) {
            const value = field.rand()
            values.push(value)
        }

        coefficients = genCoefficients(values)
        commitment = commit(coefficients)
    })

    describe('single-point proof verification', () => {
        it('should verify a valid proof', async () => {
            for (let i = 1; i < degree; i++) {
                const proof = genProof(coefficients, i, srsForPK)
                const yVal = values[i]
                const value = G1.affine(G1.mulScalar(pk1, yVal))
                const isValid = verifyViaEIP197(commitment, proof, i, value, pk2)
                expect(isValid).toBeTruthy()

                const params = genVerifierContractParams(commitment, proof, i, value, pk2)

                const result = await verifierContract.verify(
                    params.commitment,
                    params.proof,
                    params.index,
                    params.value,
                    params.pk2,
                )
                expect(result).toBeTruthy()
            }
        })

        it('should not verify an invalid proof', async () => {
            const i = 0
            const proof = genProof(coefficients, i, srsForPK)
            const yVal = values[i]
            const value = G1.affine(G1.mulScalar(pk1, yVal))
            const params = genVerifierContractParams(commitment, proof, i, value, pk2)

            const result = await verifierContract.verify(
                params.commitment,
                ['0x0', '0x0'],
                params.index,
                params.value,
                params.pk2,
            )
            expect(result).toBeFalsy()
        })

        it('should not verify an invalid commitment', async () => {
            const i = 0
            const proof = genProof(coefficients, i, srsForPK)
            const yVal = values[i]
            const value = G1.affine(G1.mulScalar(pk1, yVal))
            const params = genVerifierContractParams(commitment, proof, i, value, pk2)

            const result = await verifierContract.verify(
                ['0x0', '0x0'],
                params.proof,
                params.index,
                params.value,
                params.pk2,
            )
            expect(result).toBeFalsy()
        })

        it('verify benchmarks', async () => {
            for (let i = 0; i < degree; i++) {
                const proof = genProof(coefficients, i, srsForPK)
                const yVal = values[i]
                const value = G1.affine(G1.mulScalar(pk1, yVal))
                const params = genVerifierContractParams(commitment, proof, i, value, pk2)

                const tx = await verifierContract.verifyBenchmark(
                    params.commitment,
                    params.proof,
                    params.index,
                    params.value,
                    params.pk2,
                )
                const response = await tx.wait()
                console.log(response.gasUsed.toString())
            }
        })
    })
})
