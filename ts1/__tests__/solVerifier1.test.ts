jest.setTimeout(90000)
const Verifier = require('../../compiled/Verifier.json')
import * as ethers from 'ethers'
import * as etherlime from 'etherlime-lib'
import {
    genBabyJubField,
    genCoefficients,
    commit,
    commit2,
    genProof,
    genVerifierContractParams,
    srsG1,
    srsG2,
    getPKInG1,
    getPKInG2,
    verifyViaEIP197
} from '../'

import { bn128 } from 'ffjavascript'
const G1 = bn128.G1
const G2 = bn128.G2

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
    let pk
    let srsForPK

    beforeAll(async () => {
        verifierContract = await deployer.deploy(
            Verifier,
            {},
        )

        sk = field.rand()
        // sk = BigInt(1)
        pk = getPKInG2(sk)
        srsForPK = srsG2(129)
        for (let i = 0; i < srsForPK.length; i++) {
            srsForPK[i] = G2.affine(G2.mulScalar(srsForPK[i], sk))
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
                const value = G2.affine(G2.mulScalar(pk, yVal))
                const isValid = verifyViaEIP197(commitment, proof, i, value, pk)
                expect(isValid).toBeTruthy()

                const params = genVerifierContractParams(commitment, proof, i, value, pk)

                const result = await verifierContract.verify(
                    params.commitment,
                    params.proof,
                    params.index,
                    params.value,
                    params.pk,
                )
                expect(result).toBeTruthy()
            }
        })

        it('should not verify an invalid proof', async () => {
            const i = 0
            const proof = genProof(coefficients, i, srsForPK)
            const yVal = values[i]
            const value = G2.affine(G2.mulScalar(pk, yVal))
            const params = genVerifierContractParams(commitment, proof, i, value, pk)

            const result = await verifierContract.verify(
                params.commitment,
                [['0x0', '0x0'],[ '0x0', '0x0']],
                params.index,
                params.value,
                params.pk,
            )
            expect(result).toBeFalsy()
        })

        it('should not verify an invalid commitment', async () => {
            const i = 0
            const proof = genProof(coefficients, i, srsForPK)
            const yVal = values[i]
            const value = G2.affine(G2.mulScalar(pk, yVal))
            const params = genVerifierContractParams(commitment, proof, i, value, pk)

            const result = await verifierContract.verify(
                ['0x0', '0x0'],
                params.proof,
                params.index,
                params.value,
                params.pk,
            )
            expect(result).toBeFalsy()
        })

        it('verify benchmarks', async () => {
            for (let i = 0; i < 1; i++) {
                const proof = genProof(coefficients, i, srsForPK)
                const yVal = values[i]
                const value = G2.affine(G2.mulScalar(pk, yVal))
                const params = genVerifierContractParams(commitment, proof, i, value, pk)

                const tx = await verifierContract.verifyBenchmark(
                    params.commitment,
                    params.proof,
                    params.index,
                    params.value,
                    params.pk,
                )
                const response = await tx.wait()
                console.log(response.gasUsed.toString())
            }
        })
    })
})
