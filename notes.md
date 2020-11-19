$$field.evalPolyAt(field.newVectorFrom(c), BigInt(i))$$

计算得到系数为c的多项式的值，index为i，即$f_c(i)$



$$genQuotientPolynomial$$ 即为 $(f(x) - f(r)) / (x - r)$



$$G.mulScalar(srs[i], coefficients[i])$$ 里srs即为$\alpha^i$， coefficients即为$\omega^i$

affine应该类似取模操作

multi proof中使用的是 commit和poly的变换，commit应该就是$g^{poly(\alpha)}$
$e(proof, commit(zPoly)) = e(commitment - commit(iPoly), g)$
proof = (poly - ipoly) / zpoly

唯一有疑惑的地方是这里的加减好像就是乘除，可能是加法群或者乘法群的问题？

智能合约中运行的函数：
verify  
169126 169150 169150 169150 169138 169150 169150 169138 169150
commit  
    128coffs: 1636734  1636758   1636794
    64 coffs: 828052   827980    828052
evalPolyAt  31366:2  31354:127  31354:1  31750:rand
verifyMulti
    128coffs: 9145290  9145410  9145254
    64coffs:  3286179  3286287  3286143


verify new pvss:
199093 199093 199105 199093 199105 199105 199093 199093 199093
199117 199129 199129 199117 199117 199129 199117 199117 199129


第一种方案：
201994 202006 201982 201982 201994 201994 201970 201994