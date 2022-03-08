# AMPPERE: A Universal Abstract Machine for Privacy-Preserving Entity Resolution Evaluation

Code and datasets for the CIKM 2021 paper [A Universal Abstract Machine for Privacy-Preserving Entity Resolution Evaluation](https://dl.acm.org/doi/pdf/10.1145/3459637.3482318). To cite our paper, please use the following:

```bibtex
@inbook{10.1145/3459637.3482318,
author = {Yao, Yixiang and Ghai, Tanmay and Ravi, Srivatsan and Szekely, Pedro},
title = {AMPPERE: A Universal Abstract Machine for Privacy-Preserving Entity Resolution Evaluation},
year = {2021},
isbn = {9781450384469},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3459637.3482318},
booktitle = {Proceedings of the 30th ACM International Conference on Information & Knowledge Management},
pages = {2394–2403},
numpages = {10}
}
```

## Abstract

Entity resolution is the task of identifying records in different datasets that refer to the same entity in the real world. In sensitive domains (e.g. financial accounts, hospital health records), entity resolution must meet privacy requirements to avoid revealing sensitive information such as personal identifiable information to untrusted parties. Existing solutions are either too algorithmically-specific or come with an implicit trade-off between accuracy of the computation, privacy, and run-time efficiency. We propose AMMPERE, an abstract computation model for performing universal privacy-preserving entity resolution. AMMPERE offers abstractions that encapsulate multiple algorithmic and platform-agnostic approaches using variants of Jaccard similarity to perform private data matching and entity resolution. Specifically, we show that two parties can perform entity resolution over their data, without leaking sensitive information. We rigorously compare and analyze the feasibility, performance overhead and privacy-preserving properties of these approaches on the Sharemind multi-party computation (MPC) platform as well as on PALISADE, a lattice-based homomorphic encryption library. The AMMPERE system demonstrates the efficacy of privacy-preserving entity resolution for real-world data while providing a precise characterization of the induced cost of preventing information leakage.


## Datasets & Settings

### Febrl

We utilize [Febrl](https://recordlinkage.readthedocs.io/en/latest/ref-datasets.html), a synthetic entity resolution dataset generated using [dsgen](https://github.com/J535D165/FEBRL-fork-v0.4.2/tree/master/dsgen). Our experiments work over a generated set of 100 records, split into 20% for D<sub>1</sub> and 80% for D<sub>2</sub> generated with the following settings: 

```
Maximal number of duplicates for one original record: 5
Maximum number of modifications per field: 5
Maximum number of modifications per record: 5
Probability distribution for duplicates: zipf
Type of modification: typo, ocr, phonetic
```

We further perform pre-processing and bi-gram, integer tokenization for each record using a [python script](https://github.com/usc-isi-i2/amppere). 


### MinHashLSH and Blocking

Additionally, we use [DataSketch](https://github.com/ekzhu/datasketch) for calculating MinHash signatures & LSH blocking keys with the following settings: 

```
Number of permutations: 128
Relative importance of false positives: 0.5
```

To understand our generated dataset and formulate a sense of ground truth, we utilize another [python script](https://github.com/usc-isi-i2/amppere) to apply blocking and non privacy-preserving entity resolution, computing three metrics: `Pairs Completeness (PC)`, `Reduction Ratio (RR)`, `F-score`. 

`Fig.3` displays the expected non privacy-preserving ER and blocking results, whereas `fig.4` details the optimal MinHashLSH blocking key size. In our findings, we note that the blocking key size is directly correlated with `b`, or the blocking threshold. 

### Environment Settings

Our experiments (for both Sharemind and PALISADE) are run on three virtual `Ubuntu
18.04.4 LTS` servers each with `2 CPUs from Intel Xeon CPU E5-2690 v4 @ 2.60GHz and 4GB` memory. All servers are in the same network and the average PING latency is around `0.12-0.23` ms. Additionally, to ensure a fair comparison between platforms we compile PALISADE with the following flag `-DWITH-NATIVEOPT = 1`, evaluate only single threaded runtimes (`export OMP-NUM-THREADS = 1`), and turn CPU scaling off. Additionally, our toggle-able pipeline component of `obfuscation` is turned off.

## Sharemind MPC

## PALISADE

We utilize the [PALISADE](https://gitlab.com/palisade/palisade-release) lattice-based homomorphic encryption library (v. 1.11.3) as our HE tool. Working with the Brakersi-Gentry-Vaikuntanathan [BGV](https://eprint.iacr.org/2011/277.pdf) and Cheon-Kim-Kim-Song [CKKS](https://eprint.iacr.org/2016/421.pdf) schemes, we configure them with the following parameters: 

| Parameter      | BGV | CKKS | 
|------------------|:------:|:----:|
| ring dim.        | 4,096   | 4096, 8,192(B) |
| mult. depth      |   1     |  1, 2(B)       |
| scale factor bits|   -     |  40            | 
| plaintext mod.   | 65,537  |  -             |
| batch size       |   -     |  16            | 
| key switching    |   BV    |  BV            |
| security level   | 128 bit |  128 bit       |  


