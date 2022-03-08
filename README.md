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

The generated datasets are stored under the `/test_data` directory as follows: 
`gen-100_30-70-5-5-5-zipf-all_20.csv` and `gen-100_30-70-5-5-5-zipf-all_80.csv`. We further perform pre-processing and bi-gram, integer tokenization for each record using the script `febrl.py`. Internally, `febrl.py` utilizes `preprocessing.py` for utility methods and functionality. To run pre-processing over a dataset, one can run the following command:

```
python3 febrl.py test_data/gen-100_30-70-5-5-5-zipf-all_20.csv test_data/ds1_output.csv  --ngram=2 --blocking --num-perm=128 --threshold=0.5
```

with the following flags `--blocking` to ensure generation of blocking keys, `--ngram` to denote the size of n (e.g. 2 for bi-gram), `--num-perm` for number of permutations, and `--threshold` for the jaccard similarity threshold value (we choose 0.2, 0.5, and 0.8). 

### MinHashLSH and Blocking

Additionally, we use [DataSketch](https://github.com/ekzhu/datasketch) for calculating MinHash signatures & LSH blocking keys with the following settings: 

```
Number of permutations: 128
Relative importance of false positives: 0.5
```

To understand our generated dataset and formulate a sense of ground truth, we utilize another python script (`eval.py`) to apply blocking and non privacy-preserving entity resolution, computing three metrics: `Pairs Completeness (PC)`, `Reduction Ratio (RR)`, `F-score`. 

To run `eval.py` for a variety of statistics/metrics, one can run the following commands:

```
    # basic statistics
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv
    # evaluating blocking threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --blocking --threshold 0.8
    
    # evaluating entity resolution threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --er --er-threshold 0.8
    # evaluating er with blocking
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --blocking --threshold 0.8 --er --er-threshold 0.8
    # estimating entity resolution threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --er --search-threshold --epoch 3
    '''
```

Note: `eval.py` can only be run, after a sample dataset (e.g. `ds2_output_0.8.csv`) has been created via a run of `febrl.py`. 

`Fig.3` displays the expected non privacy-preserving ER and blocking results, whereas `fig.4` details the optimal MinHashLSH blocking key size. In our findings, we note that the blocking key size is directly correlated with `b`, or the blocking threshold. 

### Environment Settings

Our experiments (for both Sharemind and PALISADE) are run on three virtual `Ubuntu
18.04.4 LTS` servers each with `2 CPUs from Intel Xeon CPU E5-2690 v4 @ 2.60GHz and 4GB` memory. All servers are in the same network and the average PING latency is around `0.12-0.23` ms. Additionally, to ensure a fair comparison between platforms we compile PALISADE with the following flag `-DWITH-NATIVEOPT = 1`, evaluate only single threaded runtimes (`export OMP-NUM-THREADS = 1`), and turn CPU scaling off. Additionally, our toggle-able pipeline component of `obfuscation` is turned off.

## Sharemind MPC

## PALISADE

We utilize the [PALISADE](https://gitlab.com/palisade/palisade-release) lattice-based homomorphic encryption library (v. 1.11.3) as our HE tool. Working with the Brakersi-Gentry-Vaikuntanathan [BGV](https://eprint.iacr.org/2011/277.pdf) and Cheon-Kim-Kim-Song [CKKS](https://eprint.iacr.org/2016/421.pdf) schemes, we configure them with the following parameters (`B` denotes blocking): 

| Parameter      | BGV | CKKS | 
|------------------|:------:|:----:|
| ring dim.        | 4,096   | 4096, 8,192(B) |
| mult. depth      |   1     |  1, 2(B)       |
| scale factor bits|   -     |  40            | 
| plaintext mod.   | 65,537  |  -             |
| batch size       |   -     |  16            | 
| key switching    |   BV    |  BV            |
| security level   | 128 bit |  128 bit       |  

Our various implementations are located under the `/palisade` directory, which contains a cmake user project that can easily be compiled via `cmake ..` and then `make` from the `/build` sub-directory. 

Below, we detail each file, what it denotes, and how you can run it:

- `psi_all_comparisons.cpp`: A `full comparison` calculation between 2 datasets using the `VR` set intersection size operator (detailed in the paper as the fastest one for PALISADE). 

To run: `./all_comparisons ds1_output_0.5.csv ds2_output_0.5.csv`
