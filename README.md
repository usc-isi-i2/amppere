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

`lsh_optimal_params.py` is for getting the optimal LSH parameter combinations with given `threshold` and `num_perm`.

### Environment Settings

Our experiments (for both Sharemind and PALISADE) are run on three virtual `Ubuntu
18.04.4 LTS` servers each with `2 CPUs from Intel Xeon CPU E5-2690 v4 @ 2.60GHz and 4GB` memory. All servers are in the same network and the average PING latency is around `0.12-0.23` ms. Additionally, to ensure a fair comparison between platforms we compile PALISADE with the following flag `-DWITH-NATIVEOPT = 1`, evaluate only single threaded runtimes (`export OMP-NUM-THREADS = 1`), and turn CPU scaling off. Additionally, our toggle-able pipeline component of `obfuscation` is turned off.

## Sharemind MPC

We use [Sharemind MPC Academic Server](https://sharemind.cyber.ee/sharemind-mpc/) (version 2019.03) for the experiments. Please set up the computation nodes according to its documentation first. All source code is under `/sharemind`.

### Jaccard similarity

`jaccard` is for 4 different Jaccard similarity implementations.

```
# compile SecreC program
sm_compile.sh secrec/*.sc

# compile client program
mkdir build
cd build
cmake ..
make

# start server and run
sm_start_servers.sh
./jaccard --a 0x6c6c6f 0x68656c 0x656c6c --b 0x6c6c65 0x68656c 0x656c6c --t 0.4
```

### Run End-to-end program

0. On server side, configure keydb. The keydb name has to be "dbhost". On client side, compile all SecreC and client programs.

```
[Host host]
; The name to access this host from the SecreC application.
Name = dbhost
```

1. On each client, make a CSV file which has three columns (comma as delimiter), the record id has to be in consecutive number:

```
id,original_id,tokens
0,rec-242-org,0x656e 0x6e67 0x6720 0x2066
1,rec-160-dup-2,0x6672 0x7265 0x6520 0x2066 0x6620 0x2033 0x3331 0x3120
...
```

Then upload data to keydb on each client. 

```
# build/upload --id {string} --tokens {white-space separated numbers}
tail -n +2 <input-csv-file.csv> | awk -F',' '{print "build/upload --key "$1" --tokens "$3}' | xargs -I {} sh -c "{}"
```

2. Compute and find pairs from one of the clients.

```
build/link --a_prefix ds1_ --a_size 2 --b_prefix ds2_ --b_size 8 --t 0.5
```

### Run program with blocking

0. In keydb config file, `ScanCount` needs to be set to a value greater than the total number of records in keydb. Total number of records can be computed as `26 * (a_size + b_size)` in which each record occupies 25 blocking keys and 1 record key when threshold is set to 0.5.

1. It is similar to non-blocking version, but need an additional column which contains blocking keys. 

```
id,original_id,tokens,blocking_keys
0,rec-242-org,0x656e 0x6e67 0x6720 0x2066,2537ac800947b99c9d0d 3919229da0a2e549c9b0
...
```

For Febrl dataset, the following script can be called to generate such file.

```
python preprocessing_febrl.py <input.csv> <output.csv> \
        --ngram=2 --blocking --num-perm=128 --threshold=0.5
```

Then you need to upload tokens with blocking keys

```
# build/upload --id {id} --tokens {tokens} --prefix {prefix} --bkeys {blocking keys}
tail -n +2 <input-csv-file.csv> | awk -F',' '{print "build/upload --id "$1" --tokens "$3" --bkeys "$4" --prefix ds1_"}' | xargs -I {} sh -c "{}"
```

3. Compute and find pairs with blocking enabled.

```
build/link --a_prefix ds1_ --a_size 2 --b_prefix ds2_ --b_size 8 --t 0.5 --blocking
```

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

- `all_comparisons.cpp`: A `full comparison` calculation between 2 datasets using the `VR` set intersection size operator (detailed in the paper as the fastest one for PALISADE). 

To run: `./all-comparisons ds1_output_0.5.csv ds2_output_0.5.csv`

- `bgv_sr.cpp`/`ckks_sr.cpp`: An implementation of private-set intersection size methods (e.g. `VR`, `VE`) in their respective cryptographic scheme (e.g.`BGV`, `CKKS`) in the sender-receiver (`SR`) mode. It randomly picks a record from each dataset and compares them with the chosen method input as a user parameter. 

To run: `./bgv-sr ds1_output_0.5.csv ds2_output_0.5.csv vr` / `./ckks-sr ds1_output_0.5.csv ds2_output_0.5.csv ve`

- `bgv_3pc.cpp`/`ckks_3pc.cpp`: An implementation of private-set intersection size methods (e.g. `VR`, `VE`) in their respective cryptographic scheme (e.g.`BGV`, `CKKS`) in the three party (`3PC`) mode. It randomly picks a record from each dataset and compares them with the chosen method input as a user parameter. 

To run: `./bgv-3pc ds1_output_0.5.csv ds2_output_0.5.csv ve` / `./ckks-3pc ds1_output_0.5.csv ds2_output_0.5.csv vr`

- `b_ckks_sr.cpp`/`b_ckks_3pc.cpp`: Our blocking implementations in both the sender-receiver (`SR`) and three party (`3PC`) modes utilizing only the vector rotation (`VR`) private set intersection size method for efficiency. 

To run: `./b-ckks-sr ds1_b_output_0.5.csv ds2_b_output_0.5.csv` / `./b-ckks-3pc ds1_b_output_0.5.csv ds2_b_output_0.5.csv`

Note: Make sure to run the febrl processing script with the `--blocking` flag on in order to generate blocking keys; the blocking implementations expect those to be present in the .csv file inputs.

