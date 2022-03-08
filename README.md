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

