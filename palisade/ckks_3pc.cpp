#include "palisade.h"
#include <iostream>
#include <fstream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include "csvstream.h"
#include <sstream>
#include <chrono>
#include <cstdlib>
#include "utils.h"

using namespace std;
using namespace lbcrypto;

map<int, vector<int64_t>> readFromCSVFile(string csvFilePath);

bool isMatchViaNaive(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                     LPKeyPair<DCRTPoly> keyPair2,
                     vector<Ciphertext<DCRTPoly>> ciphertextA,
                     vector<Ciphertext<DCRTPoly>> ciphertextB, float threshold);

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       LPKeyPair<DCRTPoly> keyPair2,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size);

bool isMatchViaExtension(CryptoContext<DCRTPoly> cc,
                         LPKeyPair<DCRTPoly> keyPair,
                         LPKeyPair<DCRTPoly> keyPair2,
                         vector<Ciphertext<DCRTPoly>> ciphertextA,
                         vector<Ciphertext<DCRTPoly>> ciphertextB,
                         float threshold);

bool isMatchViaExtension2(CryptoContext<DCRTPoly> cc,
                          LPKeyPair<DCRTPoly> keyPair,
                          LPKeyPair<DCRTPoly> keyPair2,
                          Ciphertext<DCRTPoly> cipherA,
                          vector<Ciphertext<DCRTPoly>> cipherB, float threshold,
                          int a_size);

int main(int argc, char** argv) {
  auto start = std::chrono::high_resolution_clock::now();
  string path = std::__fs::filesystem::current_path();

  string ds1 = argv[1];
  string ds2 = argv[2];
  string mode = argv[3];

  // Instantiate the CKKS crypto context
  usint init_size = 1;
  usint dcrtBits = 40;
  usint batchSize = 16;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          init_size - 1, dcrtBits, batchSize, HEStd_128_classic,
          0,                    /*ringDimension*/
          APPROXRESCALE, BV, 1, /*numLargeDigits*/
          1,                    /*maxDepth*/
          60,                   /*firstMod*/
          5, OPTIMIZED);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(MULTIPARTY);
  LPKeyPair<DCRTPoly> keyPair;
  LPKeyPair<DCRTPoly> keyPair2;
  LPKeyPair<DCRTPoly> kpMultiparty;
  keyPair = cc->KeyGen();

  map<int, vector<int64_t>> setA =
      readFromCSVFile(path + "/../../test_data/" + ds1);
  map<int, vector<int64_t>> setB =
      readFromCSVFile(path + "/../../test_data/" + ds2);

  int psi = 0;
  float threshold = 0.5;

  srand(time(0));

  int a_idx = rand() % setA.size();
  int b_idx = rand() % setB.size();

  vector<int64_t> rec_a_tokens_int = setA[a_idx];
  vector<complex<double>> rec_a_tokens(rec_a_tokens_int.begin(),
                                       rec_a_tokens_int.end());
  vector<int64_t> rec_b_tokens_int = setB[b_idx];
  vector<complex<double>> rec_b_tokens(rec_b_tokens_int.begin(),
                                       rec_b_tokens_int.end());

  std::vector<int> rotationIndices(rec_a_tokens.size() * 2);
  std::iota(std::begin(rotationIndices), std::end(rotationIndices),
            -rec_a_tokens.size());

  cc->EvalAtIndexKeyGen(keyPair.secretKey, rotationIndices);
  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalAutomorphismKeyMap(keyPair.secretKey->GetKeyTag()));

  keyPair2 = cc->MultipartyKeyGen(keyPair.publicKey);

  cc->EvalSumKeyGen(keyPair.secretKey);
  cc->EvalMultKeyGen(keyPair.secretKey);

  auto evalAtIndexKeysB = cc->MultiEvalAtIndexKeyGen(
      keyPair2.secretKey, evalAtIndexKeys, rotationIndices,
      keyPair2.publicKey->GetKeyTag());

  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, keyPair2.publicKey->GetKeyTag());

  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalSumKeyMap(keyPair.secretKey->GetKeyTag()));

  auto evalSumKeysB = cc->MultiEvalSumKeyGen(keyPair2.secretKey, evalSumKeys,
                                             keyPair2.publicKey->GetKeyTag());

  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(
      evalSumKeys, evalSumKeysB, keyPair2.publicKey->GetKeyTag());

  cc->InsertEvalSumKey(evalSumKeysJoin);

  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);
  ;

  //  cout << "Comparing record " << a_idx << " from set A, and record " <<
  //  b_idx
  //       << " from set B" << endl;

  if (mode == "vr" or mode == "ve2") {
    Plaintext plaintextA;
    Plaintext plaintextB;

    Ciphertext<DCRTPoly> ciphertextA;
    Ciphertext<DCRTPoly> ciphertextB;

    plaintextA = cc->MakeCKKSPackedPlaintext(rec_a_tokens);
    plaintextB = cc->MakeCKKSPackedPlaintext(rec_b_tokens);

    ciphertextA = cc->Encrypt(keyPair2.publicKey, plaintextA);
    ciphertextB = cc->Encrypt(keyPair2.publicKey, plaintextB);

    bool er;
    if (mode == "vr") {
      er = isMatchViaOverlap(cc, keyPair, keyPair2, ciphertextA, ciphertextB,
                             threshold, plaintextA->GetLength(),
                             plaintextB->GetLength());
    } else {
      vector<Ciphertext<DCRTPoly>> ciphertextB_ext;

      for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
        ciphertextB_ext.push_back(cc->Encrypt(
            keyPair2.publicKey, cc->MakeCKKSPackedPlaintext({rec_b_tokens[i]})));
      }
      er = isMatchViaExtension2(cc, keyPair, keyPair2, ciphertextA,
                                ciphertextB_ext, threshold,
                                plaintextA->GetLength());
    }
    if (er) {
      psi += 1;
    }

    auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = stop - start;
    cout << duration.count() << endl;

  } else if (mode == "na" or mode == "ve") {
    vector<Plaintext> plaintextA;
    vector<Plaintext> plaintextB;

    vector<Ciphertext<DCRTPoly>> ciphertextA;
    vector<Ciphertext<DCRTPoly>> ciphertextB;

    for (unsigned int i = 0; i < rec_a_tokens.size(); i++) {
      Plaintext a;
      a = cc->MakeCKKSPackedPlaintext({rec_a_tokens[i]});
      plaintextA.push_back(a);
      ciphertextA.push_back(cc->Encrypt(keyPair2.publicKey, a));
    }

    for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
      Plaintext b;
      b = cc->MakeCKKSPackedPlaintext({rec_b_tokens[i]});
      plaintextB.push_back(b);
      ciphertextB.push_back(cc->Encrypt(keyPair2.publicKey, b));
    }

    bool er;
    if (mode == "na") {
      er = isMatchViaNaive(cc, keyPair, keyPair2, ciphertextA, ciphertextB,
                           threshold);
    } else {
      er = isMatchViaExtension(cc, keyPair, keyPair2, ciphertextA, ciphertextB,
                               threshold);
    }
    if (er) {
      psi += 1;
    }

    auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = stop - start;
    cout << duration.count() << endl;

  } else {
    return 0;
  }
}

bool isMatchViaNaive(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                     LPKeyPair<DCRTPoly> keyPair2,
                     vector<Ciphertext<DCRTPoly>> ciphertextsA,
                     vector<Ciphertext<DCRTPoly>> ciphertextsB,
                     float threshold) {
  int match_counter = 0;
  for (unsigned int k = 0; k < ciphertextsA.size(); k++) {
    for (unsigned int l = 0; l < ciphertextsB.size(); l++) {
      auto sub = cc->EvalSub(ciphertextsA[k], ciphertextsB[l]);
      DCRTPoly partialPlaintext1;
      DCRTPoly partialPlaintext2;

      Plaintext plaintextMultipartyNew;

      const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
          keyPair.secretKey->GetCryptoParameters();
      const shared_ptr<typename DCRTPoly::Params> elementParams =
          cryptoParams->GetElementParams();

      // partial decryption by first party
      auto ciphertextPartial1 =
          cc->MultipartyDecryptLead(keyPair.secretKey, {sub});

      // partial decryption by second party
      auto ciphertextPartial2 =
          cc->MultipartyDecryptMain(keyPair2.secretKey, {sub});

      vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
      partialCiphertextVec.push_back(ciphertextPartial1[0]);
      partialCiphertextVec.push_back(ciphertextPartial2[0]);

      // partial decryptions are combined together
      cc->MultipartyDecryptFusion(partialCiphertextVec,
                                  &plaintextMultipartyNew);

      if (plaintextMultipartyNew->GetCKKSPackedValue()[0].real() <= 0.0005 &&
          plaintextMultipartyNew->GetCKKSPackedValue()[0].real() >= -0.0005) {
        match_counter++;
      }
    }
  }

  bool er = jaccard(match_counter, ciphertextsA.size(), ciphertextsB.size(),
                    threshold);

  if (er) {
    return 1;
  } else {
    return 0;
  }
}

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       LPKeyPair<DCRTPoly> keyPair2,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size) {
  float overlap = 0;

  auto d = cc->EvalSub(cipherA, cipherB);

  Plaintext plaintextAddNew1;
  Plaintext plaintextAddNew2;

  DCRTPoly partialPlaintext1;
  DCRTPoly partialPlaintext2;

  Plaintext plaintextMultipartyNew;

  const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
      keyPair.secretKey->GetCryptoParameters();
  const shared_ptr<typename DCRTPoly::Params> elementParams =
      cryptoParams->GetElementParams();

  // partial decryption by first party
  auto ciphertextPartial1 = cc->MultipartyDecryptLead(keyPair.secretKey, {d});

  // partial decryption by second party
  auto ciphertextPartial2 = cc->MultipartyDecryptMain(keyPair2.secretKey, {d});

  vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
  partialCiphertextVec.push_back(ciphertextPartial1[0]);
  partialCiphertextVec.push_back(ciphertextPartial2[0]);

  // partial decryptions are combined together
  cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
  plaintextMultipartyNew->SetLength(a_size);

  vector<complex<double>> v = plaintextMultipartyNew->GetCKKSPackedValue();
  for (int i = 0; i < v.size(); i++) {
    if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
      overlap++;
    }
  }

  unsigned int idx = 1;
  while (idx < a_size) {
    auto rot1 = cc->EvalAtIndex(cipherA, idx);
    auto rot2 = cc->EvalAtIndex(cipherA, idx - a_size);

    auto merged = cc->EvalAdd(rot1, rot2);

    auto d = cc->EvalSub(merged, cipherB);

    Plaintext plaintextAddNew1;
    Plaintext plaintextAddNew2;

    DCRTPoly partialPlaintext1;
    DCRTPoly partialPlaintext2;

    Plaintext plaintextMultipartyNew;

    const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
        keyPair.secretKey->GetCryptoParameters();
    const shared_ptr<typename DCRTPoly::Params> elementParams =
        cryptoParams->GetElementParams();

    // partial decryption by first party
    auto ciphertextPartial1 = cc->MultipartyDecryptLead(keyPair.secretKey, {d});

    // partial decryption by second party
    auto ciphertextPartial2 =
        cc->MultipartyDecryptMain(keyPair2.secretKey, {d});

    vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    // partial decryptions are combined together
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
    plaintextMultipartyNew->SetLength(a_size);

    vector<complex<double>> v = plaintextMultipartyNew->GetCKKSPackedValue();
    for (int i = 0; i < v.size(); i++) {
      if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
        overlap++;
      }
    }

    idx++;
  }

  bool er = jaccard(overlap, a_size, b_size, threshold);

  if (er) {
    return 1;
  } else {
    return 0;
  }
}

bool isMatchViaExtension(CryptoContext<DCRTPoly> cc,
                         LPKeyPair<DCRTPoly> keyPair,
                         LPKeyPair<DCRTPoly> keyPair2,
                         vector<Ciphertext<DCRTPoly>> ciphertextA,
                         vector<Ciphertext<DCRTPoly>> ciphertextB,
                         float threshold) {
  int b_size = ciphertextB.size();
  int sizeOfRecA = ciphertextA.size();

  ciphertextA.reserve(b_size * sizeOfRecA);
  for (int i = 0; i < b_size - 1; i++) {
    ciphertextA.insert(ciphertextA.end(), ciphertextA.begin(),
                       ciphertextA.begin() + sizeOfRecA);
  }

  vector<Ciphertext<DCRTPoly>> cipherB_expanded;
  cipherB_expanded.reserve(ciphertextA.size());

  for (unsigned int i = 0; i < b_size; i++) {
    for (unsigned int j = 0; j < sizeOfRecA; j++) {
      cipherB_expanded.push_back(ciphertextB[i]);
    }
  }

  int match_counter = 0;
  if (ciphertextA.size() != cipherB_expanded.size()) {
    cout << "EXPANSION IS WRONG" << endl;
  } else {
    for (unsigned int i = 0; i < ciphertextA.size(); i++) {
      auto sub = cc->EvalSub(ciphertextA[i], cipherB_expanded[i]);

      Plaintext plaintextAddNew1;
      Plaintext plaintextAddNew2;

      DCRTPoly partialPlaintext1;
      DCRTPoly partialPlaintext2;

      Plaintext plaintextMultipartyNew;

      const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
          keyPair.secretKey->GetCryptoParameters();
      const shared_ptr<typename DCRTPoly::Params> elementParams =
          cryptoParams->GetElementParams();

      // partial decryption by first party
      auto ciphertextPartial1 =
          cc->MultipartyDecryptLead(keyPair.secretKey, {sub});

      // partial decryption by second party
      auto ciphertextPartial2 =
          cc->MultipartyDecryptMain(keyPair2.secretKey, {sub});

      vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
      partialCiphertextVec.push_back(ciphertextPartial1[0]);
      partialCiphertextVec.push_back(ciphertextPartial2[0]);

      // partial decryptions are combined together
      cc->MultipartyDecryptFusion(partialCiphertextVec,
                                  &plaintextMultipartyNew);
      plaintextMultipartyNew->SetLength(1);

      if (plaintextMultipartyNew->GetCKKSPackedValue()[0].real() <= 0.0005 &&
          plaintextMultipartyNew->GetCKKSPackedValue()[0].real() >= -0.0005) {
        match_counter++;
      }
    }
  }
  bool er = jaccard(match_counter, sizeOfRecA, b_size, threshold);

  if (er) {
    return 1;
  } else {
    return 0;
  }
}

bool isMatchViaExtension2(CryptoContext<DCRTPoly> cc,
                          LPKeyPair<DCRTPoly> keyPair,
                          LPKeyPair<DCRTPoly> keyPair2,
                          Ciphertext<DCRTPoly> cipherA,
                          vector<Ciphertext<DCRTPoly>> cipherB, float threshold,
                          int a_size) {
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {-a_size});

  int match_counter = 0;
  int b_size = cipherB.size();

  for (int i = 0; i < cipherB.size(); i++) {
    auto curr = cipherB[i];
    curr = cc->EvalAtIndex(curr, -a_size);

    auto d = cc->EvalSub(cipherA, cc->EvalSum(curr, a_size));

    Plaintext plaintextAddNew1;
    Plaintext plaintextAddNew2;

    DCRTPoly partialPlaintext1;
    DCRTPoly partialPlaintext2;

    Plaintext plaintextMultipartyNew;

    const shared_ptr<LPCryptoParameters<DCRTPoly>> cryptoParams =
        keyPair.secretKey->GetCryptoParameters();
    const shared_ptr<typename DCRTPoly::Params> elementParams =
        cryptoParams->GetElementParams();

    // partial decryption by first party
    auto ciphertextPartial1 = cc->MultipartyDecryptLead(keyPair.secretKey, {d});

    // partial decryption by second party
    auto ciphertextPartial2 =
        cc->MultipartyDecryptMain(keyPair2.secretKey, {d});

    vector<Ciphertext<DCRTPoly>> partialCiphertextVec;
    partialCiphertextVec.push_back(ciphertextPartial1[0]);
    partialCiphertextVec.push_back(ciphertextPartial2[0]);

    // partial decryptions are combined together
    cc->MultipartyDecryptFusion(partialCiphertextVec, &plaintextMultipartyNew);
    plaintextMultipartyNew->SetLength(a_size);

    vector<complex<double>> v = plaintextMultipartyNew->GetCKKSPackedValue();
    for (int i = 0; i < v.size(); i++) {
      if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
        match_counter++;
      }
    }
  }

  bool er = jaccard(match_counter, a_size, b_size, threshold);
  if (er) {
    return 1;
  } else {
    return 0;
  }
}

map<int, vector<int64_t>> readFromCSVFile(string csvFilePath) {
  csvstream csvin(csvFilePath);

  map<int, vector<int64_t>> records;
  map<string, string> row;

  while (csvin >> row) {
    int id_num;
    string id = row["id"];
    stringstream ss;
    ss << id;
    ss >> id_num;

    vector<int64_t> tokens;

    stringstream t(row["tokens"]);

    string intermediate;

    while (getline(t, intermediate, ' ')) {
      //            cout << "hex value: " << intermediate << endl;
      uint64_t x;
      std::stringstream ss;
      ss << std::hex << intermediate;
      ss >> x;
      //            cout << "unsignted int value: " << x << endl;
      tokens.push_back(x);
    }

    records[id_num] = tokens;
  }
  return records;
}