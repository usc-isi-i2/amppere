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
#include "psi_blocking_utils.h"

using namespace std;
using namespace lbcrypto;

map<int, vector<int64_t>> readFromCSVFile(string csvFilePath);

bool isMatchViaNaive(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                     vector<Plaintext> plaintextA,
                     vector<Ciphertext<DCRTPoly>> ciphertextB, float threshold);

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Plaintext recA, Ciphertext<DCRTPoly> cipherB,
                       float threshold, int b_size);

bool isMatchViaExtension(CryptoContext<DCRTPoly> cc,
                         LPKeyPair<DCRTPoly> keyPair, vector<Plaintext> recA,
                         vector<Ciphertext<DCRTPoly>> cipherB, float threshold);

bool isMatchViaExtension2(CryptoContext<DCRTPoly> cc,
                          LPKeyPair<DCRTPoly> keyPair, Plaintext recA,
                          vector<Ciphertext<DCRTPoly>> cipherB, float threshold,
                          int b_size);

int main(int argc, char** argv) {
  auto start = std::chrono::high_resolution_clock::now();
  string path = std::__fs::filesystem::current_path();

  string ds1 = argv[1];
  string ds2 = argv[2];
  string mode = argv[3];

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

  //  cout << *cc->GetElementParams() << endl;

  // Enable features that to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cc->KeyGen();

  cc->EvalSumKeyGen(keyPair.secretKey);

  map<int, vector<int64_t>> setA =
      readFromCSVFile(path + "/../test_data/" + ds1);
  map<int, vector<int64_t>> setB =
      readFromCSVFile(path + "/../test_data/" + ds2);

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

  //  cout << "Comparing record " << a_idx << " from set A, and record " <<
  //  b_idx
  //       << " from set B" << endl;

  if (mode == "vr" or mode == "ve2") {
    Plaintext plaintextA;
    Plaintext plaintextB;

    Ciphertext<DCRTPoly> ciphertextB;

    plaintextA = cc->MakeCKKSPackedPlaintext(rec_a_tokens);
    plaintextB = cc->MakeCKKSPackedPlaintext(rec_b_tokens);

    ciphertextB = cc->Encrypt(keyPair.publicKey, plaintextB);

    bool er;
    if (mode == "vr") {
      er = isMatchViaOverlap(cc, keyPair, plaintextA, ciphertextB, threshold,
                             plaintextB->GetLength());
    } else {
      vector<Ciphertext<DCRTPoly>> ciphertextB_ext;

      for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
        ciphertextB_ext.push_back(cc->Encrypt(
            keyPair.publicKey, cc->MakeCKKSPackedPlaintext({rec_b_tokens[i]})));
      }
      er = isMatchViaExtension2(cc, keyPair, plaintextA, ciphertextB_ext,
                                threshold, plaintextB->GetLength());
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

    vector<Ciphertext<DCRTPoly>> ciphertextB;

    for (unsigned int i = 0; i < rec_a_tokens.size(); i++) {
      Plaintext a;
      a = cc->MakeCKKSPackedPlaintext({rec_a_tokens[i]});
      plaintextA.push_back(a);
    }

    for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
      Plaintext b;
      b = cc->MakeCKKSPackedPlaintext({rec_b_tokens[i]});
      plaintextB.push_back(b);
      ciphertextB.push_back(cc->Encrypt(keyPair.publicKey, b));
    }

    bool er;
    if (mode == "na") {
      er = isMatchViaNaive(cc, keyPair, plaintextA, ciphertextB, threshold);
    } else {
      er = isMatchViaExtension(cc, keyPair, plaintextA, ciphertextB, threshold);
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
                     vector<Plaintext> plaintextsA,
                     vector<Ciphertext<DCRTPoly>> ciphertextsB,
                     float threshold) {
  int match_counter = 0;
  for (unsigned int k = 0; k < plaintextsA.size(); k++) {
    for (unsigned int l = 0; l < ciphertextsB.size(); l++) {
      auto sub = cc->EvalSub(plaintextsA[k], ciphertextsB[l]);
      Plaintext decryptResult;
      cc->Decrypt(keyPair.secretKey, sub, &decryptResult);
      if (decryptResult->GetCKKSPackedValue()[0].real() <= 0.0005 &&
          decryptResult->GetCKKSPackedValue()[0].real() >= -0.0005) {
        match_counter++;
      }
    }
  }

  bool er = jaccard(match_counter, plaintextsA.size(), ciphertextsB.size(),
                    threshold);

  if (er) {
    return 1;
  } else {
    return 0;
  }
}

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Plaintext recA, Ciphertext<DCRTPoly> cipherB,
                       float threshold, int b_size) {

  vector<complex<double>> a = recA->GetCKKSPackedValue();
  if (a.size() < b_size) {
    while (a.size() < b_size) {
      a.push_back(INT_MIN);
    }
  }
  recA = cc->MakeCKKSPackedPlaintext(a);

  float overlap = 0;
  auto d = cc->EvalSub(recA, cipherB);
  Plaintext decryptResult;
  cc->Decrypt(keyPair.secretKey, d, &decryptResult);
  decryptResult->SetLength(b_size);

  vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
  for (int i = 0; i < v.size(); i++) {
    if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
      overlap++;
    }
  }

  int idx = 1;
  while (idx < a.size()) {
    std::rotate(a.begin(), a.begin() + 1, a.end());
    recA = cc->MakeCKKSPackedPlaintext(a);

    auto d = cc->EvalSub(recA, cipherB);

    Plaintext decryptResult;
    cc->Decrypt(keyPair.secretKey, d, &decryptResult);
    decryptResult->SetLength(b_size);

    vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
    for (int i = 0; i < v.size(); i++) {
      if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
        overlap++;
      }
    }
    idx++;
  }

  bool er = jaccard(overlap, recA->GetLength(), b_size, threshold);

  if (er) {
    return 1;
  } else {
    return 0;
  }
}

bool isMatchViaExtension(CryptoContext<DCRTPoly> cc,
                         LPKeyPair<DCRTPoly> keyPair, vector<Plaintext> recA,
                         vector<Ciphertext<DCRTPoly>> cipherB,
                         float threshold) {
  int b_size = cipherB.size();
  int sizeOfRecA = recA.size();

  recA.reserve(b_size * sizeOfRecA);
  for (int i = 0; i < b_size - 1; i++) {
    recA.insert(recA.end(), recA.begin(), recA.begin() + sizeOfRecA);
  }

  vector<Ciphertext<DCRTPoly>> cipherB_expanded;
  cipherB_expanded.reserve(recA.size());

  for (unsigned int i = 0; i < b_size; i++) {
    for (unsigned int j = 0; j < sizeOfRecA; j++) {
      cipherB_expanded.push_back(cipherB[i]);
    }
  }

  int match_counter = 0;
  if (recA.size() != cipherB_expanded.size()) {
    cout << "EXPANSION IS WRONG" << endl;
  } else {
    for (unsigned int i = 0; i < recA.size(); i++) {
      auto sub = cc->EvalSub(recA[i], cipherB_expanded[i]);
      Plaintext decryptResult;
      cc->Decrypt(keyPair.secretKey, sub, &decryptResult);
      decryptResult->SetLength(1);
      vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
      for (int i = 0; i < v.size(); i++) {
        if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
          match_counter++;
        }
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
                          LPKeyPair<DCRTPoly> keyPair, Plaintext recA,
                          vector<Ciphertext<DCRTPoly>> cipherB, float threshold,
                          int b_size) {

  int a_size = recA->GetLength();
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {-a_size});


  int match_counter = 0;

  for (int i = 0; i < cipherB.size(); i++) {
    auto curr = cipherB[i];
    curr = cc->EvalAtIndex(curr, -a_size);

    //auto d_test = cc->EvalSum(curr, a_size);
    auto d = cc->EvalSub(recA, cc->EvalSum(curr, a_size));
    Plaintext decryptResult;
    cc->Decrypt(keyPair.secretKey, d, &decryptResult);
    decryptResult->SetLength(a_size);
    //cout << decryptResult << endl;
    vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
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