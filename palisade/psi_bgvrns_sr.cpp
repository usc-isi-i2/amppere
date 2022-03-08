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

  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 1;

  // Instantiate the BGVrns crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

   // cout << *cc->GetElementParams() << endl;

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

  vector<int64_t> rec_a_tokens = setA[a_idx];
  vector<int64_t> rec_b_tokens = setB[b_idx];

  cout << "Comparing record " << a_idx << " from set A, and record " << b_idx << " from set B" << endl;

  if (mode == "vr" or mode == "ve2") {
    Plaintext plaintextA;
    Plaintext plaintextB;

    Ciphertext<DCRTPoly> ciphertextB;

    plaintextA = cc->MakePackedPlaintext(rec_a_tokens);
    plaintextB = cc->MakePackedPlaintext(rec_b_tokens);

    ciphertextB = cc->Encrypt(keyPair.publicKey, plaintextB);

    bool er;
    if (mode == "vr") {
      er = isMatchViaOverlap(cc, keyPair, plaintextA, ciphertextB, threshold, plaintextB->GetLength());
    } else {
      vector<Ciphertext<DCRTPoly>> ciphertextB_ext;

      for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
        ciphertextB_ext.push_back(cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({rec_b_tokens[i]})));
      }
      er = isMatchViaExtension2(cc, keyPair, plaintextA, ciphertextB_ext, threshold, plaintextB->GetLength());
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
      a = cc->MakePackedPlaintext({rec_a_tokens[i]});
      plaintextA.push_back(a);
    }

    for (unsigned int i = 0; i < rec_b_tokens.size(); i++) {
      Plaintext b;
      b = cc->MakePackedPlaintext({rec_b_tokens[i]});
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
      if (decryptResult->GetPackedValue()[0] == 0) {
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

  vector<int64_t> a = recA->GetPackedValue();
  if (a.size() < b_size) {
    while (a.size() < b_size) {
      a.push_back(INT_MIN);
    }
  }
  recA = cc->MakePackedPlaintext(a);

  float overlap = 0;
  auto d = cc->EvalSub(recA, cipherB);
  Plaintext decryptResult;
  cc->Decrypt(keyPair.secretKey, d, &decryptResult);
  decryptResult->SetLength(b_size);

  overlap += count(decryptResult->GetPackedValue().begin(),
                   decryptResult->GetPackedValue().end(), 0);

  unsigned int idx = 1;
  while (idx < a.size()) {
    std::rotate(a.begin(), a.begin() + 1, a.end());
    recA = cc->MakePackedPlaintext(a);

    auto d = cc->EvalSub(recA, cipherB);

    Plaintext decryptResult;
    cc->Decrypt(keyPair.secretKey, d, &decryptResult);
    decryptResult->SetLength(b_size);

    overlap += count(decryptResult->GetPackedValue().begin(),
                     decryptResult->GetPackedValue().end(), 0);

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
      if (decryptResult->GetPackedValue()[0] == 0) {
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


bool isMatchViaExtension2(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Plaintext recA, vector<Ciphertext<DCRTPoly>> cipherB,
                       float threshold, int b_size) {

  int a_size = recA->GetLength();
  cc->EvalAtIndexKeyGen(keyPair.secretKey, {-a_size});

  int match_counter = 0;

  for (int i = 0; i < cipherB.size(); i++) {
    auto curr = cipherB[i];
    curr = cc->EvalAtIndex(curr, -a_size);

    auto d = cc->EvalSub(recA, cc->EvalSum(curr, a_size));
    Plaintext decryptResult;
    cc->Decrypt(keyPair.secretKey, d, &decryptResult);
    decryptResult->SetLength(a_size);
    //cout << decryptResult << endl;
    match_counter += count(decryptResult->GetPackedValue().begin(), decryptResult->GetPackedValue().end(), 0);
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