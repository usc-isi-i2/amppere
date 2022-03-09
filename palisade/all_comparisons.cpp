#include "palisade.h"
#include <iostream>
#include <fstream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include "csvstream.h"
#include <sstream>
#include <chrono>
#include "utils.h"

using namespace std;
using namespace lbcrypto;

map<tuple<string, string>, vector<complex<double>>> readFromCSVFile(
    string csvFilePath);


bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size);

double jaccardDuration = 0;

int main(int argc, char** argv) {
  string path = std::__fs::filesystem::current_path();

  string ds1 = argv[1];
  string ds2 = argv[2];

  // Instantiate the CKKS crypto context
  uint32_t multDepth = 1;         // 3
  uint32_t scaleFactorBits = 30;  // 40
  uint32_t batchSize = 2048;
  SecurityLevel securityLevel = HEStd_128_classic;
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize, securityLevel, 0,
          EXACTRESCALE);

  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cc->KeyGen();

  cc->EvalSumKeyGen(keyPair.secretKey);
  cc->EvalMultKeyGen(keyPair.secretKey);

  map<tuple<string, string>, vector<complex<double>>> setA =
      readFromCSVFile(path + "/../../test_data/" + ds1);
  map<tuple<string, string>, vector<complex<double>>> setB =
      readFromCSVFile(path + "/../../test_data/" + ds2);

  map<int, Plaintext> plain_setA;
  map<int, Plaintext> plain_setB;
  map<int, Ciphertext<DCRTPoly>> encrypted_setA;
  map<int, Ciphertext<DCRTPoly>> encrypted_setB;

  for (auto rec : setA) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakeCKKSPackedPlaintext(get<1>(rec));
    plain_setA[x] = p;
    encrypted_setA[x] = cc->Encrypt(keyPair.publicKey, p);
  }

  for (auto rec : setB) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakeCKKSPackedPlaintext(get<1>(rec));
    plain_setB[x] = p;
    encrypted_setB[x] = cc->Encrypt(keyPair.publicKey, p);
  }
  auto start = std::chrono::high_resolution_clock::now();

  map<int, Ciphertext<DCRTPoly>> setA_ids =
      encrypt_set_ids_ckks(cc, keyPair, setA.size());
  map<int, Ciphertext<DCRTPoly>> setB_ids =
      encrypt_set_ids_ckks(cc, keyPair, setB.size());

  vector<Ciphertext<DCRTPoly>> enc_setA_ids;
  for (auto id : setA_ids) {
    enc_setA_ids.push_back(get<1>(id));
  }

  vector<Ciphertext<DCRTPoly>> enc_setB_ids;
  for (auto id : setB_ids) {
    enc_setB_ids.push_back(get<1>(id));
  }

  //___________________________PARTY 3 Starts here___________________________

  map<int, vector<bool>> results;
  for (int i = 0; i < setA.size(); i++) {
    vector<bool> row(setA.size(), 0);
    results[i] = row;
  }

  int psi = 0;
  float threshold = 0.5;
  for (int i = 0; i < setA.size(); i++) {
    for (int j = 0; j < setB.size(); j++) {
      bool er = isMatchViaOverlap(cc, keyPair, encrypted_setA[i],
                             encrypted_setB[j],
                             threshold, plain_setA[i]->GetLength(),
                                  plain_setB[j]->GetLength());
      psi += er;
      vector<bool> row = results[i];
      row[j] = er;
      results[i] = row;
    }
  }

  auto stop = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = stop - start;
  cout << "time taken: "
       << duration.count() << " ms" << endl;

  cout << "Total # of true pairs found: " << psi << endl;

}

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size) {
  auto start = std::chrono::high_resolution_clock::now();

  std::vector<int> rotationIndices(a_size * 2);
  std::iota(std::begin(rotationIndices), std::end(rotationIndices), -a_size);

  cc->EvalAtIndexKeyGen(keyPair.secretKey, rotationIndices);

  float overlap = 0;

  auto d = cc->EvalSub(cipherA, cipherB);
  Plaintext decryptResult;
  cc->Decrypt(keyPair.secretKey, d, &decryptResult);
  decryptResult->SetLength(a_size);

  vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
  for (int i = 0; i < v.size(); i++) {
    if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
      overlap++;
    }
  }

  int idx = 1;
  while (idx < a_size) {
    auto rot1 = cc->EvalAtIndex(cipherA, idx);
    auto rot2 = cc->EvalAtIndex(cipherA, idx - a_size);

    auto merged = cc->EvalAdd(rot1, rot2);

    auto d = cc->EvalSub(merged, cipherB);

    Plaintext decryptResult;
    cc->Decrypt(keyPair.secretKey, d, &decryptResult);
    decryptResult->SetLength(a_size);

    vector<complex<double>> v = decryptResult->GetCKKSPackedValue();
    for (int i = 0; i < v.size(); i++) {
      if (v[i].real() <= 0.0005 && v[i].real() >= -0.0005) {
        overlap++;
      }
    }
    idx++;
  }

  float jaccardSimilarity = jaccard(overlap, a_size, b_size, threshold);

  auto stop = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = stop - start;
  jaccardDuration += duration.count();
  cout << "time taken (s): " << duration.count() << " ms" << endl;

  cout << "jaccard similarity score: " << jaccardSimilarity << endl;

  if (jaccardSimilarity >= threshold) {
    return true;
  } else {
    return false;
  }
}


map<tuple<string, string>, vector<complex<double>>> readFromCSVFile(
    string csvFilePath) {
  csvstream csvin(csvFilePath);

  map<tuple<string, string>, vector<complex<double>>> records;
  map<string, string> row;

  while (csvin >> row) {
    tuple<string, string> ids{row["id"], row["original_id"]};

    vector<complex<double>> tokens;

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

    records[ids] = tokens;
  }
  return records;
}