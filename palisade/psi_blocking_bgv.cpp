#include "palisade.h"
#include <iostream>
#include <fstream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include "csvstream.h"
#include <sstream>
#include <chrono>
#include "psi_blocking_utils.h"

using namespace std;
using namespace lbcrypto;

map<tuple<string, string>, vector<int64_t>> readFromCSVFile(string csvFilePath);

map<int, vector<string>> readBlocks(string csvFilePath);

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size);

double jaccardDuration = 0;

int main(int argc, char** argv) {
  string path = std::__fs::filesystem::current_path();

  string ds1 = argv[1];
  string ds2 = argv[2];

  cout << ds1 << endl;
  cout << ds2 << endl;

  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  // Instantiate the BGVrns crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth);

  // Enable features that to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  //  cout << *cc->GetElementParams() << endl;
  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cc->KeyGen();

  cc->EvalSumKeyGen(keyPair.secretKey);
  cc->EvalMultKeyGen(keyPair.secretKey);

  map<tuple<string, string>, vector<int64_t>> setA =
      readFromCSVFile(path + "/../src/pke/examples/test_data/" + ds1);
  map<tuple<string, string>, vector<int64_t>> setB =
      readFromCSVFile(path + "/../src/pke/examples/test_data/" + ds2);


  map<int, Plaintext> plain_setA;
  map<int, Plaintext> plain_setB;
  map<int, Ciphertext<DCRTPoly>> encrypted_setA;
  map<int, Ciphertext<DCRTPoly>> encrypted_setB;

  for (auto rec : setA) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakePackedPlaintext(get<1>(rec));
    plain_setA[x] = p;
    encrypted_setA[x] = cc->Encrypt(keyPair.publicKey, p);
  }

  for (auto rec : setB) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakePackedPlaintext(get<1>(rec));
    plain_setB[x] = p;
    encrypted_setB[x] = cc->Encrypt(keyPair.publicKey, p);
  }
  auto start = std::chrono::high_resolution_clock::now();

  map<int, vector<string>> blocksA =
      readBlocks(path + "/../src/pke/examples/test_data/" + ds1);
  map<int, vector<string>> blocksB =
      readBlocks(path + "/../src/pke/examples/test_data/" + ds2);

  map<string, vector<int>> reversedIndexA;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexA;

  map<string, vector<int>> reversedIndexB;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexB;

  map<int, Ciphertext<DCRTPoly>> setA_ids =
      encrypt_set_ids_bgv(cc, keyPair, setA.size());
  map<int, Ciphertext<DCRTPoly>> setB_ids =
      encrypt_set_ids_bgv(cc, keyPair, setB.size());

  vector<int64_t> f = {0};
  auto false_val =
      cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(f));

  vector<int64_t> t = {1};
  auto true_val =
      cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(t));

  vector<Ciphertext<DCRTPoly>> enc_setA_ids;
  for (auto id : setA_ids) {
    enc_setA_ids.push_back(get<1>(id));
  }

  vector<Ciphertext<DCRTPoly>> enc_setB_ids;
  for (auto id : setB_ids) {
    enc_setB_ids.push_back(get<1>(id));
  }

  srand (time(NULL));
  vector<int64_t> random_num_gen1{(rand() % (int) min(setA.size(), setB.size())) + 1};
  vector<int64_t> random_num_gen2{(rand() % (int) min(setA.size(), setB.size())) + 1};
  vector<int64_t> random_num_gen3{(rand() % (int) min(setA.size(), setB.size())) + 1};

  cout << random_num_gen1 << ", " << random_num_gen2 << ", " << random_num_gen3 << endl;

  auto r1 = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(random_num_gen1));
  auto r2 = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(random_num_gen2));
  auto r3 = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(random_num_gen3));

  for (auto a_block : blocksA) {
    vector<string> b_keys = get<1>(a_block);
    for (string key : b_keys) {
      if (reversedIndexA.find(key) == reversedIndexA.end()) {
        reversedIndexA[key] = {get<0>(a_block)};
      } else {
        vector<int> intermediate = reversedIndexA[key];
        intermediate.push_back(get<0>(a_block));
        reversedIndexA[key] = intermediate;
      }
    }
  }

  for (auto b_block : blocksB) {
    vector<string> b_keys = get<1>(b_block);
    for (string key : b_keys) {
      if (reversedIndexB.find(key) == reversedIndexB.end()) {
        reversedIndexB[key] = {get<0>(b_block)};
      } else {
        vector<int> intermediate = reversedIndexB[key];
        intermediate.push_back(get<0>(b_block));
        reversedIndexB[key] = intermediate;
      }
    }
  }

  for (auto reverse_block : reversedIndexA) {
    vector<int> ids = get<1>(reverse_block);
    vector<Ciphertext<DCRTPoly>> enc_ids;
    for (int i = 0; i < ids.size(); i++) {
      vector<int64_t> test = {ids[i]};
      enc_ids.push_back(setA_ids[ids[i]]);
    }
    encReversedIndexA[get<0>(reverse_block)] = enc_ids;
  }

  for (auto reverse_block : reversedIndexB) {
    vector<int> ids = get<1>(reverse_block);
    vector<Ciphertext<DCRTPoly>> enc_ids;
    for (int i = 0; i < ids.size(); i++) {
      vector<int64_t> test = {ids[i]};
      enc_ids.push_back(setB_ids[ids[i]]);
    }
    encReversedIndexB[get<0>(reverse_block)] = enc_ids;
  }

  auto stop = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = stop - start;
  cout << "time taken for generating block data structures: "
       << duration.count() << " ms" << endl;


  vector<Ciphertext<DCRTPoly>> col_ids; vector<Ciphertext<DCRTPoly>> row_ids;
  map<string, vector<Ciphertext<DCRTPoly>>> rowIndex; map<string, vector<Ciphertext<DCRTPoly>>> colIndex;
  map<int, Plaintext> row_set; map<int, Plaintext> col_set;
  map<int, Ciphertext<DCRTPoly>> enc_row_set; map<int, Ciphertext<DCRTPoly>> enc_col_set;
  if (setA.size() <= setB.size()) {
    row_ids = enc_setB_ids;
    rowIndex = encReversedIndexB;
    row_set = plain_setB;
    enc_row_set = encrypted_setB;
    col_ids = enc_setA_ids;
    colIndex = encReversedIndexA;
    col_set = plain_setA;
    enc_col_set = encrypted_setA;
  } else {
    row_ids = enc_setA_ids;
    rowIndex = encReversedIndexA;
    row_set = plain_setA;
    enc_row_set = encrypted_setA;
    col_ids = enc_setB_ids;
    colIndex = encReversedIndexB;
    col_set = plain_setB;
    enc_col_set = encrypted_setB;
  }

  //___________________________PARTY 3 Starts here___________________________

  start = std::chrono::high_resolution_clock::now();

  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> cand_pairs;
  for (auto id: row_ids) {
    vector<Ciphertext<DCRTPoly>> row(col_ids.size(), false_val);
    cand_pairs[id] = row;
  }

  auto one = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({3}));
  auto two = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({5}));
  auto result = eeq_bgv(cc, keyPair, one, two, r1, r2, r3);

  Plaintext d;
  cc->Decrypt(keyPair.secretKey, result, &d);
  cout << d->GetPackedValue()[0] << endl;

//  for (auto b_key : rowIndex) {
//    string key = get<0>(b_key);
//    if (colIndex.find(key) == colIndex.end()) {
//      continue;
//    } else {
//      vector<Ciphertext<DCRTPoly>> a_ids = rowIndex[key];
//      vector<Ciphertext<DCRTPoly>> b_ids = colIndex[key];
//
////      #pragma omp parallel for
//      for (int i = 0; i < a_ids.size(); i++) {
//        auto enc_a_id = a_ids[i];
////        #pragma omp parallel for
//        for (int j = 0; j < b_ids.size(); j++) {
//          auto enc_b_id = b_ids[j];
//          cand_pairs[enc_a_id] = row_update_bgv(cc, keyPair, cand_pairs[enc_a_id], enc_b_id, col_ids, true_val, r);
//        }
//      }
//    }
//  }

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for deduplication & candidate pair generation: " << duration.count() << " ms" << endl;

  start = std::chrono::high_resolution_clock::now();

//  auto obfu_pairs = matrix_union(cc, cand_pairs, noise_pairs);


//  map<int, vector<int>> cand_pairs_clear;
//  Plaintext decryptResult;
//  for (auto mapping: cand_pairs) {
//    Ciphertext<DCRTPoly> row_idx = get<0>(mapping);
//    vector<Ciphertext<DCRTPoly>> col_idxs = get<1>(mapping);
//    cc->Decrypt(keyPair.secretKey, row_idx, &decryptResult);
//    int key = decryptResult->GetPackedValue()[0];
//    vector<int> decrypted_row;
//    for (int i = 0; i < col_idxs.size(); i++) {
//      cc->Decrypt(keyPair.secretKey, col_idxs[i], &decryptResult);
//      decrypted_row.push_back(decryptResult->GetPackedValue()[0]);
//    }
//    cout << key << endl;
//    cout << decrypted_row << endl;
//    cand_pairs_clear[key] = decrypted_row;
//  }

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for obfuscation: " << duration.count() << " ms" << endl;



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

  vector<int64_t> v = decryptResult->GetPackedValue();
  for (int i = 0; i < v.size(); i++) {
    if (v[i] == 0) {
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

    vector<int64_t> v = decryptResult->GetPackedValue();
    for (int i = 0; i < v.size(); i++) {
      if (v[i] == 0) {
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

map<int, vector<string>> readBlocks(string csvFilePath) {
  csvstream csvin(csvFilePath);
  map<int, vector<string>> blocks;
  map<string, string> row;

  while (csvin >> row) {
    string bKey = row["blocking_keys"];
    vector<string> b_keys;

    std::istringstream stm(bKey);
    std::string token;
    while (stm >> token) b_keys.push_back(token);

    stringstream id(row["id"]);
    int64_t x = 0;
    id >> x;
    blocks[x] = b_keys;
  }

  return blocks;
}

map<tuple<string, string>, vector<int64_t>> readFromCSVFile(string csvFilePath) {
  csvstream csvin(csvFilePath);

  map<tuple<string, string>, vector<int64_t>> records;
  map<string, string> row;

  while (csvin >> row) {
    tuple<string, string> ids{row["id"], row["original_id"]};

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

    records[ids] = tokens;
  }
  return records;
}