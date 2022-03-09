#include "palisade.h"
#include "palisadecore.h"

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

map<int, vector<string>> readBlocks(string csvFilePath);


bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
                       Plaintext recA, Ciphertext<DCRTPoly> cipherB,
                       float threshold, int b_size);


double jaccardDuration = 0;

int main(int argc, char** argv) {
  string path = std::__fs::filesystem::current_path();

  string ds1 = argv[1];
  string ds2 = argv[2];

  cout << ds1 << endl;
  cout << ds2 << endl;

  // Instantiate the CKKS crypto context
  unsigned int multDepth = 2;
  unsigned int scaleFactorBits = 30;
  unsigned int batchSize = 2048;
  SecurityLevel securityLevel = HEStd_128_classic;

  CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize, securityLevel, 0,
          EXACTRESCALE, HYBRID, 0, 2, 60, 0, OPTIMIZED);

  //Enable features that to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  LPKeyPair<DCRTPoly> kp1;

  kp1 = cc->KeyGen();
  cc->EvalSumKeyGen(kp1.secretKey);
  cc->EvalMultKeyGen(kp1.secretKey);

  map<tuple<string, string>, vector<complex<double>>> setA =
      readFromCSVFile(path + "/../../test_data/" + ds1);
  map<tuple<string, string>, vector<complex<double>>> setB =
      readFromCSVFile(path + "/../../test_data/" + ds2);

  map<int, Plaintext> plain_setA;
  map<int, Plaintext> plain_setB;
  map<int, Ciphertext<DCRTPoly>> encrypted_setB;

  for (auto rec : setA) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakeCKKSPackedPlaintext(get<1>(rec));
    plain_setA[x] = p;
  }

  for (auto rec : setB) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakeCKKSPackedPlaintext(get<1>(rec));
    plain_setB[x] = p;
    encrypted_setB[x] = cc->Encrypt(kp1.publicKey, p);
  }


  auto start = std::chrono::high_resolution_clock::now();

  map<int, vector<string>> blocksA =
      readBlocks(path + "/../../test_data/" + ds1);
  map<int, vector<string>> blocksB =
      readBlocks(path + "/../../test_data/" + ds2);

  map<string, vector<int>> reversedIndexA;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexA;

  map<string, vector<int>> reversedIndexB;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexB;


  map<int, Ciphertext<DCRTPoly>> setB_ids =
      encrypt_set_ids_ckks(cc, kp1, setB.size());

  vector<complex<double>> f = {0};
  auto false_val = cc->Encrypt(kp1.publicKey, cc->MakeCKKSPackedPlaintext(f));

  vector<complex<double>> t = {1};
  auto true_val = cc->Encrypt(kp1.publicKey, cc->MakeCKKSPackedPlaintext(t));

  vector<int> setA_ids(setA.size());
  std::iota (std::begin(setA_ids), std::end(setA_ids), 0);


  vector<Ciphertext<DCRTPoly>> enc_setB_ids;
  for (auto id : setB_ids) {
    enc_setB_ids.push_back(get<1>(id));
  }

  srand(time(NULL));
  vector<complex<double>> random_num_gen{(rand() % 10) + 1};
  auto r = cc->Encrypt(kp1.publicKey, cc->MakeCKKSPackedPlaintext(random_num_gen));

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

  for (auto reverse_block : reversedIndexB) {
    vector<int> ids = get<1>(reverse_block);
    vector<Ciphertext<DCRTPoly>> enc_ids;
    for (int i = 0; i < ids.size(); i++) {
      vector<complex<double>> test = {ids[i]};
      enc_ids.push_back(setB_ids[ids[i]]);
    }
    encReversedIndexB[get<0>(reverse_block)] = enc_ids;
  }

  auto stop = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = stop - start;
  cout << "time taken for generating block data structures: "
       << duration.count() << " ms" << endl;


// map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> noise_pairs =
//       gen_noise_matrix(
//           row_ids, col_ids, 0, true_val,
//           false_val);  // omega needs to be within 0 and (sizeA * sizeB)


//___________________________PARTY 3 Starts here___________________________


map<int, vector<Ciphertext<DCRTPoly>>> cand_pairs;
  for (auto id: setA_ids) {
    vector<Ciphertext<DCRTPoly>> row(setB.size(), false_val);
    cand_pairs[id] = row;
  }

  for (auto b_key : reversedIndexA) {
    string key = get<0>(b_key);
    if (encReversedIndexB.find(key) == encReversedIndexB.end()) {
      continue;
    } else {
      vector<int> a_ids = reversedIndexA[key];
      vector<Ciphertext<DCRTPoly>> b_ids = encReversedIndexB[key];

      for (int i = 0; i < a_ids.size(); i++) {
        int a_id = a_ids[i];
        for (int j = 0; j < b_ids.size(); j++) {
          auto enc_b_id = b_ids[j];
          cand_pairs[a_id] = row_update_ckks_sr(cc, kp1, cand_pairs[a_id], enc_b_id, enc_setB_ids, true_val, r);
        }
      }
    }
  }

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for deduplication & candidate pair generation: "
       << duration.count() << " ms" << endl;

  start = std::chrono::high_resolution_clock::now();

  //auto obfu_pairs = matrix_union(cc, cand_pairs, noise_pairs);
  auto obfu_pairs = cand_pairs;

  map<int, vector<bool>> results;


  map<int, vector<double>> obfu_pairs_clear;
  //map<Ciphertext<DCRTPoly>, vector<bool>> result;
  Plaintext decryptResult;
  for (auto mapping : obfu_pairs) {
    int row_idx = get<0>(mapping);
    vector<Ciphertext<DCRTPoly>> col_idxs = get<1>(mapping);
    vector<double> decrypted_row;
    for (int i = 0; i < col_idxs.size(); i++) {
      cc->Decrypt(kp1.secretKey, col_idxs[i], &decryptResult);
      decrypted_row.push_back(
          (double)decryptResult->GetCKKSPackedValue()[0].real());
    }
       // cout << row_idx << endl;
       // cout << decrypted_row << endl;
    obfu_pairs_clear[row_idx] = decrypted_row;
  }


  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for obfuscation: " << duration.count() << " ms" << endl;

  start = std::chrono::high_resolution_clock::now();

  int psi = 0;
  float threshold = 0.5;
  for (auto pair : obfu_pairs_clear) {
    int row_idx = get<0>(pair);
    vector<double> col_idxs = get<1>(pair);
    for (int j = 0; j < col_idxs.size(); j++) {
      if (col_idxs[j] >= 0.9) {
        bool er = isMatchViaOverlap(cc, kp1, plain_setA[row_idx], encrypted_setB[j], threshold, 
          (int) plain_setB[j]->GetLength());
        psi += er;
        vector<bool> row = results[row_idx];
        row[j] = er;
        results[row_idx] = row;
      }
    }
  }

  // auto final_results = matrix_choose(cc, cand_pairs, results);

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for filtering: " << duration.count() << " ms" << endl;

  cout << "Total # of true pairs found: " << psi << endl;

  cout << "time taken for just jaccard calculations: " << jaccardDuration
       << " ms" << endl;


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