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
#include "psi_blocking_utils.h"

using namespace std;
using namespace lbcrypto;

map<tuple<string, string>, vector<complex<double>>> readFromCSVFile(
    string csvFilePath);

map<int, vector<string>> readBlocks(string csvFilePath);

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc,
                       LPKeyPair<DCRTPoly> kp1,
                       LPKeyPair<DCRTPoly> kp2,
                       LPKeyPair<DCRTPoly> kpMultiparty,
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
  cc->Enable(MULTIPARTY);

   // cout << *cc->GetElementParams() << endl;

  //Initialize Public Key Containers
  LPKeyPair<DCRTPoly> kp1;
  LPKeyPair<DCRTPoly> kp2;
  LPKeyPair<DCRTPoly> kpMultiparty;

  //Generate a public/private key pairs
  kp1 = cc->KeyGen();
  cc->EvalSumKeyGen(kp1.secretKey);
  cc->EvalMultKeyGen(kp1.secretKey);
  kp2 = cc->MultipartyKeyGen(kp1.publicKey);

  // sum eval key
  auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
      cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

  auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());
  auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());

  // mult eval key
  auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);

  auto evalMultKey2 =
      cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);

  auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2,
                                         kp2.publicKey->GetKeyTag());

  auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey,
                                          kp2.publicKey->GetKeyTag());

  auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey,
                                          kp2.publicKey->GetKeyTag());
  auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB,
                                                evalMultAB->GetKeyTag());

  cc->InsertEvalSumKey(evalSumKeysJoin);
  cc->InsertEvalMultKey({evalMultFinal});

  vector<LPPrivateKey<DCRTPoly>> secretKeys;
  secretKeys.push_back(kp1.secretKey);
  secretKeys.push_back(kp2.secretKey);

  kpMultiparty = cc->MultipartyKeyGen(secretKeys);

  map<tuple<string, string>, vector<complex<double>>> setA =
      readFromCSVFile(path + "/../test_data/" + ds1);
  map<tuple<string, string>, vector<complex<double>>> setB =
      readFromCSVFile(path + "/../test_data/" + ds2);

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
    encrypted_setA[x] = cc->Encrypt(kp2.publicKey, p);
  }

  for (auto rec : setB) {
    stringstream id(get<0>(get<0>(rec)));
    int x = 0;
    id >> x;
    Plaintext p = cc->MakeCKKSPackedPlaintext(get<1>(rec));
    plain_setB[x] = p;
    encrypted_setB[x] = cc->Encrypt(kp2.publicKey, p);
  }
  
  auto start = std::chrono::high_resolution_clock::now();

  map<int, vector<string>> blocksA =
      readBlocks(path + "/../test_data/" + ds1);
  map<int, vector<string>> blocksB =
      readBlocks(path + "/../test_data/" + ds2);

  map<string, vector<int>> reversedIndexA;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexA;

  map<string, vector<int>> reversedIndexB;
  map<string, vector<Ciphertext<DCRTPoly>>> encReversedIndexB;

  map<int, Ciphertext<DCRTPoly>> setA_ids =
      encrypt_set_ids_ckks(cc, kp2, setA.size());
  map<int, Ciphertext<DCRTPoly>> setB_ids =
      encrypt_set_ids_ckks(cc, kp2, setB.size());

  vector<complex<double>> f = {0};
  auto false_val = cc->Encrypt(kp2.publicKey, cc->MakeCKKSPackedPlaintext(f));

  vector<complex<double>> t = {1};
  auto true_val = cc->Encrypt(kp2.publicKey, cc->MakeCKKSPackedPlaintext(t));

  vector<Ciphertext<DCRTPoly>> enc_setA_ids;
  for (auto id : setA_ids) {
    enc_setA_ids.push_back(get<1>(id));
  }

  vector<Ciphertext<DCRTPoly>> enc_setB_ids;
  for (auto id : setB_ids) {
    enc_setB_ids.push_back(get<1>(id));
  }

  srand(time(NULL));
  vector<complex<double>> random_num_gen{(rand() % 10) + 1};
  auto r =
      cc->Encrypt(kp2.publicKey, cc->MakeCKKSPackedPlaintext(random_num_gen));

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
      vector<complex<double>> test = {ids[i]};
      enc_ids.push_back(setA_ids[ids[i]]);
    }
    encReversedIndexA[get<0>(reverse_block)] = enc_ids;
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

  vector<Ciphertext<DCRTPoly>> col_ids;
  vector<Ciphertext<DCRTPoly>> row_ids;
  map<string, vector<Ciphertext<DCRTPoly>>> rowIndex;
  map<string, vector<Ciphertext<DCRTPoly>>> colIndex;
  map<int, Plaintext> row_set;
  map<int, Plaintext> col_set;
  map<int, Ciphertext<DCRTPoly>> enc_row_set;
  map<int, Ciphertext<DCRTPoly>> enc_col_set;
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

  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> noise_pairs =
      gen_noise_matrix(
          row_ids, col_ids, 0, true_val,
          false_val);  // omega needs to be within 0 and (sizeA * sizeB)

  //___________________________PARTY 3 Starts here___________________________

  start = std::chrono::high_resolution_clock::now();

  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> cand_pairs;
  for (auto id : row_ids) {
    vector<Ciphertext<DCRTPoly>> row(col_ids.size(), false_val);
    cand_pairs[id] = row;
  }

  for (auto b_key : rowIndex) {
    string key = get<0>(b_key);
    if (colIndex.find(key) == colIndex.end()) {
      continue;
    } else {
      vector<Ciphertext<DCRTPoly>> a_ids = rowIndex[key];
      vector<Ciphertext<DCRTPoly>> b_ids = colIndex[key];

      //      #pragma omp parallel for
      for (int i = 0; i < a_ids.size(); i++) {
        auto enc_a_id = a_ids[i];
        //        #pragma omp parallel for
        for (int j = 0; j < b_ids.size(); j++) {
          auto enc_b_id = b_ids[j];
          cand_pairs[enc_a_id] =
              row_update_ckks(cc, kp2, kpMultiparty, cand_pairs[enc_a_id],
                              enc_b_id, col_ids, true_val, r);
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

  map<Ciphertext<DCRTPoly>, vector<bool>> results;

  for (auto mapping : cand_pairs) {
    Ciphertext<DCRTPoly> row_idx = get<0>(mapping);
    vector<bool> row(col_ids.size(), 0);
    results[row_idx] = row;
  }

  map<double, vector<double>> obfu_pairs_clear;
  map<int, Ciphertext<DCRTPoly>> row_id_mapping;

  map<Ciphertext<DCRTPoly>, vector<bool>> result;
  Plaintext decryptResult;
  for (auto mapping : obfu_pairs) {
    Ciphertext<DCRTPoly> row_idx = get<0>(mapping);
    vector<Ciphertext<DCRTPoly>> col_idxs = get<1>(mapping);
    cc->Decrypt(kpMultiparty.secretKey, row_idx, &decryptResult);
    double key = (double)decryptResult->GetCKKSPackedValue()[0].real();
    row_id_mapping[std::round(key)] = row_idx;
    vector<double> decrypted_row;
    for (int i = 0; i < col_idxs.size(); i++) {
      cc->Decrypt(kpMultiparty.secretKey, col_idxs[i], &decryptResult);
      decrypted_row.push_back(
          (double)decryptResult->GetCKKSPackedValue()[0].real());
    }
    //    cout << key << endl;
    //    cout << decrypted_row << endl;
    obfu_pairs_clear[key] = decrypted_row;
  }

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for obfuscation: " << duration.count() << " ms" << endl;

  start = std::chrono::high_resolution_clock::now();

  int psi = 0;
  float threshold = 0.5;
  for (auto pair : obfu_pairs_clear) {
    double row_idx = get<0>(pair);
    vector<double> col_idxs = get<1>(pair);
    //    #pragma omp parallel for
    for (int j = 0; j < col_idxs.size(); j++) {
      if (col_idxs[j] >= 0.9) {
        cout << (unsigned)std::round(row_idx) << ", " << j << endl;
        bool er = isMatchViaOverlap(cc, kp1, kp2, kpMultiparty, enc_col_set[j],
                                    enc_row_set[(unsigned)std::round(row_idx)],
                                    threshold, (int)col_set[j]->GetLength(),
                                    (int)row_set[row_idx]->GetLength());
        psi += er;
        vector<bool> row =
            results[row_id_mapping[(unsigned)std::round(row_idx)]];
        row[j] = er;
        results[row_id_mapping[(unsigned)std::round(row_idx)]] = row;
      }
    }
  }

  auto final_results = matrix_choose(cc, cand_pairs, results);

  stop = std::chrono::high_resolution_clock::now();
  duration = stop - start;
  cout << "time taken for filtering: " << duration.count() << " ms" << endl;

  cout << "Total # of true pairs found: " << psi << endl;

  cout << "time taken for just jaccard calculations: " << jaccardDuration
       << " ms" << endl;
}

bool isMatchViaOverlap(CryptoContext<DCRTPoly> cc,
                       LPKeyPair<DCRTPoly> kp1,
                       LPKeyPair<DCRTPoly> kp2,
                       LPKeyPair<DCRTPoly> kpMultiParty,
                       Ciphertext<DCRTPoly> cipherA,
                       Ciphertext<DCRTPoly> cipherB, float threshold,
                       int a_size, int b_size) {


  // rotation eval key
  std::vector<int> rotationIndices(a_size * 2);
  std::iota(std::begin(rotationIndices), std::end(rotationIndices), -a_size);

  cc->EvalAtIndexKeyGen(kp1.secretKey, rotationIndices);

  auto evalAtIndexKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
  cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

  auto evalAtIndexKeysB =
      cc->MultiEvalAtIndexKeyGen(kp2.secretKey, evalAtIndexKeys,
                                 rotationIndices, kp2.publicKey->GetKeyTag());

  auto evalAtIndexKeysJoin = cc->MultiAddEvalAutomorphismKeys(
      evalAtIndexKeys, evalAtIndexKeysB, kp2.publicKey->GetKeyTag());

  cc->InsertEvalAutomorphismKey(evalAtIndexKeysJoin);

  float overlap = 0;
  Plaintext plaintextMultipartyNew;

  unsigned int idx = 0;
  Ciphertext<DCRTPoly> d = nullptr;
  while (idx < a_size) {
    if (idx > 0) {
      auto rot1 = cc->EvalAtIndex(cipherA, idx);
      auto rot2 = cc->EvalAtIndex(cipherA, idx - a_size);
      auto merged = cc->EvalAdd(rot1, rot2);

      d = cc->EvalSub(merged, cipherB);
    } else {
      d = cc->EvalSub(cipherA, cipherB);
    }

    cc->Decrypt(kpMultiParty.secretKey, d, &plaintextMultipartyNew);
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