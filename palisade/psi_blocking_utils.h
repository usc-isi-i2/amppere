#include "palisade.h"

#include <time.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <chrono>
#include "omp.h"

using namespace std;
using namespace lbcrypto;

Ciphertext<DCRTPoly> eeq_ckks_sr(CryptoContext<DCRTPoly> cc,
                              LPKeyPair<DCRTPoly> keyPair,
                              Ciphertext<DCRTPoly> first,
                              Ciphertext<DCRTPoly> second,
                              Ciphertext<DCRTPoly> r) {
//     auto start = std::chrono::high_resolution_clock::now();

  auto eps = 0.0001;
  Plaintext decryptResult;

  auto val = cc->EvalSub(first, second);
  auto val_with_eps = cc->EvalAdd(val, eps);

  auto re = cc->EvalMult(val_with_eps, r);
  cc->Decrypt(keyPair.secretKey, re, &decryptResult);
  auto reciprocal = -1 / (decryptResult->GetCKKSPackedValue()[0].real());

  vector<complex<double>> test2{reciprocal};
  auto enc_rec =
      cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(test2));

  auto final = cc->EvalAdd(cc->EvalMult(val, cc->EvalMult(enc_rec, r)), 1);
//
//     auto stop = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = stop - start;
//     cout << "time taken (s): " << duration.count() << " ms" << endl;

  return final;
}


Ciphertext<DCRTPoly> eeq_ckks(CryptoContext<DCRTPoly> cc,
                              LPKeyPair<DCRTPoly> keyPair,
                              LPKeyPair<DCRTPoly> multiKeyPair,
                              Ciphertext<DCRTPoly> first,
                              Ciphertext<DCRTPoly> second,
                              Ciphertext<DCRTPoly> r) {
//     auto start = std::chrono::high_resolution_clock::now();

  auto eps = 0.0001;
  Plaintext decryptResult;

  auto val = cc->EvalSub(first, second);
  auto val_with_eps = cc->EvalAdd(val, eps);

  auto re = cc->EvalMult(val_with_eps, r);
  cc->Decrypt(multiKeyPair.secretKey, re, &decryptResult);
  auto reciprocal = -1 / (decryptResult->GetCKKSPackedValue()[0].real());

  vector<complex<double>> test2{reciprocal};
  auto enc_rec =
      cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(test2));

  auto final = cc->EvalAdd(cc->EvalMult(val, cc->EvalMult(enc_rec, r)), 1);
//
//     auto stop = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double, std::milli> duration = stop - start;
//     cout << "time taken (s): " << duration.count() << " ms" << endl;

  return final;
}

Ciphertext<DCRTPoly> eeq_bgv(CryptoContext<DCRTPoly> cc,
                             LPKeyPair<DCRTPoly> keyPair,
                             Ciphertext<DCRTPoly> first,
                             Ciphertext<DCRTPoly> second,
                             Ciphertext<DCRTPoly> r1, Ciphertext<DCRTPoly> r2,
                             Ciphertext<DCRTPoly> r3) {
//  auto start = std::chrono::high_resolution_clock::now();

  auto eps = 1;
  Plaintext d1;
  Plaintext d2;
  Plaintext d3;
  Plaintext d4;

  auto r_first = cc->EvalMult(r3, cc->EvalMult(first, r1));
  auto r_second = cc->EvalMult(r3, cc->EvalMult(second, r2));
  auto r_val_one = cc->EvalMult(r1, cc->EvalMult(cc->EvalSub(first, second), r3));
  auto r_val_two = cc->EvalMult(r2, cc->EvalMult(cc->EvalSub(first, second), r3));

  cc->Decrypt(keyPair.secretKey, r_first, &d1);
  cc->Decrypt(keyPair.secretKey, r_second, &d2);
  cc->Decrypt(keyPair.secretKey, r_val_one, &d3);
  cc->Decrypt(keyPair.secretKey, r_val_two, &d4);

  int64_t val_one = std::round(-d1->GetPackedValue()[0] / ((d3->GetPackedValue()[0]) + eps));
  int64_t val_two = std::round(d2->GetPackedValue()[0] / ((d4->GetPackedValue()[0]) + eps));
  auto first_quantity = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({val_one}));
  auto second_quantity = cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext({val_two}));

  auto final = cc->EvalAdd(first_quantity, second_quantity);
  final = cc->EvalAdd(final, cc->MakePackedPlaintext({1}));

//  cout << first_quantity << ", " << second_quantity << endl;
//
//   auto stop = std::chrono::high_resolution_clock::now();
//   std::chrono::duration<double, std::milli> duration = stop - start;
//   cout << "time taken (s): " << duration.count() << " ms" << endl;

  return final;
}

vector<Ciphertext<DCRTPoly>> row_update_bgv(
    CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
    vector<Ciphertext<DCRTPoly>> row, Ciphertext<DCRTPoly> col_id,
    vector<Ciphertext<DCRTPoly>> col_ids, Ciphertext<DCRTPoly> val,
    Ciphertext<DCRTPoly> r1, Ciphertext<DCRTPoly> r2, Ciphertext<DCRTPoly> r3) {
  //  auto start = std::chrono::high_resolution_clock::now();

#pragma omp parallel for
  for (int i = 0; i < col_ids.size(); i++) {
    row[i] = cc->EvalAdd(row[i],
                         eeq_bgv(cc, keyPair, col_ids[i], col_id, r1, r2, r3));
  }

  return row;
}


vector<Ciphertext<DCRTPoly>> row_update_ckks_sr(
    CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair,
    vector<Ciphertext<DCRTPoly>> row, Ciphertext<DCRTPoly> col_id,
    vector<Ciphertext<DCRTPoly>> col_ids, Ciphertext<DCRTPoly> val,
    Ciphertext<DCRTPoly> r) {
  //  auto start = std::chrono::high_resolution_clock::now();

#pragma omp parallel for
  for (int i = 0; i < col_ids.size(); i++) {
    row[i] = cc->EvalAdd(row[i], eeq_ckks_sr(cc, keyPair, col_ids[i], col_id, r));
  }

  //  Plaintext decryptResult;
  //  vector<double> decrypted_row;
  //  for (int i = 0; i < row.size(); i++) {
  //    cc->Decrypt(keyPair.secretKey, row[i], &decryptResult);
  //    decrypted_row.push_back(decryptResult->GetCKKSPackedValue()[0].real());
  //  }
  //
  //  cout << decrypted_row << endl;

  //  auto stop = std::chrono::high_resolution_clock::now();
  //  std::chrono::duration<double, std::milli> duration = stop - start;
  //  cout << "time for row mask gen: "
  //       << duration.count() << " ms" << endl;
  return row;
}


vector<Ciphertext<DCRTPoly>> row_update_ckks(
    CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> keyPair, LPKeyPair<DCRTPoly> multiKeyPair,
    vector<Ciphertext<DCRTPoly>> row, Ciphertext<DCRTPoly> col_id,
    vector<Ciphertext<DCRTPoly>> col_ids, Ciphertext<DCRTPoly> val,
    Ciphertext<DCRTPoly> r) {
  //  auto start = std::chrono::high_resolution_clock::now();

#pragma omp parallel for
  for (int i = 0; i < col_ids.size(); i++) {
    row[i] = cc->EvalAdd(row[i], eeq_ckks(cc, keyPair, multiKeyPair, col_ids[i], col_id, r));
  }

  //  Plaintext decryptResult;
  //  vector<double> decrypted_row;
  //  for (int i = 0; i < row.size(); i++) {
  //    cc->Decrypt(keyPair.secretKey, row[i], &decryptResult);
  //    decrypted_row.push_back(decryptResult->GetCKKSPackedValue()[0].real());
  //  }
  //
  //  cout << decrypted_row << endl;

  //  auto stop = std::chrono::high_resolution_clock::now();
  //  std::chrono::duration<double, std::milli> duration = stop - start;
  //  cout << "time for row mask gen: "
  //       << duration.count() << " ms" << endl;
  return row;
}

map<int, Ciphertext<DCRTPoly>> encrypt_set_ids_bgv(CryptoContext<DCRTPoly> cc,
                                                   LPKeyPair<DCRTPoly> keyPair,
                                                   int size) {
  map<int, Ciphertext<DCRTPoly>> enc_values;

  //  std::vector<int> random_ids(size);
  //  std::iota (std::begin(random_ids), std::end(random_ids), 1);
  //
  //  auto rng = std::default_random_engine{};
  //  std::shuffle(std::begin(random_ids), std::end(random_ids), rng);

  int idx = 0;
  while (idx < size) {
    vector<int64_t> test = {idx};
    enc_values[idx] =
        cc->Encrypt(keyPair.publicKey, cc->MakePackedPlaintext(test));
    idx++;
  }

  return enc_values;
}

map<int, Ciphertext<DCRTPoly>> encrypt_set_ids_ckks(CryptoContext<DCRTPoly> cc,
                                                    LPKeyPair<DCRTPoly> keyPair,
                                                    int size) {
  map<int, Ciphertext<DCRTPoly>> enc_values;

  //  std::vector<int> random_ids(size);
  //  std::iota (std::begin(random_ids), std::end(random_ids), 1);
  //
  //  auto rng = std::default_random_engine{};
  //  std::shuffle(std::begin(random_ids), std::end(random_ids), rng);

  int idx = 0;
  while (idx < size) {
    vector<complex<double>> test = {idx};
    enc_values[idx] =
        cc->Encrypt(keyPair.publicKey, cc->MakeCKKSPackedPlaintext(test));
    idx++;
  }

  return enc_values;
}


map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> matrix_choose(
    CryptoContext<DCRTPoly> cc,
map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> m1,
map<Ciphertext<DCRTPoly>, vector<bool>> m2) {

  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> m3;

  for (auto mapping: m2) {
    Ciphertext<DCRTPoly> row_idx = get<0>(mapping);
    auto m1_row = m1[row_idx];
    auto m2_row = m2[row_idx];

    vector<Ciphertext<DCRTPoly>> row(m1_row.size());
    #pragma omp parallel for
    for (int i = 0; i < m1_row.size(); i++) {
      row[i] = cc->EvalMult(m1_row[i], m2_row[i]);
    }

    m3[row_idx] = row;
  }

  return m3;
}


map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> matrix_union(
    CryptoContext<DCRTPoly> cc,
    map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> m1,
    map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> m2) {
  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> m3;

  for (auto mapping : m1) {
    auto key = mapping.first;
    auto val = mapping.second;

    vector<Ciphertext<DCRTPoly>> row;
//    #pragma omp parallel for
    for (int i = 0; i < val.size(); i++) {
      row.push_back(cc->EvalAdd(m1[key][i], m2[key][i]));
    }

    m3[key] = row;
  }

  return m3;
}

map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> gen_noise_matrix(
    vector<Ciphertext<DCRTPoly>> enc_set_a_ids,
    vector<Ciphertext<DCRTPoly>> enc_set_b_ids, int omega,
    Ciphertext<DCRTPoly> true_val, Ciphertext<DCRTPoly> false_val) {
  map<Ciphertext<DCRTPoly>, vector<Ciphertext<DCRTPoly>>> noise_pairs;
  if (omega == 0) {
    return noise_pairs;
  }
  for (auto enc_id : enc_set_a_ids) {
    vector<Ciphertext<DCRTPoly>> row;
    for (int i = 0; i < enc_set_b_ids.size(); i++) {
      int placeholder = (rand() % 10);
      if (placeholder != 0 && omega > 0) {
        row.push_back(true_val);
        omega--;
      } else {
        row.push_back(false_val);
      }
    }
    noise_pairs[enc_id] = row;
  }

  return noise_pairs;
}

bool jaccard(float match_counter, float a_size, float b_size, float threshold) {
  float jaccardSimilarity =
      (match_counter) / ((a_size + b_size) - match_counter);
  cout << jaccardSimilarity << endl;
  return jaccardSimilarity >= threshold;
}
