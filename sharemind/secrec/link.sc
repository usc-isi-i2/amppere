import stdlib;
import shared3p;
import shared3p_sort;
import keydb;
import shared3p_keydb;
import oblivious;
import shared3p_statistics_common;
import profiling;

domain pd_shared3p shared3p;

float EPSILON = 0.00001;

template <domain D>
D bool jaccard(D uint64 inter, uint64 union, D float32 t) {
    // jaccard(x, y) = len(x & y) / len(x | y) 
    //               = len(x & y) / (len(x) + len(y) - len(x & y))
    D float32 jaccard_result = (float32)inter / ((float32)union - (float32)inter);

    return (jaccard_result + EPSILON) >= t;
}

template <domain D>
D bool jaccard_sort(D uint64 [[1]] a, D uint64 [[1]] b, D float32 t) {
    if (size(a) == 0 && size(b) == 0)
        return false;

    // both a and b can not have duplicated entries
    // a = [1, 2, 3], b = [3, 4]
    // c = [1, 2, 3, 3, 4]
    // c1 = [1, 2, 3, 3]
    // c2 = [2, 3, 3, 4]
    // intersection = sum(c1 == c2)
    D uint64 [[1]] c = cat(a, b);
    c = quicksort(c);
    D uint64 match_counter = sum(c[:size(c)-1] == c[1:]);

    return jaccard(match_counter, size(a) + size(b), t);
}

void main() {
    string a_prefix = argument("a_prefix");
    uint64 a_size = argument("a_size");
    string b_prefix = argument("b_prefix");
    uint64 b_size = argument("b_size");
    bool blocking = argument("blocking");
    string bprefix = argument("bprefix");
    pd_shared3p float32 t = argument("t");
    pd_shared3p float32 u = argument("u");
    
    keydb_connect("dbhost");


    uint32 stype1 = newSectionType("blocking");
    uint32 sec1 = startSection(stype1, (uint)1);
    // generate candidate pairs
    pd_shared3p bool[[2]] cand_pairs(a_size, b_size) = false;
    if (blocking) {

        ScanCursor a_cur = keydb_scan(bprefix + a_prefix + "*");
        // a_cur
        while (a_cur.cursor != 0) {
            pd_shared3p uint64[[1]] a_ids = keydb_get(a_cur.key);
            string key_suffix = substring(a_cur.key, strlen(bprefix + a_prefix), strlen(a_cur.key));

            // b_cur
            ScanCursor b_cur = keydb_scan(bprefix + b_prefix + key_suffix);
            if (b_cur.cursor != 0) {
                pd_shared3p uint64[[1]] b_ids = keydb_get(b_cur.key);

                for (uint i = 0; i < size(a_ids); i++) {
                    pd_shared3p uint a_id = a_ids[i];
                    for (uint j = 0; j < size(b_ids); j++) {
                        pd_shared3p uint b_id = b_ids[j];
                        pd_shared3p bool dummy_true = true;
                        cand_pairs = matrixUpdate(cand_pairs, a_id, b_id, dummy_true);
                    }
                }
            }
            a_cur = keydb_scan_next(a_cur);
        }
    }
    endSection(sec1);

    // Obfuscation
    // TODO: randomization
    bool [[2]] obfu_pairs = declassify(cand_pairs);

    // Filtering and entity resolution
    uint32 stype2 = newSectionType("filtering+jaccard");
    uint32 sec2 = startSection(stype2, (uint)1);
    pd_shared3p bool [[2]] results(a_size, b_size) = false;
    pd_shared3p bool [[2]] dummies(a_size, b_size) = false;

    for (uint64 i = 0; i < a_size; i++) {
        for (uint64 j = 0; j < b_size; j++) {

            // filtering
            if (obfu_pairs[i, j]) {
                string a_key = a_prefix + tostring(i);
                string b_key = b_prefix + tostring(j);
                pd_shared3p uint64 [[1]] a = keydb_get(a_key);
                pd_shared3p uint64 [[1]] b = keydb_get(b_key);

                // jaccard
                pd_shared3p bool jaccard_result = jaccard_sort(a, b, t);
                results[i, j] = jaccard_result;
            }
        }
    }
    results = choose(cand_pairs, results, dummies);
    endSection(sec2);
    
    keydb_disconnect();

    // flatten matrix and return
    pd_shared3p bool [[1]] return_results = reshape(results, size(results));
    publish("result", return_results);
}