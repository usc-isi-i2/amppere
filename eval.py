import os
import csv
import sys
import argparse
import random
from collections import defaultdict


EPSILON = 0.00001;

def extract_ori_rec_id(s):
    return '-'.join(s.split('-')[:2])

def convert_tokens(ts):
    return set([int(t, 16) for t in ts])

def jaccard(a, b):
    return 1.0 * len(a & b) / len(a | b)

def jaccard_sort(a, b):
    c = list(a) + list(b)
    c = sorted(c)
    inter = sum([int(i == j) for i, j in zip(c[:-1], c[1:])])
    union = len(a) + len(b)
    print(inter, union)
    return 1.0 * inter / (union - inter)

def compute_blocking_metrics(num_of_blocked_comparison, num_full_pairwise_comparison, 
                    num_of_match_in_block, num_of_match):
    rr = 1 - 1.0 * num_of_blocked_comparison / num_full_pairwise_comparison
    pc = 1.0 * num_of_match_in_block / num_of_match
    f1 = 2.0 * pc * rr / (pc + rr)
    return round(pc, 2), round(rr, 2), round(f1, 2)

def compute_er_metrics(tp, tn, fp, fn):
    precision = (1.0 * tp / (tp + fp)) if tp + fp != 0 else 1
    recall = (1.0 * tp / (tp + fn)) if tp + fn != 0 else 1
    f1 = 2.0 * precision * recall / (precision + recall)
    return round(precision, 2), round(recall, 2), round(f1, 2)

def compute_er(ds1, ds2, t):
    tp, fp, tn, fn = 0, 0, 0, 0
    for r1id, r1token in ds1.items():
        for r2id, r2token in ds2.items():
            if jaccard(r1token, r2token) + EPSILON >= t:
                if (r1id, r2id) in true_pairs:
                    tp += 1
                else:
                    fp += 1
            else:
                if (r1id, r2id) in true_pairs:
                    fn += 1
                else:
                    tn += 1

    precision, recall, f1 = compute_er_metrics(tp, tn, fp, fn)
    return precision, recall, f1

def compute_er_with_blocking(ds1, ds2, t, blocked_comparison):
    tp, fp, tn, fn = 0, 0, 0, 0
    for r1id, r1token in ds1.items():
        for r2id, r2token in ds2.items():
            id_pair = (r1id, r2id)
            if id_pair in blocked_comps:
                if jaccard(r1token, r2token) + EPSILON >= t:
                    if id_pair in true_pairs:
                        tp += 1
                    else:
                        fp += 1
                else:
                    if id_pair in true_pairs:
                        fn += 1
                    else:
                        tn += 1
            else:
                if id_pair in true_pairs:
                    fn += 1
                else:
                    tn += 1

    precision, recall, f1 = compute_er_metrics(tp, tn, fp, fn)
    return precision, recall, f1

if __name__ == '__main__':
    '''
    # basic statistics
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv

    # evaluating blocking threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --blocking --threshold 0.8
    
    # evaluating entity resolution threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --er --er-threshold 0.8

    # evaluating er with blocking
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --blocking --threshold 0.8 --er --er-threshold 0.8

    # estimating entity resolution threshold
    python eval.py test_data/ds1_output_0.8.csv test_data/ds2_output_0.8.csv --er --search-threshold --epoch 3
    '''

    parser = argparse.ArgumentParser(description='Evaluate Febrl dataset')
    parser.add_argument('infile1', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('infile2', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('--blocking', dest='blocking', action='store_true')
    parser.add_argument('--threshold', dest='threshold', action='store', type=float)
    parser.add_argument('--er', dest='er', action='store_true')
    parser.add_argument('--er-threshold', dest='er_threshold', action='store', type=float)
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    parser.add_argument('--search-threshold', dest='search_threshold', action='store_true')
    parser.add_argument('--epoch', dest='epoch', type=int)
    args = parser.parse_args()

    fieldnames = ['id', 'original_id', 'tokens'] + ['blocking_keys'] if args.blocking else []
    csv1 = csv.DictReader(args.infile1)
    csv2 = csv.DictReader(args.infile2)

    bkey_per_record = 0
    ds1_ori_id_to_rec_id, ds2_ori_id_to_rec_id = defaultdict(set), defaultdict(set)
    ds1_ii, ds2_ii = defaultdict(set), defaultdict(set)
    ds1_size, ds2_size = 0, 0
    ds1, ds2 = {}, {}
    for idx, line in enumerate(csv1):
        if args.blocking and bkey_per_record == 0:
            bkey_per_record = len(line['blocking_keys'].split(' '))

        line['id'] = int(line['id'])
        ds1_size += 1
        ds1_ori_id_to_rec_id[extract_ori_rec_id(line['original_id'])].add(line['id'])
        if args.blocking:
            for bkey in line['blocking_keys'].split(' '):
                ds1_ii[bkey].add(line['id'])
        ds1[line['id']] = convert_tokens(set(line['tokens'].split(' ')))

    for idx, line in enumerate(csv2):
        line['id'] = int(line['id'])
        ds2_size += 1
        ds2_ori_id_to_rec_id[extract_ori_rec_id(line['original_id'])].add(line['id'])
        if args.blocking:
            for bkey in line['blocking_keys'].split(' '):
                ds2_ii[bkey].add(line['id'])
        ds2[line['id']] = convert_tokens(set(line['tokens'].split(' ')))

    print('----------------Summary----------------')
    true_pairs = set([])
    for k in (set(list(ds1_ori_id_to_rec_id.keys())) & set(list(ds2_ori_id_to_rec_id.keys()))):
        for i in ds1_ori_id_to_rec_id[k]:
            for j in ds2_ori_id_to_rec_id[k]:
                true_pairs.add((i,j))
    print(f'Total true pairs: {len(true_pairs)}')
    print(f'ds1 size: {ds1_size}, ds2 size: {ds2_size}')
    print(f'Full pairwise comparisons: {ds1_size * ds2_size}')

    if args.er and not args.blocking:
        print('---------------ER enabled---------------')
        print(f'Threshold: {args.er_threshold}')
        precision, recall, f1 = compute_er(ds1, ds2, args.er_threshold)
        print(f'Precision: {precision}, Recall: {recall}, F-score: {f1}')

    if args.blocking:
        print('------------Blocking enabled------------')
        print(f'Blocking key size (per record): {bkey_per_record}')
        print(f'Threshold: {args.threshold}')
        print(f'Unique blocking keys in ds1 / max possible: {len(ds1_ii)} / {bkey_per_record * ds1_size}')
        print(f'Unique blocking keys in ds2 / max possible: {len(ds2_ii)} / {bkey_per_record * ds2_size}')

        blocked_comps = set()
        shared_bkeys = set(list(ds1_ii.keys())) & set(list(ds2_ii.keys()))
        print(f'Shared blocking keys: {len(shared_bkeys)}')
        for k in shared_bkeys:
            for i in ds1_ii[k]:
                for j in ds2_ii[k]:
                    blocked_comps.add((i,j))
        blocked_comps = sorted(list(blocked_comps), key=lambda x: (x[0], x[1]))
        print(f'Blocked distinct comparisons: {len(blocked_comps)}')
        if args.verbose:
            print(blocked_comps)

        result = []
        for cand in blocked_comps:
            id1, id2 = cand
            score = jaccard(ds1[id1], ds2[id2])
            if score + EPSILON >= args.threshold:
                result.append(cand)
        print(f'Pairs found with blocking: {len(result)}')
        if args.verbose:
            print(result)

        not_in_block_true_pairs = list(true_pairs - set(result))
        print(f'Not in block true pairs: {len(not_in_block_true_pairs)}')
        if args.verbose:
            print(not_in_block_true_pairs)
        in_block_false_pairs = list(set(result) - true_pairs)
        print(f'In block false pairs: {len(in_block_false_pairs)}')
        if args.verbose:
            print(in_block_false_pairs)

        pc, rr, f1 = compute_blocking_metrics(len(blocked_comps), ds1_size * ds2_size, 
                                    len(true_pairs) - len(not_in_block_true_pairs), len(true_pairs))
        print(f'PC: {pc}, RR: {rr}, F-score: {f1}')

        if args.er: # er with blocking
            print(f'ER threshold: {args.er_threshold}')
            precision, recall, f1 = compute_er_with_blocking(ds1, ds2, args.er_threshold, blocked_comps)
            print(f'Precision: {precision}, Recall: {recall}, F-score: {f1}')

    if args.search_threshold:
        print('------------Threshold search------------')
        def squeeze_range(ls):
            l_idx, r_idx = None, None
            max_ = max(ls)
            # left
            for idx, v in enumerate(ls):
                if v == max_:
                    l_idx = max(0, idx - 1)
                    break
            # right
            for idx, v in reversed(list(enumerate(ls))):
                if v == max_:
                    r_idx = min(len(ls) - 1, idx + 1)
                    break
            return l_idx, r_idx

        def range_(l, r, s, d=1):
            '''float range'''
            return [1.0 * x / d for x in range(int(l * d), int(r * d), int(s * d))]

        def final_range(ls):
            max_ = max(ls)
            indices = []
            for idx, v in enumerate(ls):
                if v == max_:
                    indices.append(idx)
            if len(indices) > 2:
                indices = [indices[0], indices[-1]]
            return indices

        # 1st round
        step = 0.1
        d = 10
        t_range = range_(0, 1.1, step, d=d)
        f1s = []
        skip_range = [1, 0]  # skip unnecessary calculation
        for t in t_range:
            _, _, f1 = compute_er(ds1, ds2, t)
            f1s.append(f1)
            if f1 == 1.0:
                skip_range[0] = min(t, skip_range[0])
                skip_range[1] = max(t, skip_range[1])
        l_idx, r_idx = squeeze_range(f1s)

        # 2nd+ rounds
        for _ in range(args.epoch-1):
            step /= 2
            d *= 10
            t_range = range_(t_range[l_idx], t_range[r_idx]+step, step, d=d)
            f1s = []
            for t in t_range:
                if skip_range[0] <= t <= skip_range[1]:
                    f1 = 1.0
                else:
                    _, _, f1 = compute_er(ds1, ds2, t)
                f1s.append(f1)
                if f1 == 1.0:
                    skip_range[0] = min(t, skip_range[0])
                    skip_range[1] = max(t, skip_range[1])
            l_idx, r_idx = squeeze_range(f1s)

        indices = final_range(f1s)
        if len(indices) > 1:
            print(f'The best threshold range: [{t_range[indices[0]]}, {t_range[indices[1]]}], F-score: {f1s[indices[0]]}')
        else:
            print(f'The best threshold: {t_range[indices[0]]}, F-score: {f1s[indices[0]]}')
