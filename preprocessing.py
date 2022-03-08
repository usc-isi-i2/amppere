import sys
import hashlib
from datasketch import MinHash, MinHashLSH


def ngram(n, s, place_holder=' ', padded=False):
    if len(s) == 0:
        return []
    if padded:
        pad = place_holder * (n - 1)
        s = pad + s + pad
    s = s.split(' ')
    s = place_holder.join(s)
    if len(s) < n:
        return [s]
    return [s[i:i + n] for i in range(len(s) - n + 1)]


def encode_token(t):
    """
    example: ab -> 0x6162
    """

    # uint64 maxsize = 8 bytes
    if len(t) >= 8:
        raise ValueError('Max length of character is 8')

    re = 0
    for idx, c in enumerate(reversed(t)):
        re += (ord(c) & 0xff) << (8 * idx)
    return re


def generate_blocking_keys(data, num_perm, threshold, key_len=10):
    m = MinHash(num_perm=num_perm)
    for d in data:
        m.update(d.encode('utf8'))
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    lsh.insert("m", m)

    keys = set()
    for (start, end), hashtable in zip(lsh.hashranges, lsh.hashtables):
        # _H(m.hashvalues[start:end]) == list(hashtable._dict.keys())[0]
        byte_key = list(hashtable._dict.keys())[0]
        keys.add(hashlib.sha1(byte_key).hexdigest()[:key_len])
    return keys


if __name__ == '__main__':
    # python preprocess_bkeys.py "hello" "helle" 3
    a = sys.argv[1]
    b = sys.argv[2]
    n = int(sys.argv[3]) # n-gram

    a = set(ngram(n, a.lower()))
    b = set(ngram(n, b.lower()))

    jaccard_score = len(a & b) / len(a | b)
    print('a:', a)
    print('b:', b)
    print('jaccard similarity score:', jaccard_score)

    enc_a = [encode_token(t) for t in a]
    print('encoded a: [{}]'.format(', '.join([hex(e) for e in enc_a])))
    enc_b = [encode_token(t) for t in b]
    print('encoded b: [{}]'.format(', '.join([hex(e) for e in enc_b])))


