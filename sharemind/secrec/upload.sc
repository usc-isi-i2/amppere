import stdlib;
import shared3p;
import keydb;
import shared3p_keydb;

domain pd_shared3p shared3p;

void main() {
    keydb_connect("dbhost");

    string prefix = argument("prefix");
    uint64 id = argument("id");
    string key = prefix + tostring(id);
    pd_shared3p uint64 [[1]] tokens = argument("tokens");

    keydb_set(key, tokens);

    keydb_disconnect();
}
