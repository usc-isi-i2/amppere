import stdlib;
import keydb;
import shared3p;
import shared3p_keydb;

domain pd_shared3p shared3p;

void append_value(string key, pd_shared3p uint64 value) {
    pd_shared3p uint64[[1]] old_values;
    pd_shared3p uint64[[1]] new_values (1);
    new_values = value;

    // fetch value if key already exists
    // assert(keydb_clean("*"));
    ScanCursor cur = keydb_scan(key);
    if (cur.cursor != 0) {
        old_values = keydb_get(key);
    }
    // keydb_scan_cursor_free(cur);

    // set new value
    pd_shared3p uint64[[1]] values = cat(old_values, new_values);
    keydb_del(key); // need to delete old key first
    keydb_set(key, values);
}

void main() {
    keydb_connect("dbhost");

    pd_shared3p uint64 id = argument("id");
    string bkey = argument("bkey");
    string prefix = argument("prefix");
    string bprefix = argument("bprefix");
    
    string key = bprefix + prefix + bkey;
    append_value(key, id);

    keydb_disconnect();
}
