// License here.

#ifndef __AFS_HASHMAP_MAX_HPP_INCLUDED__
#define __AFS_HASHMAP_MAX_HPP_INCLUDED__

#include <stddef.h>
#include <string.h>
#include <unordered_map>
#include "../util.hpp"
#include "ft_operator.hpp"

namespace afs {

// Array of numeric values
template<class K, class V>
class HashMap_L1 : public FTOperator {

private:
    std::unordered_map<K, V> map, backup_map;
    double tot_diff;

public:
    HashMap_L1(double d = 0);
    ~HashMap_L1();

    // interface for fault tolerance, derived from the base class FTInterface
    double CalculateDivergence();
    void SerializeState(BackupData &backup_data);
    void RecoveryState(BackupData &backup_data);

    // derived from the base class FTInterface
    void Clear();

    // for normal processing
    void UpdateValue(K key, V value);
    V GetValue(K key);
    bool HasKey(K key);
    std::unordered_map<K,V> & Get_entire();
};

template<class K, class V>
HashMap_L1<K, V>::HashMap_L1(double d) : FTOperator(d) {
}

template<class K, class V>
HashMap_L1<K, V>::~HashMap_L1() {
}

template<class K, class V>
void HashMap_L1<K, V>::UpdateValue(K key, V value) {
    double old_diff = abs(map[key] - backup_map[key]);
    double new_diff = abs(value -  backup_map[key]);
    tot_diff = tot_diff - old_diff + new_diff;

    map[key] = value;
}

template<class K, class V>
V HashMap_L1<K, V>::GetValue(K key) {
    return map[key];
}

//Return entire 
template<class K, class V>
std::unordered_map<K,V> & HashMap_L1<K, V>::Get_entire() {
    return map;
}

template<class K, class V>
bool HashMap_L1<K, V>::HasKey(K key) {
    
    if(map.find(key) == map.end())	
        return false;
    else return true;
}

template<class K, class V>
void HashMap_L1<K, V>::Clear() {
    map.clear();
    backup_map.clear();
    tot_diff = 0;
}

template<class K, class V>
double HashMap_L1<K, V>::CalculateDivergence() {
    return tot_diff;
}
    
template<class K, class V>
void HashMap_L1<K, V>::SerializeState(BackupData &backup_data) {
    K max_diff_key = map.begin()->first;
    for (auto it = map.begin(); it != map.end(); it++) {
        if (abs(map[it->first]-backup_map[it->first])>abs(map[max_diff_key]-backup_map[max_diff_key])) {
            max_diff_key = it->first;
        }
    }

    backup_data.meta.len = sizeof(K) + sizeof(V);
    backup_data.meta.key = (uint64_t)max_diff_key;
    memcpy(backup_data.data, &max_diff_key, sizeof(K));
    memcpy(backup_data.data+sizeof(K), &map[max_diff_key], sizeof(V));

    tot_diff -= abs(map[max_diff_key]-backup_map[max_diff_key]);
    backup_map[max_diff_key] = map[max_diff_key];
    // LOG_MSG("Save state %lu %lf\n", max_diff_key, map[max_diff_key]);
    memset(&max_diff_key, 0, sizeof(K));
}
    
template<class K, class V>
void HashMap_L1<K, V>::RecoveryState(BackupData& backup_data) {
    //LOG_MSG("len %u key %lu\n", backup_data.meta.len, backup_data.meta.key);
    K key;
    memcpy(&key, backup_data.data, sizeof(K));
    map[key] = backup_map[key] = *(V*)(backup_data.data+sizeof(K));
    //LOG_MSG("    value %ld\n", array[index]);
    LOG_MSG("Restore state %lu %lf\n", key, map[key]);
}

} // namespace afs

#endif // __AFS_COUNTER_ARRAY_HPP_INCLUDED__
