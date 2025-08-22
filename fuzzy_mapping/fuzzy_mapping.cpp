
#include "fuzzy_mapping.h"
#include "rb_okvs.h"

namespace osuCrypto {
namespace fmap {
i32 find(const std::vector<segment> &segments, const u64 &x) {
  u32 begin(0), end(segments.size() - 1);
  u32 middle(end / 2);

  while (end > begin + 1) {
    if (x >= segments[middle][0]) {
      begin = middle;
    } else {
      end = middle;
    }
    middle = (begin + end) / 2;
  }

  if (x >= segments[end][0]) {
    return end;
  }
  if (x < segments[begin][0]) {
    return -1;
  }
  return begin;
}

void insert(std::vector<segment> &segments, const segment &interval) {
  i32 segments_size(segments.size());
  if (segments_size == 0) {
    segments.push_back(interval);
    return;
  }

  i32 flag = find(segments, interval[0]);
  if (flag == -1) {
    if (interval[1] >= segments[0][0]) {
      segments[0][0] = interval[0];
      return;
    } else {
      segments.insert(segments.begin(), interval);
      return;
    }
  }

  if (flag == segments_size - 1) {
    if (interval[0] <= segments[flag][1]) {
      if (segments[segments_size - 1][1] < interval[1]) {
        segments[segments_size - 1][1] = interval[1];
      }
      return;
    } else {
      segments.push_back(interval);
      return;
    }
  }

  if (interval[0] <= segments[flag][1]) {
    if (interval[1] <= segments[flag][1]) {
      return;
    } else if (interval[1] < segments[flag + 1][0]) {
      segments[flag][1] = interval[1];
      return;
    } else {
      segments[flag][1] = segments[flag + 1][1];
      segments.erase(segments.begin() + flag + 1);
      return;
    }
  } else {
    if (interval[1] < segments[flag + 1][0]) {
      segments.insert(segments.begin() + flag + 1, interval);
      return;
    } else {
      segments[flag + 1][0] = interval[0];
      return;
    }
  }
}

void get_interval(const u64 &x, const i32 &delta, const i32 &side_length,
                  segment &interval) {
  interval[0] = (u64)((u64)((x - delta) / side_length));
  interval[1] = (u64)((u64)((x + delta) / side_length));
  return;
}

void point_to_block_vector(const Rist25519_point &point,
                           const std::vector<block>::iterator &block_vec) {
  u8 temp_bytes[POINT_LENGTH_IN_BYTE];
  point.toBytes(temp_bytes);
  if (sizeof(block) * 2 == POINT_LENGTH_IN_BYTE) {
    memcpy(block_vec[0].data(), temp_bytes, sizeof(block));
    memcpy(block_vec[1].data(), temp_bytes + sizeof(block), sizeof(block));
  } else {
    throw std::runtime_error(
        "no proper parameter for point [lsOPRF.cpp: point_to_block_vector]");
  }
  return;
}

void block_vector_to_point(const std::vector<block>::iterator &block_vec,
                           Rist25519_point &point) {
  u8 temp_bytes[POINT_LENGTH_IN_BYTE];
  memcpy(temp_bytes, block_vec[0].data(), sizeof(block));
  memcpy(temp_bytes + sizeof(block), block_vec[1].data(), sizeof(block));
  point.fromBytes(temp_bytes);
  return;
}

u64 sender_get_interval(const u64 &x, const i32 &side_length) {
  return (u64)(x / side_length);
}

Rist25519_point
get_own_seed(const std::vector<u64> &element,
             const std::vector<std::vector<segment>> &segments_in_dimensions,
             const std::vector<std::vector<Rist25519_number>> &values,
             const u32 &dimension, const i32 &side_length) {
  Rist25519_number sum(
      values[0][find(segments_in_dimensions[0], element[0] / side_length)]);
  for (auto i = 1; i < dimension; i++) {
    sum = sum +
          values[i][find(segments_in_dimensions[i], element[i] / side_length)];
  }
  return Rist25519_point::mulGenerator(sum);
}

////////////////////////////////////
void assign_segments(const std::size_t &elements_size,
                     std::vector<std::vector<Rist25519_number>> &values,
                     std::stack<Rist25519_number> &vals_candidate_r,
                     std::stack<Rist25519_number> &vals_candidate_skr,
                     const u32 &dimension, const i32 &delta,
                     const i32 &side_length, const Rist25519_number &sk) {

  PRNG prng(oc::sysRandomSeed());
  Rist25519_number rG, sk_rG;
  u64 num_interval_per_element_per_dimension(((2 * delta + 1) / side_length) +
                                             2);

  Rist25519_number value_i = Rist25519_number(prng);
  Rist25519_number rG_value = Rist25519_number(prng);
  Rist25519_number sk_rG_value = sk * rG_value;
  for (auto i = 0; i < dimension; i++) {
    std::vector<Rist25519_number> values_i;
    for (auto j = 0; j < elements_size; j++) {
      values_i.push_back(value_i);
      //   values_i.push_back(Rist25519_number(prng));
      for (auto k = 0; k < num_interval_per_element_per_dimension; k++) {
        // rG = Rist25519_number(prng);
        // sk_rG = sk * rG;
        vals_candidate_r.push(rG_value);
        vals_candidate_skr.push(sk_rG_value);
      }
    }
    values.push_back(values_i);
  }

  // for(auto j = 0; j < elements_size; j++){
  //     rG = Rist25519_point(prng);
  //     sk_rG = sk * rG;
  //     vals_candidate_r.push(rG);
  //     vals_candidate_skr.push(sk_rG);
  // }

  return;
}

void get_mask_cipher(const std::size_t &elements_size,
                     std::vector<Rist25519_number> &masks,
                     std::vector<Rist25519_number> &masks_inv,
                     const std::array<Rist25519_point, 2> &pk) {
  PRNG prng(oc::sysRandomSeed());
  Rist25519_number temp_mask = Rist25519_number(prng);
  Rist25519_number temp_mask_inverse = temp_mask.inverse();
  //   std::array<Rist25519_point, 2> temp_enc_kq;
  for (auto i = 0; i < elements_size; i++) {
    ////////////////////////////
    // temp_mask = 1;
    ////////////////////////////

    masks.push_back(temp_mask);
    masks_inv.push_back(temp_mask_inverse);

    // temp_r = Rist25519_number(prng);
    // temp_enc_kq[0] = temp_r * pk[0];
    // temp_enc_kq[1] = temp_r * pk[1] + temp_masks;
    // mask_cipher.push_back(temp_enc_kq);
  }

  return;
}
//////////////////////////////////
void elements_to_segments(
    const std::vector<std::vector<u64>> &elements,
    std::vector<std::vector<segment>> &segments_in_dimensions,
    const u32 &dimension, const i32 &delta, const i32 &side_length) {
  segment temp_interval;
  for (u64 i = 0; i < dimension; i++) {
    std::vector<segment> segments_in_i;
    segments_in_dimensions.push_back(segments_in_i);
  }
  for (auto iter : elements) {
    for (u64 i = 0; i < dimension; i++) {
      get_interval(iter[i], delta, side_length, temp_interval);
      insert(segments_in_dimensions[i], temp_interval);
    }
  }
  return;
}

void get_own_seeds(
    const std::vector<std::vector<u64>> &elements,
    const std::vector<std::vector<segment>> &segments_in_dimensions,
    const std::vector<std::vector<Rist25519_number>> &values,
    std::vector<Rist25519_point> &seeds, const u32 &dimension,
    const i32 &side_length) {
  for (auto iter : elements) {
    seeds.push_back(get_own_seed(iter, segments_in_dimensions, values,
                                 dimension, side_length));
  }
  return;
}

void get_key_value_pair(
    const std::vector<std::vector<segment>> &segments_in_dimensions,
    const std::vector<std::vector<Rist25519_number>> &values,
    std::stack<Rist25519_number> &vals_candidate_r,
    std::stack<Rist25519_number> &vals_candidate_skr, std::vector<block> &keys,
    std::vector<std::vector<Rist25519_number>> &vals, const u32 &dimension) {
  std::vector<Rist25519_number> temp_Rist25519_number_vector(
      EC_CIPHER_SIZE_IN_NUMBER);
  for (u64 i = 0; i < dimension; i++) {
    for (u64 j = 0; j < segments_in_dimensions[i].size(); j++) {
      for (u64 k = segments_in_dimensions[i][j][0];
           k < segments_in_dimensions[i][j][1] + 1; k++) {
        keys.push_back(block(i, k));
        // point_to_block_vector(vals_candidate_r.top(),
        // temp_block_vector.begin());
        // point_to_block_vector(vals_candidate_skr.top() + values[i][j],
        // temp_block_vector.begin() + 2);
        // point_to_block_vector( values[i][j], temp_block_vector.begin() + 2);
        temp_Rist25519_number_vector[0] = vals_candidate_r.top();
        temp_Rist25519_number_vector[1] =
            vals_candidate_skr.top() + values[i][j];
        vals.push_back(temp_Rist25519_number_vector);
        vals_candidate_r.pop();
        vals_candidate_skr.pop();
      }
    }
  }
  return;
}

void get_vec_enc_mask_seedsum(
    const std::vector<std::vector<u64>> &elements,
    const std::vector<std::vector<Rist25519_point>> &codeWords,
    const std::vector<Rist25519_number> &masks,
    const std::vector<Rist25519_point> &own_seeds,
    // std::stack<Rist25519_number>& vals_candidate_r,
    // std::stack<Rist25519_number>& vals_candidate_skr,
    std::vector<Rist25519_point> &vec_enc_mask_seedsum, const u32 &dimension,
    const i32 &side_length, const i32 &okvs_n,
    const std::array<Rist25519_point, 2> &pk) {
  std::array<Rist25519_point, 2> temp_enc_mask_seedsum, okvs_value;
  RBOKVS_rist rb_okvs;
  rb_okvs.init(okvs_n, 0.1, lambda, seed);

  PRNG prng(oc::sysRandomSeed());

  for (auto i = 0; i < elements.size(); i++) {
    Rist25519_number temp_num(prng);
    temp_enc_mask_seedsum[0] = pk[0] * temp_num;
    temp_enc_mask_seedsum[1] = pk[1] * temp_num + own_seeds[i];

    for (u64 j = 0; j < dimension; j++) {
      auto k = sender_get_interval(elements[i][j], side_length);
      auto value =
          rb_okvs.decode(codeWords, block(j, k), EC_CIPHER_SIZE_IN_NUMBER);
      temp_enc_mask_seedsum[0] += value[0];
      temp_enc_mask_seedsum[1] += value[1];
    }

    temp_enc_mask_seedsum[0] *= masks[i];
    temp_enc_mask_seedsum[1] *= masks[i];

    // vec_enc_mask_seedsum.push_back(temp_enc_mask_seedsum);
    vec_enc_mask_seedsum.push_back(temp_enc_mask_seedsum[0]);
    vec_enc_mask_seedsum.push_back(temp_enc_mask_seedsum[1]);
  }

  return;
}
///////////////////////////////////////////////////////////////////////

void get_dhk_mask_seedsum(
    const std::vector<Rist25519_point> &vec_enc_mask_seedsum,
    std::vector<Rist25519_point> &dhk_mask_seedsum, const Rist25519_number &sk,
    const Rist25519_number &dh_sk) {
  for (u64 i = 0; i < (vec_enc_mask_seedsum.size() / 2); i++) {
    dhk_mask_seedsum.push_back(dh_sk * (vec_enc_mask_seedsum[2 * i + 1] -
                                        sk * vec_enc_mask_seedsum[2 * i]));
  }
  // printf("seedsum 369 = \n");
  // print_point(dhk_mask_seedsum[369]);
  // printf("\n");
  // for(auto iter : vec_enc_mask_seedsum){
  //     dhk_mask_seedsum.push_back(dh_sk * (iter[1] - sk * iter[0]));
  // }
  return;
}

void get_dhkk_seedsum(const std::vector<Rist25519_point> &dhk_mask_seedsum,
                      const std::vector<Rist25519_number> &masks_inv,
                      std::vector<Rist25519_point> &vec_dhkk_seedsum,
                      const Rist25519_number &dh_sk) {
  for (auto i = 0; i < masks_inv.size(); i++) {
    vec_dhkk_seedsum[i] = (dh_sk * (masks_inv[i] * dhk_mask_seedsum[i]));
  }
  return;
}

///////////////////////////////////////////////////////////////////////
void fmap_recv_online(coproto::LocalAsyncSocket *channel,
                      std::vector<std::vector<u64>> *receiver_elements,
                      std::vector<std::vector<Rist25519_number>> *recv_values,
                      std::stack<Rist25519_number> *recv_vals_candidate_r,
                      std::stack<Rist25519_number> *recv_vals_candidate_skr,
                      std::vector<Rist25519_number> *recv_masks,
                      std::vector<Rist25519_number> *recv_masks_inv,
                      std::vector<Rist25519_point> *recv_vec_dhkk_seedsum,
                      u32 dimension, i32 delta, i32 side_length,
                      Rist25519_number recv_sk,
                      std::array<Rist25519_point, 2> recv_pk,
                      Rist25519_number recv_dh_sk) {
  u64 recv_set_size((*receiver_elements).size());

  std::vector<std::vector<segment>> recv_segments_in_dimensions;
  fmap::elements_to_segments(*receiver_elements, recv_segments_in_dimensions,
                             dimension, delta, side_length);

  std::vector<Rist25519_point> recv_seeds;
  fmap::get_own_seeds(*receiver_elements, recv_segments_in_dimensions,
                      *recv_values, recv_seeds, dimension, side_length);

  std::vector<element> recv_fmap_keys;
  std::vector<std::vector<Rist25519_number>> recv_fmap_vals;
  fmap::get_key_value_pair(recv_segments_in_dimensions, *recv_values,
                           *recv_vals_candidate_r, *recv_vals_candidate_skr,
                           recv_fmap_keys, recv_fmap_vals, dimension);

  RBOKVS_rist recv_fmap_okvs;
  recv_fmap_okvs.init(recv_fmap_keys.size(), 0.1, lambda, seed);
  std::vector<std::vector<Rist25519_point>> recv_fmap_codeWords(
      recv_fmap_okvs.num_columns,
      std::vector<Rist25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
  // recv_fmap_okvs.encode(recv_fmap_keys, recv_fmap_vals,
  // EC_CIPHER_SIZE_IN_NUMBER, recv_fmap_codeWords,
  // Rist25519_point::mulGenerator(1));
  recv_fmap_okvs.encode(recv_fmap_keys, recv_fmap_vals,
                        EC_CIPHER_SIZE_IN_NUMBER, recv_fmap_codeWords);

  std::vector<Rist25519_point> recv_fmap_codeWords_net(
      recv_fmap_okvs.num_columns * EC_CIPHER_SIZE_IN_NUMBER);
  std::vector<Rist25519_point> send_fmap_codeWords_net;

  for (u64 i = 0; i < recv_fmap_okvs.num_columns; i++) {
    for (u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++) {
      recv_fmap_codeWords_net[i * EC_CIPHER_SIZE_IN_NUMBER + j] =
          recv_fmap_codeWords[i][j];
    }
  }
  // std::cout << "fmap_recv_online: fmap_codeWords send recv begin" <<
  // std::endl;
  coproto::sync_wait((*channel).send(recv_fmap_codeWords_net));
  // std::cout << "fmap_recv_online: fmap_codeWords send done" << std::endl;
  coproto::sync_wait((*channel).recvResize(send_fmap_codeWords_net));
  // std::cout << "fmap_recv_online: fmap_codeWords send recv done" <<
  // std::endl;

  std::vector<std::vector<Rist25519_point>> send_fmap_codeWords(
      (send_fmap_codeWords_net.size() / EC_CIPHER_SIZE_IN_NUMBER),
      std::vector<Rist25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
  for (u64 i = 0;
       i < (send_fmap_codeWords_net.size() / EC_CIPHER_SIZE_IN_NUMBER); i++) {
    for (u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++) {
      send_fmap_codeWords[i][j] =
          send_fmap_codeWords_net[i * EC_CIPHER_SIZE_IN_NUMBER + j];
    }
  }

  u64 send_fmap_keys_size;
  // std::cout << "fmap_recv_online: recv_fmap_keys send recv begin" <<
  // std::endl;
  coproto::sync_wait((*channel).send(recv_fmap_keys.size()));
  // std::cout << "fmap_recv_online: recv_fmap_keys send done" << std::endl;
  coproto::sync_wait((*channel).recvResize(send_fmap_keys_size));
  // std::cout << "fmap_recv_online: recv_fmap_keys send recv done" <<
  // std::endl;

  std::array<Rist25519_point, 2> send_pk;
  // std::cout << "fmap_recv_online: recv_pk send recv begin" << std::endl;
  coproto::sync_wait((*channel).send(recv_pk));
  // std::cout << "fmap_recv_online: recv_pk send done" << std::endl;
  coproto::sync_wait((*channel).recvResize(send_pk));
  // std::cout << "fmap_recv_online: recv_pk send recv done" << std::endl;

  std::vector<Rist25519_point> recv_vec_enc_mask_seedsum;
  fmap::get_vec_enc_mask_seedsum(*receiver_elements, send_fmap_codeWords,
                                 *recv_masks, recv_seeds,
                                 recv_vec_enc_mask_seedsum, dimension,
                                 side_length, send_fmap_keys_size, send_pk);

  std::vector<Rist25519_point> send_vec_enc_mask_seedsum;
  // std::cout << "fmap_recv_online: vec_enc_mask_seedsum send recv begin" <<
  // std::endl;
  coproto::sync_wait((*channel).send(recv_vec_enc_mask_seedsum));
  // std::cout << "fmap_recv_online: vec_enc_mask_seedsum send done" <<
  // std::endl;
  coproto::sync_wait((*channel).recvResize(send_vec_enc_mask_seedsum));
  // std::cout << "fmap_recv_online: vec_enc_mask_seedsum send recv done" <<
  // std::endl;

  std::vector<Rist25519_point> send_dhk_mask_seedsum;
  fmap::get_dhk_mask_seedsum(send_vec_enc_mask_seedsum, send_dhk_mask_seedsum,
                             recv_sk, recv_dh_sk);

  std::vector<Rist25519_point> recv_dhk_mask_seedsum;
  // std::cout << "fmap_recv_online: dhk_mask_seedsum send recv begin" <<
  // std::endl;
  coproto::sync_wait((*channel).send(send_dhk_mask_seedsum));
  // std::cout << "fmap_recv_online: dhk_mask_seedsum send done" << std::endl;
  coproto::sync_wait((*channel).recvResize(recv_dhk_mask_seedsum));
  // std::cout << "fmap_recv_online: dhk_mask_seedsum send recv done" <<
  // std::endl;
  fmap::get_dhkk_seedsum(recv_dhk_mask_seedsum, *recv_masks_inv,
                         *recv_vec_dhkk_seedsum, recv_dh_sk);

  return;
}

void fmap_send_online(coproto::LocalAsyncSocket *channel,
                      std::vector<std::vector<u64>> *sender_elements,
                      std::vector<std::vector<Rist25519_number>> *send_values,
                      std::stack<Rist25519_number> *send_vals_candidate_r,
                      std::stack<Rist25519_number> *send_vals_candidate_skr,
                      std::vector<Rist25519_number> *send_masks,
                      std::vector<Rist25519_number> *send_masks_inv,
                      std::vector<Rist25519_point> *send_vec_dhkk_seedsum,
                      u32 dimension, i32 delta, i32 side_length,
                      Rist25519_number send_sk,
                      std::array<Rist25519_point, 2> send_pk,
                      Rist25519_number send_dh_sk) {

  std::vector<std::vector<segment>> send_segments_in_dimensions;
  fmap::elements_to_segments(*sender_elements, send_segments_in_dimensions,
                             dimension, delta, side_length);

  std::vector<Rist25519_point> send_seeds;
  fmap::get_own_seeds(*sender_elements, send_segments_in_dimensions,
                      *send_values, send_seeds, dimension, side_length);

  std::vector<element> send_fmap_keys;
  std::vector<std::vector<Rist25519_number>> send_fmap_vals;
  fmap::get_key_value_pair(send_segments_in_dimensions, *send_values,
                           *send_vals_candidate_r, *send_vals_candidate_skr,
                           send_fmap_keys, send_fmap_vals, dimension);

  RBOKVS_rist send_fmap_okvs;
  send_fmap_okvs.init(send_fmap_keys.size(), 0.1, lambda, seed);
  std::vector<std::vector<Rist25519_point>> send_fmap_codeWords(
      send_fmap_okvs.num_columns,
      std::vector<Rist25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
  // send_fmap_okvs.encode(send_fmap_keys, send_fmap_vals,
  // EC_CIPHER_SIZE_IN_NUMBER, send_fmap_codeWords,
  // Rist25519_point::mulGenerator(1));
  send_fmap_okvs.encode(send_fmap_keys, send_fmap_vals,
                        EC_CIPHER_SIZE_IN_NUMBER, send_fmap_codeWords);

  std::vector<Rist25519_point> send_fmap_codeWords_net(
      send_fmap_okvs.num_columns * EC_CIPHER_SIZE_IN_NUMBER);
  std::vector<Rist25519_point> recv_fmap_codeWords_net;

  for (u64 i = 0; i < send_fmap_okvs.num_columns; i++) {
    for (u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++) {
      send_fmap_codeWords_net[i * EC_CIPHER_SIZE_IN_NUMBER + j] =
          send_fmap_codeWords[i][j];
    }
  }
  coproto::sync_wait((*channel).recvResize(recv_fmap_codeWords_net));
  coproto::sync_wait((*channel).send(send_fmap_codeWords_net));

  std::vector<std::vector<Rist25519_point>> recv_fmap_codeWords(
      (recv_fmap_codeWords_net.size() / EC_CIPHER_SIZE_IN_NUMBER),
      std::vector<Rist25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
  for (u64 i = 0;
       i < (recv_fmap_codeWords_net.size() / EC_CIPHER_SIZE_IN_NUMBER); i++) {
    for (u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++) {
      recv_fmap_codeWords[i][j] =
          recv_fmap_codeWords_net[i * EC_CIPHER_SIZE_IN_NUMBER + j];
    }
  }

  // std::vector<std::vector<block>> recv_fmap_codeWords;
  // coproto::sync_wait((*channel).recvResize(recv_fmap_codeWords));
  // coproto::sync_wait((*channel).send(send_fmap_codeWords));

  u64 recv_fmap_keys_size;
  coproto::sync_wait((*channel).recvResize(recv_fmap_keys_size));
  coproto::sync_wait((*channel).send(send_fmap_keys.size()));

  std::array<Rist25519_point, 2> recv_pk;
  coproto::sync_wait((*channel).recvResize(recv_pk));
  coproto::sync_wait((*channel).send(send_pk));

  std::vector<Rist25519_point> send_vec_enc_mask_seedsum;
  fmap::get_vec_enc_mask_seedsum(*sender_elements, recv_fmap_codeWords,
                                 *send_masks, send_seeds,
                                 send_vec_enc_mask_seedsum, dimension,
                                 side_length, recv_fmap_keys_size, recv_pk);

  std::vector<Rist25519_point> recv_vec_enc_mask_seedsum;
  coproto::sync_wait((*channel).recvResize(recv_vec_enc_mask_seedsum));
  coproto::sync_wait((*channel).send(send_vec_enc_mask_seedsum));

  std::vector<Rist25519_point> recv_dhk_mask_seedsum;
  fmap::get_dhk_mask_seedsum(recv_vec_enc_mask_seedsum, recv_dhk_mask_seedsum,
                             send_sk, send_dh_sk);

  std::vector<Rist25519_point> send_dhk_mask_seedsum;
  coproto::sync_wait((*channel).recvResize(send_dhk_mask_seedsum));
  coproto::sync_wait((*channel).send(recv_dhk_mask_seedsum));
  fmap::get_dhkk_seedsum(send_dhk_mask_seedsum, *send_masks_inv,
                         *send_vec_dhkk_seedsum, send_dh_sk);

  return;
}

} // namespace fmap

} // namespace osuCrypto
