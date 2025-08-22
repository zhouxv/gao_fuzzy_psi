#include "fm.h"
#include <ipcl/bignum.h>
#include <vector>

using segment = std::array<oc::u64, 2>;
using block = oc::block;

namespace osuCrypto {

namespace OT_for_FPSI {
std::vector<element> run_ot_receiver(coproto::LocalAsyncSocket &channel,
                                     BitVector &choices, const u64 &numOTs) {
  std::vector<element> result;
  std::vector<block> recvMsg(numOTs);

  if (numOTs <= OT_NUMS_BOUND) // using libOTe-CO15
  {
    PRNG prng((block(oc::sysRandomSeed())));
    osuCrypto::DefaultBaseOT baseOTs;
    std::vector<block> mask(numOTs);
    std::vector<block> maskMsg(numOTs);

    // random OT
    // std::cout << " recv: choices: " << choices << std::endl;
    auto p = baseOTs.receive(choices, mask, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    // random OT -> OT
    coproto::sync_wait(channel.recv(maskMsg));
    for (u64 i = 0; i < numOTs; i++) {
      recvMsg[i] = maskMsg[i] ^ mask[i];
    }
  } else {

    PRNG prng(block(oc::sysRandomSeed()));
    osuCrypto::DefaultBaseOT baseOTs;
    std::vector<block> mask(numOTs);
    std::vector<block> maskMsg(numOTs);

    std::vector<std::array<element, 2>> baseSend(KAPPA);

    prng.get((u8 *)baseSend.data()->data(),
             sizeof(block) * 2 * baseSend.size());
    auto p = baseOTs.send(baseSend, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    osuCrypto::IknpOtExtReceiver recv;
    recv.setBaseOts(baseSend);
    auto proto = recv.receive(choices, mask, prng, channel);
    auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
    std::get<0>(result).result();

    // random OT -> OT
    coproto::sync_wait(channel.recv(maskMsg));
    for (u64 i = 0; i < numOTs; i++) {
      recvMsg[i] = maskMsg[i] ^ mask[i];
    }
  }

  for (u64 i = 0; i < numOTs; i++) {
    if (choices[i] == 1) {
      result.push_back(element(recvMsg[i]));
    }
  }

  return result;
}

void run_ot_sender(coproto::LocalAsyncSocket &channel,
                   std::vector<std::array<element, 2>> sendMsg) {
  const u64 numOTs(sendMsg.size());

  if (numOTs <= OT_NUMS_BOUND) {
    osuCrypto::DefaultBaseOT baseOTs;
    PRNG prng(block(oc::sysRandomSeed()));
    std::vector<block> half_sendMsg(numOTs);
    std::vector<std::array<element, 2>> randMsg(numOTs);

    // random OT
    auto p = baseOTs.send(randMsg, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    // random OT -> OT
    for (u64 i = 0; i < numOTs; i++) {
      half_sendMsg[i] = sendMsg[i][1] ^ randMsg[i][1];
    }
    coproto::sync_wait(channel.send(half_sendMsg));
  } else {
    osuCrypto::DefaultBaseOT baseOTs;
    PRNG prng(block(oc::sysRandomSeed()));
    std::vector<block> half_sendMsg(numOTs);
    std::vector<std::array<element, 2>> randMsg(numOTs);

    std::vector<block> baseRecv(KAPPA);
    osuCrypto::BitVector baseChoice(KAPPA);

    baseChoice.randomize(prng);

    // random OT (base)
    auto p = baseOTs.receive(baseChoice, baseRecv, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    osuCrypto::IknpOtExtSender sender;
    sender.setBaseOts(baseRecv, baseChoice);
    auto proto = sender.send(randMsg, prng, channel);
    auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
    std::get<0>(result).result();

    // random OT -> OT
    for (u64 i = 0; i < numOTs; i++) {
      half_sendMsg[i] = sendMsg[i][1] ^ randMsg[i][1];
    }
    coproto::sync_wait(channel.send(half_sendMsg));

    return;
  }
}

std::vector<std::vector<element>>
run_ot_receiver_long_half_one(coproto::LocalAsyncSocket &channel,
                              BitVector &choices, const u64 &numOTs,
                              const u64 Msg_Length) {
  std::vector<std::vector<element>> result;
  std::vector<block> recvMsg(Msg_Length);

  if (numOTs <= OT_NUMS_BOUND) // using libOTe-CO15
  {
    PRNG prng(block(oc::sysRandomSeed()));
    osuCrypto::DefaultBaseOT baseOTs;
    std::vector<block> mask(numOTs);
    // std::vector<block> maskMsg_0(numOTs * Msg_Length);
    std::vector<block> maskMsg_1(numOTs * Msg_Length);

    // random OT
    // std::cout << " recv: choices: " << choices << std::endl;
    auto p = baseOTs.receive(choices, mask, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    // random OT -> OT
    // coproto::sync_wait(channel.recv(maskMsg_0));
    coproto::sync_wait(channel.recv(maskMsg_1));
    for (u64 i = 0; i < numOTs; i++) {
      prng.SetSeed(mask[i]);
      if (choices[i] == 0) {
        // for(u64 j = 0; j < Msg_Length; j++){
        //     recvMsg[j] = maskMsg_0[i * Msg_Length + j] ^ prng.get<block>();
        // }
      } else {
        for (u64 j = 0; j < Msg_Length; j++) {
          recvMsg[j] = maskMsg_1[i * Msg_Length + j] ^ prng.get<block>();
        }
      }

      result.push_back(recvMsg);
    }
  } else {

    PRNG prng(block(oc::sysRandomSeed()));
    osuCrypto::DefaultBaseOT baseOTs;
    std::vector<block> mask(numOTs);
    // std::vector<block> maskMsg_0(numOTs * Msg_Length);
    std::vector<block> maskMsg_1(numOTs * Msg_Length);

    std::vector<std::array<element, 2>> baseSend(KAPPA);

    prng.get((u8 *)baseSend.data()->data(),
             sizeof(block) * 2 * baseSend.size());
    auto p = baseOTs.send(baseSend, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    osuCrypto::IknpOtExtReceiver recv;
    recv.setBaseOts(baseSend);
    auto proto = recv.receive(choices, mask, prng, channel);
    auto half_result =
        macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
    std::get<0>(half_result).result();

    // random OT -> OT
    // coproto::sync_wait(channel.recv(maskMsg_0));
    coproto::sync_wait(channel.recv(maskMsg_1));
    for (u64 i = 0; i < numOTs; i++) {
      prng.SetSeed(mask[i]);
      if (choices[i] == 0) {
        // for(u64 j = 0; j < Msg_Length; j++){
        //     recvMsg[j] = maskMsg_0[i * Msg_Length + j] ^ prng.get<block>();
        // }
      } else {
        for (u64 j = 0; j < Msg_Length; j++) {
          recvMsg[j] = maskMsg_1[i * Msg_Length + j] ^ prng.get<block>();
        }
      }

      result.push_back(recvMsg);
    }
  }

  return result;
}

void run_ot_sender_long_half_one(
    coproto::LocalAsyncSocket &channel,
    std::vector<std::array<std::vector<element>, 2>> sendMsg,
    const u64 Msg_Length) {
  const u64 numOTs(sendMsg.size());

  if (numOTs <= OT_NUMS_BOUND) {
    osuCrypto::DefaultBaseOT baseOTs;
    PRNG prng(block(oc::sysRandomSeed()));
    // std::vector<block> half_sendMsg_0(numOTs * Msg_Length);
    std::vector<block> half_sendMsg_1(numOTs * Msg_Length);
    std::vector<std::array<element, 2>> randMsg(numOTs);

    // random OT
    auto p = baseOTs.send(randMsg, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    // random OT -> OT
    PRNG prng0, prng1;
    for (u64 i = 0; i < numOTs; i++) {
      prng0.SetSeed(randMsg[i][0]);
      prng1.SetSeed(randMsg[i][1]);
      for (u64 j = 0; j < Msg_Length; j++) {
        // half_sendMsg_0[i * Msg_Length + j] = sendMsg[i][0][j] ^
        // prng0.get<block>();
        half_sendMsg_1[i * Msg_Length + j] =
            sendMsg[i][1][j] ^ prng1.get<block>();
      }
    }
    // coproto::sync_wait(channel.send(half_sendMsg_0));
    coproto::sync_wait(channel.send(half_sendMsg_1));
  } else {
    osuCrypto::DefaultBaseOT baseOTs;
    PRNG prng(block(oc::sysRandomSeed()));
    std::vector<block> half_sendMsg_0(numOTs * Msg_Length);
    std::vector<block> half_sendMsg_1(numOTs * Msg_Length);
    std::vector<std::array<element, 2>> randMsg(numOTs);

    std::vector<block> baseRecv(KAPPA);
    osuCrypto::BitVector baseChoice(KAPPA);

    baseChoice.randomize(prng);

    // random OT (base)
    auto p = baseOTs.receive(baseChoice, baseRecv, prng, channel);
    auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
    std::get<0>(r).result();

    osuCrypto::IknpOtExtSender sender;
    sender.setBaseOts(baseRecv, baseChoice);
    auto proto = sender.send(randMsg, prng, channel);
    auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
    std::get<0>(result).result();

    // random OT -> OT
    PRNG prng0, prng1;
    for (u64 i = 0; i < numOTs; i++) {
      prng0.SetSeed(randMsg[i][0]);
      prng1.SetSeed(randMsg[i][1]);
      for (u64 j = 0; j < Msg_Length; j++) {
        // half_sendMsg_0[i * Msg_Length + j] = sendMsg[i][0][j] ^
        // prng0.get<block>();
        half_sendMsg_1[i * Msg_Length + j] =
            sendMsg[i][1][j] ^ prng1.get<block>();
      }
    }
    // coproto::sync_wait(channel.send(half_sendMsg_0));
    coproto::sync_wait(channel.send(half_sendMsg_1));

    return;
  }
}

void last_ot_recv(coproto::LocalAsyncSocket *channel, u64 send_set_size,
                  BitVector *recv_out, u64 dimension) {

  // std::vector<u8> send_out;
  // coproto::sync_wait((*channel).flush());
  // coproto::sync_wait((*channel).recvResize(send_out));

  BitVector result(*recv_out);
  // printf("result size = %d\n", result.size());
  auto result_element = OT_for_FPSI::run_ot_receiver_long_half_one(
      *channel, result, result.size(), dimension / 2);
  return;
}

void last_ot_send(coproto::LocalAsyncSocket *channel,
                  std::vector<std::vector<u64>> *sender_elements,
                  u64 dimension) {

  // std::vector<u8> send_msg(send_out->size());
  // for(u64 i = 0; i < send_msg.size(); i++){
  //     send_msg[i] = ((* send_out)[i] == 1);
  // }
  // coproto::sync_wait((*channel).flush());
  // coproto::sync_wait((*channel).send(send_msg));

  std::vector<std::array<std::vector<element>, 2UL>> send_results;
  std::array<std::vector<element>, 2UL> send_result;

  send_result[0].resize(dimension / 2);
  send_result[1].resize(dimension / 2);

  for (u64 i = 0; i < (*sender_elements).size(); i++) {
    memcpy(send_result[1].data(), (*sender_elements)[i].data(),
           dimension * sizeof(u64) / sizeof(block));
    send_results.push_back(send_result);
  }

  // printf("send_results size = %d\n", send_results.size());
  OT_for_FPSI::run_ot_sender_long_half_one(*channel, send_results,
                                           dimension / 2);

  return;
}

} // namespace OT_for_FPSI

namespace fm_paillier {
inline block get_key_from_k_d_x(const Rist25519_point &k, const u32 &d,
                                const u64 &x) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, k.data, k.size);
  blake3_hasher_update(&hasher, &d, sizeof(d));
  blake3_hasher_update(&hasher, &x, sizeof(x));
  blake3_hasher_finalize(&hasher, hash_out.data(), 16);
  return hash_out;
}

inline DH25519_number get_dh_number_from_block(const block &k) {
  u8 temp[DH25519_number::size];
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, k.data(), 16);
  blake3_hasher_finalize(&hasher, temp, DH25519_number::size);
  DH25519_number result;
  result.fromBytes(temp);
  return result;
}

std::vector<block> bignumer_to_block_vector(const BigNumber &bn) {
  std::vector<u32> ct;
  bn.num2vec(ct);
  std::vector<block> cipher_block(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock);
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    cipher_block[i] = block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                            ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i])));
  }
  return cipher_block;
}

BigNumber block_vector_to_bignumer(const std::vector<block> &ct) {

  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);
  u32 temp[4];
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    memcpy(temp, ct[i].data(), 16);

    ct_u32[4 * i] = temp[0];
    ct_u32[4 * i + 1] = temp[1];
    ct_u32[4 * i + 2] = temp[2];
    ct_u32[4 * i + 3] = temp[3];
  }
  BigNumber bn = BigNumber(ct_u32.data(), ct_u32.size());
  return bn;
}

inline u64 count_trailing_zeros(const u64 &a) {
  if (a == 0) {
    return 64;
  }

  block temp_a(a);
  u64 cnt(0);
  while ((temp_a & block(1)) == block(0)) {
    temp_a >>= 1;
    cnt++;
  }
  return cnt;
}

inline u64 count_trailing_ones(const u64 &a) {
  block temp_a(a);
  u64 cnt(0);
  while ((temp_a & block(1)) == block(1)) {
    temp_a >>= 1;
    cnt++;
  }
  return cnt;
}

void interval_to_prefix(const u32 &a, const u32 &b,
                        std::vector<block> &prefixes) {
  u64 start(a), end(b);
  u64 num_zeros, num_ones;
  u64 length((b - a) + 1);
  block container;
  while (start < end) {
    num_zeros = count_trailing_zeros(start);
    if ((num_zeros == 64) || (((1) << num_zeros) > length)) {
      break;
    }
    container = block(((start >> num_zeros)), num_zeros);
    // printf("recv pre: %d, %d\n", (start >> num_zeros), num_zeros);
    prefixes.push_back(container);
    start += ((1) << num_zeros);
    length -= ((1) << num_zeros);
  }

  while (start < end) {
    num_ones = count_trailing_ones(end);
    container = block(((end >> num_ones)), num_ones);
    // printf("recv pre: %d, %d\n", end >> num_ones, num_ones);
    prefixes.push_back(container);
    if (end < ((1) << num_ones)) {
      end = 1;
      break;
    }
    end -= ((1) << num_ones);
  }

  if (start == end) {
    container = block(start, 0);
    // printf("recv pre: %d, %d\n", start, 0);
    prefixes.push_back(container);
  }

  return;
}

void block_to_prefix(const u32 &x, const int &log_delta_pow_p,
                     std::vector<block> &prefixes) {
  block container;
  for (auto i = 0; i < log_delta_pow_p; i++) {
    container = block((x >> i), i);
    // printf("send pre: %d, %d\n", x >> i, i);
    prefixes.push_back(container);
  }
  return;
}

/////////////////////////////////////////////////////////
void receiver_value_paillier_lp(const std::size_t &elements_size,
                                std::vector<std::vector<block>> &vals,
                                const u32 &dimension, const i32 &delta,
                                const u32 &p,
                                const ipcl::KeyPair &paillier_key) {
  ipcl::initializeContext("QAT");
  ipcl::PlainText pt;
  ipcl::CipherText ct;
  ipcl::setHybridMode(ipcl::HybridMode::QAT);
  std::vector<uint32_t> i_power_of_p(2 * delta + 1);
  std::vector<uint32_t> vec_zero_cipher(2 * delta + 1, 0);
  ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
  ipcl::CipherText ct_zero = paillier_key.pub_key.encrypt(pt_zero);
  i_power_of_p[0] = 0;

  for (u64 i = 1; i <= delta; i++) {
    i_power_of_p[2 * i - 1] = pow(i, p);
    i_power_of_p[2 * i] = pow(i, p);
  }
  pt = ipcl::PlainText(i_power_of_p);
  ct = paillier_key.pub_key.encrypt(pt);
  for (u64 i = 0; i < elements_size; i++) {
    for (u64 j = 0; j < dimension; j++) {
      ct = ct + ct_zero;
      vals.push_back(bignumer_to_block_vector(ct.getElement(0)));

      // if(i == 0){
      //     // printf("value: ");
      //     // print_vector(bignumer_to_block_vector(ct.getElement(0)));
      //     // printf("\n");
      //     ct_test[j] = ipcl::CipherText(paillier_key.pub_key,
      //     ct.getElement(0));
      //     // std::cout << "values_bignumber_in_dimension 0 0" <<
      //     ct.getElement(0) << std::endl;
      // }
      // // std::cout << "recv dimension" << j << ": " << ct.getElement(0) <<
      // std::endl;

      for (u64 k = 1; k <= delta; k++) {
        vals.push_back(bignumer_to_block_vector(ct.getElement(2 * k - 1)));
        vals.push_back(bignumer_to_block_vector(ct.getElement(2 * k)));
      }
    }
  }
  // printf("encode value i = 0, j = 1:\n");
  // print_vector(vals[2 * delta + 1]);
  // printf("\n");

  // ipcl::CipherText ct_test_sum = ct_test[0] + ct_test[1];
  // ipcl::PlainText pt_test = paillier_key.priv_key.decrypt(ct_test_sum);
  // for(int j = 0; j < pt_test.getSize(); j++){
  //     printf("pt_test : %d th :\n", j);
  //     for(auto iter : pt_test.getElementVec(j)){
  //         printf("%d ", iter);
  //     }
  //     printf("\n");
  // }

  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

void receiver_value_paillier_linfty(const std::size_t &elements_size,
                                    std::vector<std::vector<block>> &vals,
                                    const u32 &dimension, const i32 &delta,
                                    const ipcl::KeyPair &paillier_key) {
  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::QAT);

  std::vector<uint32_t> vec_zero_cipher(2 * delta + 1, 0);
  ipcl::PlainText pt_zero = ipcl::PlainText(vec_zero_cipher);
  ipcl::CipherText ct_zero = paillier_key.pub_key.encrypt(pt_zero);

  std::vector<std::vector<block>> bignum_blk_vec;
  for (u64 i = 0; i < 2 * delta + 1; i++) {
    bignum_blk_vec.push_back(bignumer_to_block_vector(ct_zero.getElement(i)));
  }

  for (u64 i = 0; i < elements_size; i++) {
    for (u64 j = 0; j < dimension; j++) {
      vals.push_back(bignum_blk_vec[0]);

      for (u64 k = 1; k <= delta; k++) {
        vals.push_back(bignum_blk_vec[2 * k - 1]);
        vals.push_back(bignum_blk_vec[2 * k]);
      }
    }
  }

  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

void sender_mask_paillier_lp(const std::size_t &elements_size,
                             std::vector<u32> &masks,
                             ipcl::CipherText &vec_mask_ct,
                             const ipcl::PublicKey &pk) {
  PRNG prng(oc::sysRandomSeed());

  std::vector<u32> vec_mask_u32(elements_size);
  prng.get<u32>(vec_mask_u32);

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  for (u64 i = 0; i < elements_size; i++) {
    ////////////////////
    // vec_mask_u32[i] = 10;
    ////////////////////

    masks.push_back((vec_mask_u32[i]));
  }
  vec_mask_ct = pk.encrypt(ipcl::PlainText(vec_mask_u32));

  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

void receiver_w_to_key_paillier_lp(
    const std::vector<std::vector<u64>> &elements,
    const std::vector<Rist25519_point> &vec_keyw, std::vector<block> &keys,
    const u32 &dimension, const i32 &delta) {
  for (u64 i = 0; i < elements.size(); i++) {
    for (u64 j = 0; j < dimension; j++) {

      keys.push_back(get_key_from_k_d_x(vec_keyw[i], j, elements[i][j]));

      for (u64 k = 1; k <= delta; k++) {
        keys.push_back(get_key_from_k_d_x(vec_keyw[i], j, elements[i][j] + k));
        keys.push_back(get_key_from_k_d_x(vec_keyw[i], j, elements[i][j] - k));
      }
    }
  }
  return;
}

void sender_q_to_masked_distance_paillier_lp(
    const std::vector<std::vector<u64>> &elements,
    const std::vector<Rist25519_point> &vec_kq,
    const std::vector<std::vector<block>> &codeWords,
    const ipcl::CipherText &vec_mask_ct, ipcl::CipherText &vec_masked_distance,
    const u32 &dimension, const i32 &okvs_n, const ipcl::PublicKey &pk) {

  RBOKVS rb_okvs;
  rb_okvs.init(okvs_n, 0.1, lambda, seed);

  ipcl::initializeContext("QAT");
  std::vector<std::vector<BigNumber>> decode_result_in_dimension(
      dimension, std::vector<BigNumber>(elements.size()));
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  for (u64 i = 0; i < elements.size(); i++) {

    for (u64 j = 0; j < dimension; j++) {
      std::vector<element> value = rb_okvs.decode(
          codeWords, get_key_from_k_d_x(vec_kq[i], j, elements[i][j]),
          PAILLIER_CIPHER_SIZE_IN_BLOCK);
      decode_result_in_dimension[j][i] = block_vector_to_bignumer(value);
    }
  }
  ipcl::CipherText masked_distances(vec_mask_ct);

  for (u64 j = 0; j < dimension; j++) {
    masked_distances =
        masked_distances + ipcl::CipherText(pk, decode_result_in_dimension[j]);
  }

  vec_masked_distance = masked_distances;
  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

void sender_q_to_masked_distance_paillier_linfty(
    const std::vector<std::vector<u64>> &elements,
    const std::vector<Rist25519_point> &vec_kq,
    const std::vector<std::vector<block>> &codeWords,
    ipcl::CipherText &vec_masked_distance,
    std::vector<BigNumber> &additive_masks, const u32 &dimension,
    const i32 &okvs_n, const ipcl::PublicKey &pk) {

  RBOKVS rb_okvs;
  rb_okvs.init(okvs_n, 0.1, lambda, seed);
  BigNumber N = *(pk.getN());

  ipcl::initializeContext("QAT");
  std::vector<std::vector<BigNumber>> decode_result_in_dimension(
      dimension, std::vector<BigNumber>(elements.size()));
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  for (u64 i = 0; i < elements.size(); i++) {
    additive_masks[i] = (ipcl::getRandomBN(2048) % N);

    for (u64 j = 0; j < dimension; j++) {
      std::vector<element> value = rb_okvs.decode(
          codeWords, get_key_from_k_d_x(vec_kq[i], j, elements[i][j]),
          PAILLIER_CIPHER_SIZE_IN_BLOCK);
      decode_result_in_dimension[j][i] = block_vector_to_bignumer(value);
    }
  }
  ipcl::CipherText masked_distances(
      ipcl::CipherText(pk, decode_result_in_dimension[0]));

  for (u64 j = 1; j < dimension; j++) {
    masked_distances =
        masked_distances + ipcl::CipherText(pk, decode_result_in_dimension[j]);
  }

  vec_masked_distance =
      masked_distances + pk.encrypt(ipcl::PlainText(additive_masks));
  // vec_masked_distance = masked_distances;

  // std::cout << "[send]: send paillier cipher done" <<
  // vec_masked_distance.getElement(0) << std::endl;

  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

// void sender_q_to_mask_distance_paillier_lp(const
// std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>&
// vec_kq, const std::vector<std::vector<block>>& codeWords,
//                                             std::vector<u32>& masks,
//                                             std::vector<std::vector<block>>&
//                                             vec_masked_distance, const u32&
//                                             dimension, const i32& okvs_n,
//                                             const ipcl::PublicKey& pk){
//     PRNG prng(oc::sysRandomSeed());
//     std::vector<u32> vec_mask_u32(elements.size());
//     prng.get<u32>(vec_mask_u32);
//     RBOKVS rb_okvs;
//     rb_okvs.init(okvs_n, 0.1, lambda, seed);
//     ipcl::initializeContext("QAT");
//     std::vector<std::vector<BigNumber>> decode_result_in_dimension(dimension,
//     std::vector<BigNumber>(elements.size()));
//     ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
//     for(auto i = 0; i < elements.size(); i++){
//         masks.push_back((vec_mask_u32[i]));
//         for(auto j = 0; j < dimension; j++){
//             auto value = rb_okvs.decode(codeWords,
//             get_key_from_k_d_x(vec_kq[i], j, elements[i][j]),
//             PAILLIER_CIPHER_SIZE_IN_BLOCK); decode_result_in_dimension[j][i]
//             = block_vector_to_bignumer(value);
//         }
//     }
//     ipcl::CipherText
//     masked_distances(pk.encrypt(ipcl::PlainText(vec_mask_u32))); for(auto j =
//     0; j < dimension; j++){
//         masked_distances = masked_distances + ipcl::CipherText(pk,
//         decode_result_in_dimension[j]);
//     }
//     for(auto i = 0; i < elements.size(); i++){
//         vec_masked_distance.push_back(bignumer_to_block_vector(masked_distances.getElement(i)));
//     }
//     ipcl::setHybridOff();
//     ipcl::terminateContext();
//     return;
// }

void receiver_get_masked_distance_paillier_lp(
    const ipcl::CipherText &vec_masked_distance,
    std::vector<u32> &masked_distance, const ipcl::KeyPair &paillier_key) {

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::PlainText masked_distance_plain =
      paillier_key.priv_key.decrypt(vec_masked_distance);

  for (u64 i = 0; i < masked_distance_plain.getSize(); i++) {

    masked_distance.push_back((masked_distance_plain.getElementVec(i)[0]));

    // printf("masked_distance:%d \n", masked_distance[i]);
  }
  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

void receiver_get_result_paillier_linfty(
    const ipcl::CipherText &vec_masked_distance,
    std::vector<BigNumber> &result_masks, const ipcl::KeyPair &paillier_key) {

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::PlainText masked_distance_plain =
      paillier_key.priv_key.decrypt(vec_masked_distance);
  result_masks = std::vector<BigNumber>(masked_distance_plain);

  // std::cout << "[recv]: recv paillier cipher dec" << result_masks[0] %
  // *(paillier_key.pub_key.getN()) << std::endl;

  // for(u64 i = 0; i < masked_distance_plain.getSize(); i++){

  //     if((masked_distance_plain.getElementVec(i)[0]) == 0){
  //         result.pushBack(1);
  //     }else{
  //         result.pushBack(0);
  //     }

  // }
  ipcl::setHybridOff();
  ipcl::terminateContext();
  return;
}

u64 sender_get_prefixes(const std::vector<u32> &masks,
                        std::vector<std::vector<block>> &vec_prefixes,
                        const i32 &delta, const u32 &p) {
  u64 max_prefix_num(0);
  for (auto iter : masks) {
    std::vector<block> temp_prefixes;
    // std::cout << "send mask distance: " << iter << std::endl;
    //  block_to_prefix(iter, log_delta_pow_p, temp_prefixes);
    interval_to_prefix(iter, iter + (u32)(pow(delta, p)), temp_prefixes);
    vec_prefixes.push_back(temp_prefixes);
    if (max_prefix_num < temp_prefixes.size()) {
      max_prefix_num = temp_prefixes.size();
    }
  }
  return max_prefix_num;
}

void pad_send_prefixes_k(
    const std::vector<std::vector<DH25519_point>> &send_prefixes_k,
    std::vector<DH25519_point> &send_prefixes_k_net,
    const u64 &max_prefix_num) {

  PRNG prng(oc::sysRandomSeed());
  for (auto iter : send_prefixes_k) {
    send_prefixes_k_net.insert(send_prefixes_k_net.end(), iter.begin(),
                               iter.end());
    for (u64 i = 0; i < max_prefix_num - iter.size(); i++) {
      send_prefixes_k_net.push_back(DH25519_point(prng));
    }
  }
  return;
}

void receiver_get_prefixes(const std::vector<u32> &masked_distance,
                           std::vector<std::vector<block>> &vec_prefixes,
                           const i32 &delta, const u32 &p) {
  int log_delta_pow_p = log2ceil(1 + pow(delta, p));
  for (auto iter : masked_distance) {
    std::vector<block> temp_prefixes;
    // std::cout << "recv mask distance: " << iter << std::endl;
    block_to_prefix(iter, log_delta_pow_p, temp_prefixes);
    // std::cout << "recv mask distance interval: " << iter - (u32)(pow(delta,
    // p)) << ", " << iter + (u32)(pow(delta, p)) << std::endl;
    vec_prefixes.push_back(temp_prefixes);
  }
  return;
}

// DH-PSICA
void prefixes_pow_sk(const std::vector<std::vector<block>> &vec_prefixes,
                     std::vector<std::vector<DH25519_point>> &vec_prefixes_k,
                     const DH25519_number &sk) {
  for (auto iter : vec_prefixes) {
    std::vector<DH25519_point> vec_point;
    for (auto iterator : iter) {
      // DH25519_number temp = get_dh_number_from_block(iterator) * sk;
      // vec_point.push_back(DH25519_point::mulGenerator(temp));
      vec_point.push_back(DH25519_point(iterator) * sk);
    }
    vec_prefixes_k.push_back(vec_point);
  }
  return;
}

void prefixes_repow_sk(
    const std::vector<std::vector<DH25519_point>> &vec_prefixes_k,
    std::vector<std::vector<DH25519_point>> &vec_prefixes_kk,
    const DH25519_number &sk) {
  for (auto iter : vec_prefixes_k) {
    std::vector<DH25519_point> vec_point;
    for (auto iterator : iter) {
      vec_point.push_back(iterator * sk);
    }
    vec_prefixes_kk.push_back(vec_point);
  }
  return;
}

void prefixes_check(
    const std::vector<std::vector<DH25519_point>> &send_prefixes_kk,
    const std::vector<std::vector<DH25519_point>> &recv_prefixes_kk,
    BitVector &result) {
  bool temp;
  for (auto i = 0; i < send_prefixes_kk.size(); i++) {
    temp = false;
    for (auto iter : send_prefixes_kk[i]) {
      auto it_find =
          find(recv_prefixes_kk[i].begin(), recv_prefixes_kk[i].end(), iter);
      if (it_find != recv_prefixes_kk[i].end()) {
        temp = true;
        // break;
      }
    }
    if (temp == 1) {
      result.pushBack(1);
    } else {
      // printf("!!!! %d th == 0\n", i);
      result.pushBack(0);
    }
  }
  return;
}

void prefixes_check(
    const std::vector<std::vector<DH25519_point>> &send_prefixes_kk,
    const std::vector<std::vector<DH25519_point>> &recv_prefixes_kk,
    std::vector<bool> &result) {
  bool temp;
  for (auto i = 0; i < send_prefixes_kk.size(); i++) {
    temp = false;
    for (auto iter : send_prefixes_kk[i]) {
      auto it_find =
          find(recv_prefixes_kk[i].begin(), recv_prefixes_kk[i].end(), iter);
      if (it_find != recv_prefixes_kk[i].end()) {
        temp = true;
        // break;
      }
    }
    result.push_back(temp);
  }
  return;
}

void Bignumber_to_point_k(const std::vector<BigNumber> &vec_BigNum,
                          std::vector<DH25519_point> &vec_point_k,
                          const DH25519_number &sk) {

  blake3_hasher hasher;
  block hash_out;

  for (auto BigNum : vec_BigNum) {
    std::vector<u8> temp;
    BigNum.num2char(temp);

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, temp.data(), temp.size());
    blake3_hasher_finalize(&hasher, hash_out.data(), 16);

    vec_point_k.push_back(sk * DH25519_point(hash_out));
  }
  return;
}

void point_k_to_point_kk(const std::vector<DH25519_point> &vec_point_k,
                         std::vector<DH25519_point> &vec_point_kk,
                         const DH25519_number &sk) {

  for (auto point_k : vec_point_k) {
    vec_point_kk.push_back(sk * point_k);
  }
  return;
}

void dh_check(const std::vector<DH25519_point> &send_kk,
              const std::vector<DH25519_point> &recv_kk, BitVector &result) {
  for (auto i = 0; i < send_kk.size(); i++) {
    if (send_kk[i] == recv_kk[i]) {
      result.pushBack(1);
    } else {
      // printf("!!!! %d th == 0\n", i);
      result.pushBack(0);
    }
  }
  return;
}

void fmat_paillier_recv_online(
    coproto::LocalAsyncSocket *channel,
    std::vector<std::vector<u64>> *receiver_elements,
    std::vector<Rist25519_point> *recv_vec_dhkk_seedsum,
    std::vector<std::vector<block>> *fmat_vals, u64 dimension, u64 delta, u64 p,
    ipcl::KeyPair paillier_key, DH25519_number recv_dh_k) {
  std::vector<block> fmat_keys;

  receiver_w_to_key_paillier_lp(*receiver_elements, *recv_vec_dhkk_seedsum,
                                fmat_keys, dimension, delta);

  RBOKVS rb_okvs;
  rb_okvs.init(fmat_keys.size(), 0.1, lambda, seed);
  std::vector<std::vector<block>> codeWords_fmat(
      rb_okvs.mSize, std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  rb_okvs.encode(fmat_keys, *fmat_vals, PAILLIER_CIPHER_SIZE_IN_BLOCK,
                 codeWords_fmat);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(rb_okvs.mSize));
  for (u64 i = 0; i < rb_okvs.mSize; i++) {
    coproto::sync_wait((*channel).send(codeWords_fmat[i]));
  }

  // std::vector<block> codeWords_fmat_net(rb_okvs.mSize *
  // PAILLIER_CIPHER_SIZE_IN_BLOCK);

  // for(u64 i = 0;i < rb_okvs.mSize; i++){
  //     for(u64 j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++){
  //         codeWords_fmat_net[i * PAILLIER_CIPHER_SIZE_IN_BLOCK + j] =
  //         codeWords_fmat[i][j];
  //     }
  // }

  // std::cout << "rb_okvs.msize = "<< rb_okvs.mSize << std::endl;

  // std::cout << "fmat_paillier_recv_online: codeWords_fmat_net send begin" <<
  // std::endl;
  //  coproto::sync_wait((*channel).flush());
  //  coproto::sync_wait((*channel).send(codeWords_fmat_net));
  // std::cout << "fmat_paillier_recv_online: fmat_keys.size() send begin" <<
  // std::endl;
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(fmat_keys.size()));

  // std::cout << "fmat_paillier_recv_online: codeWords_fmat_net send done" <<
  // std::endl;

  ////////////////////////////////////////
  // 1. receiver sends codeWords to sender.
  ////////////////////////////////////////

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::CipherText vec_masked_distance;
  size_t size_vec_bignum;

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(size_vec_bignum));

  std::vector<BigNumber> masked_distance_temp(size_vec_bignum);
  for (u64 i = 0; i < size_vec_bignum; i++) {
    std::vector<block> ct_temp;
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).recvResize(ct_temp));
    masked_distance_temp[i] = block_vector_to_bignumer(ct_temp);
  }

  // std::cout << "fmat_paillier_recv_online: ct_temp recv done" << std::endl;

  vec_masked_distance =
      ipcl::CipherText(paillier_key.pub_key, masked_distance_temp);

  ////////////////////////////////////////
  // 2. sender sends vec_masked_distance to receiver.
  ////////////////////////////////////////

  std::vector<u32> masked_distance;
  fm_paillier::receiver_get_masked_distance_paillier_lp(
      vec_masked_distance, masked_distance, paillier_key);

  ipcl::setHybridOff();
  ipcl::terminateContext();

  std::vector<std::vector<block>> recv_prefixes;

  fm_paillier::receiver_get_prefixes(masked_distance, recv_prefixes, delta, p);

  u64 send_set_size;
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(send_set_size));

  std::vector<std::vector<DH25519_point>> send_prefixes_k(send_set_size),
      send_prefixes_kk;
  std::vector<std::vector<DH25519_point>> recv_prefixes_k,
      recv_prefixes_kk(send_set_size);

  fm_paillier::prefixes_pow_sk(recv_prefixes, recv_prefixes_k, recv_dh_k);

  for (u64 i = 0; i < send_set_size; i++) {
    coproto::sync_wait((*channel).send(recv_prefixes_k[i]));
  }

  // std::cout << "fmat_paillier_recv_online: recv_prefixes_k send done" <<
  // std::endl;
  ////////////////////////////////////////
  // 3. receiver sends recv_prefixes_k to receiver.
  ////////////////////////////////////////

  std::vector<DH25519_point> send_prefixes_k_net;
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(send_prefixes_k_net));
  u64 num_prefix_send = send_prefixes_k_net.size() / send_set_size;

  // std::cout << ": send_prefixes_k_net recv done" << std::endl;
  for (u64 i = 0; i < send_set_size; i++) {
    send_prefixes_k[i].insert(send_prefixes_k[i].end(),
                              send_prefixes_k_net.begin() + i * num_prefix_send,
                              send_prefixes_k_net.begin() +
                                  i * num_prefix_send + num_prefix_send);
  }
  ////////////////////////////////////////
  // 4. sender sends send_prefixes_k to receiver.
  ////////////////////////////////////////

  for (u64 i = 0; i < send_set_size; i++) {
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).recvResize(recv_prefixes_kk[i]));
  }

  // std::cout << "one" <<
  // std::endl;
  ////////////////////////////////////////
  // 5. sender sends shuffled recv_prefixes_kk to receiver.
  ////////////////////////////////////////
  fm_paillier::prefixes_repow_sk(send_prefixes_k, send_prefixes_kk, recv_dh_k);

  BitVector result;
  fm_paillier::prefixes_check(send_prefixes_kk, recv_prefixes_kk, result);

  // printf("FPSI-CA:%d\n", result.hammingWeight());

  // std::cout << "fmat_paillier_recv_online: run_ot_receiver begin" <<
  // std::endl;

  OT_for_FPSI::last_ot_recv(channel, result.size(), &result, dimension);
  // std::cout << "fmat_paillier_recv_online: run_ot_receiver done" <<
  // std::endl;

  return;
}

void fmat_paillier_send_online(
    coproto::LocalAsyncSocket *channel,
    std::vector<std::vector<u64>> *sender_elements,
    std::vector<Rist25519_point> *send_vec_dhkk_seedsum,
    std::vector<DH25519_point> *send_prefixes_k, ipcl::CipherText *vec_mask_ct,
    u64 dimension, u64 delta, u64 p, ipcl::PublicKey paillier_pub_key,
    DH25519_number send_dh_k) {
  // std::vector<block> codeWords_fmat_net;
  size_t fmat_keys_size;
  size_t codeWords_fmat_size;

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recv(codeWords_fmat_size));
  std::vector<std::vector<block>> codeWords_fmat(
      codeWords_fmat_size, std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));
  for (u64 i = 0; i < codeWords_fmat_size; i++) {
    coproto::sync_wait((*channel).recvResize(codeWords_fmat[i]));
  }

  // coproto::sync_wait((*channel).flush());
  // coproto::sync_wait((*channel).recvResize(codeWords_fmat_net));
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(fmat_keys_size));

  // std::vector<std::vector<block>> codeWords_fmat((codeWords_fmat_net.size() /
  // PAILLIER_CIPHER_SIZE_IN_BLOCK),
  // std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK)); for(u64 i = 0; i <
  // (codeWords_fmat_net.size() / PAILLIER_CIPHER_SIZE_IN_BLOCK); i++){
  //     for(u64 j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++){
  //         codeWords_fmat[i][j] = codeWords_fmat_net[i *
  //         PAILLIER_CIPHER_SIZE_IN_BLOCK + j];
  //     }
  // }

  ipcl::CipherText vec_masked_distance;
  fm_paillier::sender_q_to_masked_distance_paillier_lp(
      *sender_elements, *send_vec_dhkk_seedsum, codeWords_fmat, *vec_mask_ct,
      vec_masked_distance, dimension, fmat_keys_size, paillier_pub_key);

  ////////////////////////////////////////
  // 2. sender sends vec_masked_distance to receiver.
  ////////////////////////////////////////

  auto vec_masked_distance_vec_bignum = vec_masked_distance.getTexts();

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(vec_masked_distance_vec_bignum.size()));

  for (u64 i = 0; i < vec_masked_distance_vec_bignum.size(); i++) {
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait(
        (*channel).send(bignumer_to_block_vector(vec_masked_distance[i])));
  }

  // std::vector<std::vector<block>> send_prefixes;
  // fm_paillier::sender_get_prefixes(*masks, send_prefixes, delta, p);

  u64 send_set_size(sender_elements->size());
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(send_set_size));

  // std::vector<std::vector<DH25519_point>> send_prefixes_k, send_prefixes_kk;
  std::vector<std::vector<DH25519_point>> recv_prefixes_k(send_set_size),
      recv_prefixes_kk;
  ////////////////////////////////////////
  // 3. receiver sends recv_prefixes_k to receiver.
  ////////////////////////////////////////
  ////////////////////////////////////////
  // 4. sender sends send_prefixes_k to receiver.
  ////////////////////////////////////////
  ////////////////////////////////////////
  // 5. sender sends shuffled recv_prefixes_kk to receiver.
  ////////////////////////////////////////
  PRNG prng(oc::sysRandomSeed());

  for (u64 i = 0; i < send_set_size; i++) {
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).recvResize(recv_prefixes_k[i]));
    std::shuffle(recv_prefixes_k[i].begin(), recv_prefixes_k[i].end(), prng);
  }

  fm_paillier::prefixes_repow_sk(recv_prefixes_k, recv_prefixes_kk, send_dh_k);
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send((*send_prefixes_k)));

  for (u64 i = 0; i < send_set_size; i++) {
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).send(recv_prefixes_kk[i]));
  }

  // std::vector<std::array<block, 2UL>> send_msg(send_set_size);
  // for(u64 i = 0; i < send_set_size; i++){
  //     send_msg[i][1] = block((*sender_elements)[i][0],
  //     (*sender_elements)[i][1]);
  // }

  // OT_for_FPSI::run_ot_sender(*channel, send_msg);

  OT_for_FPSI::last_ot_send(channel, sender_elements, dimension);
}

void fmat_paillier_linfty_recv_online(
    coproto::LocalAsyncSocket *channel,
    std::vector<std::vector<u64>> *receiver_elements,
    std::vector<Rist25519_point> *recv_vec_dhkk_seedsum,
    std::vector<std::vector<block>> *fmat_vals, u64 dimension, u64 delta,
    ipcl::KeyPair paillier_key) {
  std::vector<block> fmat_keys;

  receiver_w_to_key_paillier_lp(*receiver_elements, *recv_vec_dhkk_seedsum,
                                fmat_keys, dimension, delta);

  RBOKVS rb_okvs;
  rb_okvs.init(fmat_keys.size(), 0.1, lambda, seed);
  std::vector<std::vector<block>> codeWords_fmat(
      rb_okvs.mSize, std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  rb_okvs.encode(fmat_keys, *fmat_vals, PAILLIER_CIPHER_SIZE_IN_BLOCK,
                 codeWords_fmat);
  // std::cout << "[recv]: encode done, send begin" << std::endl;

  // std::vector<block> codeWords_fmat_net(rb_okvs.mSize *
  // PAILLIER_CIPHER_SIZE_IN_BLOCK);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(rb_okvs.mSize));
  for (u64 i = 0; i < rb_okvs.mSize; i++) {
    coproto::sync_wait((*channel).send(codeWords_fmat[i]));
  }

  // for(u64 i = 0;i < rb_okvs.mSize; i++){
  //     for(u64 j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++){
  //         codeWords_fmat_net[i * PAILLIER_CIPHER_SIZE_IN_BLOCK + j] =
  //         codeWords_fmat[i][j];
  //     }
  // }

  // std::cout << "[recv]: encode done, send begin" << std::endl;
  // std::cout << "[recv]: send size = " << codeWords_fmat_net.size() <<
  // std::endl;

  // coproto::sync_wait((*channel).flush());
  // coproto::sync_wait((*channel).send(codeWords_fmat_net));
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send(fmat_keys.size()));

  // std::cout << "[recv]: send okvs done" << std::endl;

  ////////////////////////////////////////
  // 1. receiver sends codeWords to sender.
  ////////////////////////////////////////

  ipcl::initializeContext("QAT");
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  ipcl::CipherText vec_masked_distance;
  size_t size_vec_bignum;

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(size_vec_bignum));

  // std::cout << "[recv]: recv paillier cipher begin" << std::endl;
  //  std::cout << "[recv]: expect recv " << size_vec_bignum << " paillier
  //  cipher" << std::endl;

  std::vector<BigNumber> masked_distance_temp(size_vec_bignum);
  for (u64 i = 0; i < size_vec_bignum; i++) {
    // if((i%1000) == 0){printf("**********recv %d cipher\n", i);}
    std::vector<block> ct_temp;
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).recvResize(ct_temp));
    masked_distance_temp[i] = block_vector_to_bignumer(ct_temp);
  }

  // std::cout << "[recv]: recv paillier cipher done" << std::endl;

  // std::cout << "[recv]: recv paillier cipher done" << masked_distance_temp[0]
  // << std::endl;

  vec_masked_distance =
      ipcl::CipherText(paillier_key.pub_key, masked_distance_temp);

  ////////////////////////////////////////
  // 2. sender sends vec_masked_distance to receiver.
  ////////////////////////////////////////

  std::vector<BigNumber> masked_distance;
  fm_paillier::receiver_get_result_paillier_linfty(
      vec_masked_distance, masked_distance, paillier_key);

  ipcl::setHybridOff();
  ipcl::terminateContext();

  PRNG prng(oc::sysRandomSeed());
  DH25519_number dh_k(prng);

  std::vector<DH25519_point> vec_send_point_k, vec_send_point_kk;
  std::vector<DH25519_point> vec_recv_point_k, vec_recv_point_kk;

  Bignumber_to_point_k(masked_distance, vec_recv_point_k, dh_k);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send((vec_recv_point_k)));

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(vec_send_point_k));

  point_k_to_point_kk(vec_send_point_k, vec_send_point_kk, dh_k);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(vec_recv_point_kk));

  BitVector result;
  fm_paillier::dh_check(vec_recv_point_kk, vec_send_point_kk, result);

  // printf("FPSI-CA:%d\n", result.hammingWeight());

  // printf("FPSI-CA:%d\n", result.hammingWeight());

  // auto ot_result = OT_for_FPSI::run_ot_receiver(*channel, result,
  // result.size());

  OT_for_FPSI::last_ot_recv(channel, result.size(), &result, dimension);

  return;
}

void fmat_paillier_linfty_send_online(
    coproto::LocalAsyncSocket *channel,
    std::vector<std::vector<u64>> *sender_elements,
    std::vector<Rist25519_point> *send_vec_dhkk_seedsum, u64 dimension,
    u64 delta, ipcl::PublicKey paillier_pub_key) {
  // std::vector<block> codeWords_fmat_net;
  size_t fmat_keys_size;
  size_t codeWords_fmat_size;

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recv(codeWords_fmat_size));
  std::vector<std::vector<block>> codeWords_fmat(
      codeWords_fmat_size, std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));
  for (u64 i = 0; i < codeWords_fmat_size; i++) {
    coproto::sync_wait((*channel).recvResize(codeWords_fmat[i]));
  }

  // coproto::sync_wait((*channel).flush());
  // coproto::sync_wait((*channel).recvResize(codeWords_fmat_net));
  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recv(fmat_keys_size));

  // // std::vector<std::vector<block>>
  // codeWords_fmat((codeWords_fmat_net.size() / PAILLIER_CIPHER_SIZE_IN_BLOCK),
  // std::vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK)); for(u64 i = 0; i <
  // (codeWords_fmat_net.size() / PAILLIER_CIPHER_SIZE_IN_BLOCK); i++){
  //     for(u64 j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++){
  //         codeWords_fmat[i][j] = codeWords_fmat_net[i *
  //         PAILLIER_CIPHER_SIZE_IN_BLOCK + j];
  //     }
  // }

  ipcl::CipherText vec_masked_distance;
  std::vector<BigNumber> additive_masks((*sender_elements).size());
  fm_paillier::sender_q_to_masked_distance_paillier_linfty(
      *sender_elements, *send_vec_dhkk_seedsum, codeWords_fmat,
      vec_masked_distance, additive_masks, dimension, fmat_keys_size,
      paillier_pub_key);

  ////////////////////////////////////////
  // 2. sender sends vec_masked_distance to receiver.
  ////////////////////////////////////////

  // auto vec_masked_distance_vec_bignum = vec_masked_distance.getTexts();

  // std::cout << "[send]: additive_masks[0] done" << additive_masks[0] <<
  // std::endl; std::cout << "[send]: send paillier cipher done" <<
  // vec_masked_distance.getElement(0) << std::endl;

  // auto vec_masked_distance_check = ipcl::CipherText(paillier_pub_key,
  // vec_masked_distance.getElement(0));

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send((*sender_elements).size()));

  for (u64 i = 0; i < (*sender_elements).size(); i++) {
    coproto::sync_wait((*channel).flush());
    coproto::sync_wait((*channel).send(
        bignumer_to_block_vector(vec_masked_distance.getElement(i))));
  }

  // std::cout << additive_masks[0] << std::endl;

  PRNG prng(oc::sysRandomSeed());
  DH25519_number dh_k(prng);

  std::vector<DH25519_point> vec_send_point_k;
  std::vector<DH25519_point> vec_recv_point_k, vec_recv_point_kk;

  Bignumber_to_point_k(additive_masks, vec_send_point_k, dh_k);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).recvResize(vec_recv_point_k));

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send((vec_send_point_k)));

  point_k_to_point_kk(vec_recv_point_k, vec_recv_point_kk, dh_k);

  coproto::sync_wait((*channel).flush());
  coproto::sync_wait((*channel).send((vec_recv_point_kk)));

  // u64 send_set_size(sender_elements->size());

  // std::vector<std::array<block, 2UL>> send_msg(send_set_size);
  // for(u64 i = 0; i < send_set_size; i++){
  //     send_msg[i][1] = block((*sender_elements)[i][0],
  //     (*sender_elements)[i][1]);
  // }

  // OT_for_FPSI::run_ot_sender(*channel, send_msg);
  OT_for_FPSI::last_ot_send(channel, sender_elements, dimension);
}

} // namespace fm_paillier

} // namespace osuCrypto