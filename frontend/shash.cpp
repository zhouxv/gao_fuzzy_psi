#include "shash.h"
#include "fm.h"
#include "rb_okvs.h"

#include <stack>

#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/plaintext.hpp>

#include "fuzzy_mapping.h"

typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

namespace osuCrypto {

std::pair<double, double> test_sas_fm(const CLP &cmd) {
  const u64 dimension = cmd.getOr("d", 2);
  const u64 delta = cmd.getOr("delta", 16);
  const u64 side_length = 1;
  const u64 p = 0;
  const u64 recv_set_size = 1ull << cmd.getOr("r", 8);
  const u64 send_set_size = 1ull << cmd.getOr("s", 8);
  const u64 intersection_size = cmd.getOr("i", 10);
  if ((intersection_size > recv_set_size) |
      (intersection_size > send_set_size)) {
    throw std::runtime_error(
        "intersection_size should not be greater than set_size");
  }

  PRNG prng(oc::sysRandomSeed());

  std::vector<std::vector<u64>> receiver_elements(
      recv_set_size, std::vector<u64>(dimension, 0));
  std::vector<std::vector<u64>> sender_elements(send_set_size,
                                                std::vector<u64>(dimension, 0));

  for (u64 i = 0; i < recv_set_size; i++) {
    for (u64 j = 0; j < dimension; j++) {
      receiver_elements[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
          1.5 * delta;
    }
  }

  for (u64 i = 0; i < send_set_size; i++) {
    for (u64 j = 0; j < dimension; j++) {
      sender_elements[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
          1.5 * delta;
    }
  }

  u64 base_pos = (prng.get<u64>()) % (send_set_size - intersection_size - 1);
  // u64 base_pos = 0;
  for (u64 i = base_pos; i < base_pos + intersection_size; i++) {
    for (u64 j = 0; j < dimension; j++) {
      sender_elements[i][j] = receiver_elements[i - base_pos][j];
    }
    for (u64 j = 0; j < 2; j++) {
      sender_elements[i][j] +=
          ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
    }
  }
  // std::cout << "data init done" << std::endl;

  ///////////////////////////////////////////////////////////////////////////////////////
  // key generate
  ///////////////////////////////////////////////////////////////////////////////////////
  Rist25519_number recv_sk(prng);
  std::array<Rist25519_point, 2> recv_pk;
  recv_pk[0] = Rist25519_point(prng);
  recv_pk[1] = recv_sk * recv_pk[0];

  Rist25519_number send_sk(prng);
  std::array<Rist25519_point, 2> send_pk;
  send_pk[0] = Rist25519_point(prng);
  send_pk[1] = send_sk * send_pk[0];

  Rist25519_number recv_dh_sk(prng);
  Rist25519_number send_dh_sk(prng);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  Timer time;

  ///////////////////////////////////////////////////////////////////////////////////////
  // offline
  ///////////////////////////////////////////////////////////////////////////////////////
  time.setTimePoint("Start");

  tVar online_time;

  std::stack<Rist25519_number> recv_vals_candidate_r;
  std::stack<Rist25519_number> recv_vals_candidate_skr;
  std::vector<std::vector<Rist25519_number>> recv_values;
  fmap::assign_segments(recv_set_size, recv_values, recv_vals_candidate_r,
                        recv_vals_candidate_skr, dimension, delta, side_length,
                        recv_sk);
  std::stack<Rist25519_number> send_vals_candidate_r;
  std::stack<Rist25519_number> send_vals_candidate_skr;
  std::vector<std::vector<Rist25519_number>> send_values;
  fmap::assign_segments(send_set_size, send_values, send_vals_candidate_r,
                        send_vals_candidate_skr, dimension, delta, side_length,
                        send_sk);
  std::vector<Rist25519_number> recv_masks;
  std::vector<Rist25519_number> recv_masks_inv;
  fmap::get_mask_cipher(recv_set_size, recv_masks, recv_masks_inv, recv_pk);
  std::vector<Rist25519_number> send_masks;
  std::vector<Rist25519_number> send_masks_inv;
  fmap::get_mask_cipher(send_set_size, send_masks, send_masks_inv, send_pk);
  // std::cout << "fmap offline done" << std::endl;

  time.setTimePoint("offline");

  ///////////////////////////////////////////////////////////////////////////////////////
  // online
  ///////////////////////////////////////////////////////////////////////////////////////

  tStart(online_time);

  auto sockets = coproto::LocalAsyncSocket::makePair();

  std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);
  std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

  std::thread thread_fmap_recv(
      fmap::fmap_recv_online, &sockets[0], &receiver_elements, &recv_values,
      &recv_vals_candidate_r, &recv_vals_candidate_skr, &recv_masks,
      &recv_masks_inv, &recv_vec_dhkk_seedsum, dimension, delta, side_length,
      recv_sk, recv_pk, recv_dh_sk);
  std::thread thread_fmap_send(
      fmap::fmap_send_online, &sockets[1], &sender_elements, &send_values,
      &send_vals_candidate_r, &send_vals_candidate_skr, &send_masks,
      &send_masks_inv, &send_vec_dhkk_seedsum, dimension, delta, side_length,
      send_sk, send_pk, send_dh_sk);

  thread_fmap_recv.join();
  thread_fmap_send.join();
  double fmap_online_time = tEnd(online_time);

  auto recv_bytes_present_fmap = sockets[0].bytesSent();
  auto send_bytes_present_fmap = sockets[1].bytesSent();

  time.setTimePoint("fmap done");

  time.setTimePoint("online done");

  auto recv_bytes_present = sockets[0].bytesSent();
  auto send_bytes_present = sockets[1].bytesSent();

  return {fmap_online_time,
          ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024.0};
}

void test_shash(const CLP &cmd) {

  const u64 dimension = cmd.getOr("d", 2);
  const u64 delta = cmd.getOr("delta", 16);
  const u64 side_length = 1;
  const u64 p = 0;
  const u64 recv_set_size = 1ull << cmd.getOr("r", 8);
  const u64 send_set_size = 1ull << cmd.getOr("s", 8);
  const u64 intersection_size = cmd.getOr("i", 10);
  const u64 trait = cmd.getOr("trait", 1);
  if ((intersection_size > recv_set_size) |
      (intersection_size > send_set_size)) {
    throw std::runtime_error("intersection_size > set_size");
  }

  std::cout << "recv_set_size: " << recv_set_size
            << " | send_set_size: " << send_set_size
            << " | dimension: " << dimension << " | delta: " << delta
            << " | distance: l_infty"
            << " | 测试次数: " << trait << std::endl;

  std::vector<double> times(trait), comus(trait);
  for (u64 i = 0; i < trait; i++) {
    auto tmp = test_sas_fm(cmd);
    times[i] = tmp.first;
    comus[i] = tmp.second;
  }

  auto avg_time = std::accumulate(times.begin(), times.end(), 0.0) / trait;
  auto avg_com = std::accumulate(comus.begin(), comus.end(), 0.0) / trait;

  std::cout << "平均时间 : " << avg_time << " ms, " << avg_time / 1000.0
            << " s; 平均通信量: " << avg_com << " MB" << std::endl;
}
} // namespace osuCrypto