#pragma once

#include "rb_okvs.h"
#include "ipcl/ipcl.hpp"
#include <stack>

#include "coproto/Socket/LocalAsyncSock.h"

#include <cryptoTools/Common/BitVector.h>
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"

const oc::u32 PAILLIER_KEY_SIZE_IN_BIT = 2048;
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BLOCK = ((PAILLIER_KEY_SIZE_IN_BIT * 2) / 128);
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BYTE = PAILLIER_CIPHER_SIZE_IN_BLOCK * 16;

const oc::u32 EC_CIPHER_SIZE_IN_BLOCK = 4;

using DH25519_point = osuCrypto::Sodium::Monty25519;
using DH25519_number = osuCrypto::Sodium::Scalar25519;


using FM25519_point = osuCrypto::Sodium::Rist25519;
using FM25519_number = osuCrypto::Sodium::Prime25519;

namespace osuCrypto
{
    namespace OT_for_FPSI{
        const u64 OT_NUMS_BOUND = 128UL;
        const size_t KAPPA = 128;
        std::vector<element> run_ot_receiver(coproto::LocalAsyncSocket& channel, BitVector& choices, const u64& numOTs);

        void run_ot_sender(coproto::LocalAsyncSocket& channel, std::vector<std::array<element, 2>> sendMsg);

    }


    namespace fm_paillier{
        std::vector<block> bignumer_to_block_vector(const BigNumber& bn);

        BigNumber block_vector_to_bignumer(const std::vector<block>& ct);

        // input prefixes should be an empty vector.
        void interval_to_prefix(const u32& a, const u32& b, std::vector<block>& prefixes);

        ///////////////////////////
        // protocol

        // setup: input vals should be an empty vector.
        void receiver_value_paillier_lp(const std::size_t& elements_size,
                                        std::vector<std::vector<block>>& vals,
                                        const u32& dimension, const i32& delta, const u32& p, const ipcl::KeyPair& paillier_key);

        // setup: input vals should be an empty vector.
        void receiver_value_paillier_linfty(const std::size_t& elements_size,
                                        std::vector<std::vector<block>>& vals,
                                        const u32& dimension, const i32& delta, const ipcl::KeyPair& paillier_key);

        // setup: input masks should be an empty vector.
        void sender_mask_paillier_lp(const std::size_t& elements_size,
                                    std::vector<u32>& masks, ipcl::CipherText& vec_mask_ct,
                                    const ipcl::PublicKey& pk);

        // input keys should be an empty vector.
        void receiver_w_to_key_paillier_lp(const std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>& vec_keyw,
                                                    std::vector<block>& keys,
                                                    const u32& dimension, const i32& delta);
        
        // input vec_masked_distance should be an empty vector.
        void sender_q_to_masked_distance_paillier_lp(const std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>& vec_kq, const std::vector<std::vector<block>>& codeWords, const ipcl::CipherText& vec_mask_ct,
                                                    ipcl::CipherText& vec_masked_distance,
                                                    const u32& dimension, const i32& okvs_n, const ipcl::PublicKey& pk);
        // // without setup: input masks and vec_masked_distance should be two empty vectors.
        // void sender_q_to_mask_distance_paillier_lp(const std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>& vec_kq, const std::vector<std::vector<block>>& codeWords,
        //                                             std::vector<u32>& masks, std::vector<std::vector<block>>& vec_masked_distance,
        //                                             const u32& dimension, const i32& okvs_n, const ipcl::PublicKey& pk);

        // input masked_distance should be an empty vector.
        void receiver_get_masked_distance_paillier_lp(const ipcl::CipherText& vec_masked_distance,
                                                    std::vector<u32>& masked_distance,
                                                    const ipcl::KeyPair& paillier_key);

        // input vec_prefixes should be an empty vector.
        u64 sender_get_prefixes(const std::vector<u32>& masks,
                                std::vector<std::vector<block>>& vec_prefixes,
                                const i32& delta, const u32& p);

        // input send_prefixes_k_net should be an empty vector.
        void pad_send_prefixes_k(const std::vector<std::vector<DH25519_point>>& send_prefixes_k, std::vector<DH25519_point>& send_prefixes_k_net, const u64& max_prefix_num);

        // todo: when iter - block(pow(delta, p)) or iter + block(pow(delta, p)) is not in [0, 2^32 - 1]
        // input vec_prefixes should be an empty vector.
        void receiver_get_prefixes(const std::vector<u32>& masked_distance,
                                    std::vector<std::vector<block>>& vec_prefixes,
                                    const i32& delta, const u32& p);

        // DH-PSICA//////////////////////////////
        // input vec_prefixes_k should be an empty vector.
        void prefixes_pow_sk(const std::vector<std::vector<block>>& vec_prefixes,
                            std::vector<std::vector<DH25519_point>>& vec_prefixes_k,
                            const DH25519_number& sk);

        // todo: sender shuffle
        // input vec_prefixes_kk should be an empty vector.
        void prefixes_repow_sk(const std::vector<std::vector<DH25519_point>>& vec_prefixes_k,
                                std::vector<std::vector<DH25519_point>>& vec_prefixes_kk,
                                const DH25519_number& sk);

        // input result should be an empty vector.
        void prefixes_check(const std::vector<std::vector<DH25519_point>>& send_prefixes_kk, const std::vector<std::vector<DH25519_point>>& recv_prefixes_kk,
                            std::vector<bool>& result);

        void fmat_paillier_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements, std::vector<Rist25519_point>* recv_vec_dhkk_seedsum,
        std::vector<std::vector<block>>* fmat_vals,
        u64 dimension, u64 delta, u64 p,
        ipcl::KeyPair paillier_key, DH25519_number recv_dh_k);

        void fmat_paillier_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements, std::vector<Rist25519_point>* send_vec_dhkk_seedsum,
        std::vector<DH25519_point>* send_prefixes_k, ipcl::CipherText* vec_mask_ct,
        u64 dimension, u64 delta, u64 p,
        ipcl::PublicKey paillier_pub_key, DH25519_number send_dh_k);

        void fmat_paillier_linfty_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements, std::vector<Rist25519_point>* recv_vec_dhkk_seedsum,
        std::vector<std::vector<block>>* fmat_vals,
        u64 dimension, u64 delta,
        ipcl::KeyPair paillier_key);

        void fmat_paillier_linfty_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements, std::vector<Rist25519_point>* send_vec_dhkk_seedsum,
        u64 dimension, u64 delta,
        ipcl::PublicKey paillier_pub_key);

    }

    namespace fm_ec{
        inline block get_key_from_k_d_x(const Rist25519_point& k, const u32& d, const u64& x);

        std::vector<block> ec_cipher_to_block_vector(const FM25519_point& G, const FM25519_point& sG_M);
        
        void block_vector_to_ec_cipher(const std::vector<block>& cipher_block, FM25519_point& G, FM25519_point& sG_M);

        ///////////////////////////
        // protocol

        // setup: input vals should be an empty vector.
        void receiver_value_ec_lp(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u32& dimension, const i32& delta, const u32& p, const FM25519_number& sk, const FM25519_point& G_fm);

        // setup: input vec_G_pow_a, vec_b, vec_G_pow_c, vec_H_pow_c, and vec_G_pow_a_bj should be empty vectors.
        void sender_mask_ec_lp(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a_H_pow_c,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_G_pow_c,
                            std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            const i32& delta, const u32& p,
                            const FM25519_point& G, const FM25519_point& H);

        void receiver_w_to_key_ec_lp(const std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>& vec_keyw,
                                    std::vector<block>& keys,
                                    const u32& dimension, const i32& delta);

        void sender_q_to_masked_distance_ec_lp(const std::vector<std::vector<u64>>& elements, const std::vector<Rist25519_point>& vec_kq,
                                                const std::vector<std::vector<Rist25519_point>>& codeWords,
                                                const std::vector<FM25519_point>& vec_G_pow_a_H_pow_c,
                                                const std::vector<FM25519_number>& vec_b,
                                                const std::vector<FM25519_point>& vec_G_pow_c,
                                                std::vector<FM25519_point>& vec_F_star, std::vector<FM25519_point>& vec_H_star,
                                                const u32& dimension, const i32& okvs_n);

        void receiver_result(const std::vector<FM25519_point>& vec_F_star, const std::vector<FM25519_point>& vec_H_star, const std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            std::vector<bool>& result,
                            const FM25519_number& sk);

        void receiver_value_ec_linfty(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u32& dimension, const i32& delta, const FM25519_number& sk);

        void sender_mask_ec_linfty(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H);                              
                
        void fmat_ec_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements, std::vector<FM25519_point>* recv_vec_dhkk_seedsum,
        std::vector<std::vector<Rist25519_number>>* fmat_vals,
        u64 dimension, u64 delta,
        Rist25519_number recv_sk);

        void fmat_ec_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements, std::vector<Rist25519_point>* send_vec_dhkk_seedsum,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        u64 dimension, u64 delta);

    }
}