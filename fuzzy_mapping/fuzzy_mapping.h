#pragma once

#include "rb_okvs.h"
#include <stack>
#include <stack>

#include "coproto/Socket/LocalAsyncSock.h"

#include <cryptoTools/Common/BitVector.h>
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"

using Socket = coproto::Socket;
using segment = std::array<oc::u64, 2>;


namespace osuCrypto
{
    namespace fmap{
///////////////////////////////////////////////////////////////////////
//offline
        void assign_segments(const std::size_t& elements_size,
        std::vector<std::vector<Rist25519_number>>& values, std::stack<Rist25519_number>& vals_candidate_r, std::stack<Rist25519_number>& vals_candidate_skr,
        const u32& dimension, const i32& delta, const i32& side_length, const Rist25519_number& sk);

        void get_mask_cipher(const std::size_t& elements_size,
        std::vector<Rist25519_number>& masks, std::vector<Rist25519_number>& masks_inv,
        const std::array<Rist25519_point, 2>& pk);
///////////////////////////////////////////////////////////////////////

        void elements_to_segments(const std::vector<std::vector<u64>>& elements,
        std::vector<std::vector<segment>>& segments_in_dimensions,
        const u32& dimension, const i32& delta, const i32& side_length);

        void get_own_seeds(const std::vector<std::vector<u64>>& elements, const std::vector<std::vector<segment>>& segments_in_dimensions, const std::vector<std::vector<Rist25519_number>>& values,
        std::vector<Rist25519_point>& seeds,
        const u32& dimension, const i32& side_length);

        void get_key_value_pair(const std::vector<std::vector<segment>>& segments_in_dimensions, const std::vector<std::vector<Rist25519_number>>& values,
        std::stack<Rist25519_number>& vals_candidate_r, std::stack<Rist25519_number>& vals_candidate_skr,
        std::vector<block>& keys, std::vector<std::vector<Rist25519_number>>& vals,
        const u32& dimension);
        
        void get_vec_enc_mask_seedsum(const std::vector<std::vector<u64>>& elements, const std::vector<std::vector<Rist25519_point>>& codeWords,
        const std::vector<Rist25519_number>& masks, const std::vector<Rist25519_point>& own_seeds,
        // std::stack<Rist25519_point>& vals_candidate_r, std::stack<Rist25519_point>& vals_candidate_skr,
        std::vector<Rist25519_point>& vec_enc_mask_seedsum,
        const u32& dimension, const i32& side_length, const i32& okvs_n, const std::array<Rist25519_point, 2>& pk);

        void get_dhk_mask_seedsum(const std::vector<Rist25519_point>& vec_enc_mask_seedsum,
        std::vector<Rist25519_point>& dhk_mask_seedsum,
        const Rist25519_number& sk, const Rist25519_number& dh_sk);

        void get_dhkk_seedsum(const std::vector<Rist25519_point>& dhk_mask_seedsum, const std::vector<Rist25519_number>& masks_inv,
        std::vector<Rist25519_point>& vec_dhkk_seedsum,
        const Rist25519_number& dh_sk);

///////////////////////////////////////////////////////////////////////
//run
        void fmap_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements,
        std::vector<std::vector<Rist25519_number>>* recv_values,
        std::stack<Rist25519_number>* recv_vals_candidate_r, std::stack<Rist25519_number>* recv_vals_candidate_skr,
        std::vector<Rist25519_number>* recv_masks, std::vector<Rist25519_number>* recv_masks_inv,
        std::vector<Rist25519_point>* recv_vec_dhkk_seedsum, 
        u32 dimension, i32 delta, i32 side_length,
        Rist25519_number recv_sk, std::array<Rist25519_point, 2> recv_pk, Rist25519_number recv_dh_sk);

        void fmap_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<std::vector<Rist25519_number>>* send_values,
        std::stack<Rist25519_number>* send_vals_candidate_r, std::stack<Rist25519_number>* send_vals_candidate_skr,
        std::vector<Rist25519_number>* send_masks, std::vector<Rist25519_number>* send_masks_inv,
        std::vector<Rist25519_point>* send_vec_dhkk_seedsum, 
        u32 dimension, i32 delta, i32 side_length,
        Rist25519_number send_sk, std::array<Rist25519_point, 2> send_pk, Rist25519_number send_dh_sk);



    }


}

