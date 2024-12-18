#pragma once

#include "gm_crypto.h"
#include "fm.h"
#include <cryptoTools/Common/BitVector.h>
#include "coproto/Socket/LocalAsyncSock.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include <stack>

// const oc::u32 IND_LENGTH_BIT = 24;

namespace osuCrypto
{
    namespace Hamming{
        void receiver_precomp_value_hamming(const std::size_t& elements_size,
        std::stack<std::array<std::vector<block>, 2>>& pre_vals,
        const u32& dimension, const u32& delta, pubkey_t* gm_pubkey
        );

        void sender_precomp_mask_hamming(const std::size_t& elements_size,
        std::stack<BitVector>& masks, std::stack<std::vector<std::vector<block>>>& masks_ciphers_block,
        const u32& dimension, const u32& side_length, pubkey_t* gm_pubkey
        );

        void fpsi_hamming_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<BitVector>* receiver_elements, std::vector<std::vector<osuCrypto::u64>>* unique_components,
        std::stack<std::array<std::vector<block>, 2>>* pre_vals,
        u64 dimension, u64 delta, u32 side_length,
        pubkey_t* gm_pubkey, privkey_t* gm_prikey
        );


        void fpsi_hamming_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<BitVector>* sender_elements,
        std::stack<BitVector>* masks, std::stack<std::vector<std::vector<block>>>* masks_ciphers_block,
        u64 dimension, u64 delta, u32 side_length,
        pubkey_t* gm_pubkey
        );


    }


}

