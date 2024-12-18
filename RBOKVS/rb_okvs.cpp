// #include "cryptoTools/Common/CLP.h"

#include "rb_okvs.h"

#define XOR(a, b) for(u64 xor_cnt = 0; xor_cnt < VALUE_LENGTH_IN_BLOCK; xor_cnt++){(* ((a) + xor_cnt)) ^= (*((b) + xor_cnt));}

namespace osuCrypto{

    inline void blocks_XOR(block *a, const block *b, const u64 VALUE_LENGTH_IN_BLOCK){
        for(u64 i = 0; i < VALUE_LENGTH_IN_BLOCK; i++){
            a[i] ^= b[i];
        }
        return;
    }

    RBOKVSParam RBOKVS::getParams(const u64 &n, const double &epsilon, const u64 &stasSecParam, const block &seed){
        RBOKVSParam param;
        param.mNumRows = n;
        param.mScaler = 1 + epsilon;
        param.mStasSecParam = stasSecParam;

        // generate randomness of hash function
        PRNG prng(seed);
        param.mR1 = prng.get<block>();
        param.mR2 = prng.get<block>();
        param.mSeed = prng.get<block>();

        u64 nn = log2ceil(n);
        // compute width of band
        if (std::abs(epsilon - 0.03) <1e-5){
            // epsilon = 0.03
            // n = 2^10, \lambda = 0.08047w - 3.464
            // n = 2^14, \lambda = 0.08253w - 5.751
            // n = 2^16, \lambda = 0.08241w - 7.023
            // n = 2^18, \lambda = 0.08192w - 8.569
            // n = 2^20, \lambda = 0.08313w - 10.880
            // n = 2^24, \lambda = 0.08253w - 14.671
            if (nn <= 10){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 3.464) / 0.08047), param.numCols());
            } else if (nn <= 14){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 5.751) / 0.08253), param.numCols());
            } else if (nn <= 16){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 7.023) / 0.08241), param.numCols());
            } else if (nn <= 18){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 8.569) / 0.08192), param.numCols());
            } else if (nn <= 20){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 10.880) / 0.08313), param.numCols());
            } else if (nn <= 24){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 14.671) / 0.08253), param.numCols());
            } else {
                std::cout << "no proper parameter for this n, use parameters for n = 2^24" << std::endl;
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 14.671) / 0.08253), param.numCols());
            }
        } else if (std::abs(epsilon - 0.05) < 1e-5){
            // epsilon = 0.05
            // n = 2^10, \lambda = 0.1388w - 4.424
            // n = 2^14, \lambda = 0.1389w - 6.976
            // n = 2^16, \lambda = 0.1399w - 8.942
            // n = 2^18, \lambda = 0.1388w - 10.710
            // n = 2^20, \lambda = 0.1407w - 12.920
            // n = 2^24, \lambda = 0.1376w - 16.741
            if (nn <= 10){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 4.424) / 0.1388), param.numCols());
            } else if (nn <= 14){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 6.976) / 0.1389), param.numCols());
            } else if (nn <= 16){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 8.942) / 0.1399), param.numCols());
            } else if (nn <= 18){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 10.710) / 0.1388), param.numCols());
            } else if (nn <= 20){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 12.920) / 0.1407), param.numCols());
            } else if (nn <= 24){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 16.741) / 0.1376), param.numCols());
            } else {
                std::cout << "no proper parameter for this n, use n = 2^24" << std::endl;
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 16.741) / 0.1376), param.numCols());
            }
        } else if (std::abs(epsilon - 0.07) < 1e-5){
            // epsilon = 0.07
            // n = 2^10, \lambda = 0.1947w - 5.383
            // n = 2^14, \lambda = 0.1926w - 8.150
            // n = 2^16, \lambda = 0.1961w - 10.430
            // n = 2^18, \lambda = 0.1955w - 12.300
            // n = 2^20, \lambda = 0.1939w - 14.100
            if (nn <= 10){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 5.383) / 0.1947), param.numCols());
            } else if (nn <= 14){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 8.150) / 0.1926), param.numCols());
            } else if (nn <= 16){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 10.430) / 0.1961), param.numCols());
            } else if (nn <= 18){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 12.300) / 0.1955), param.numCols());
            } else if (nn <= 20){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 14.100) / 0.1939), param.numCols());
            } else {
                std::cout << "no proper parameter for this n, use n = 2^20" << std::endl;
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 14.100) / 0.1939), param.numCols());
            }
        } else if (std::abs(epsilon - 0.1) < 1e-5){
            // epsilon = 0.1
            // n = 2^10, \lambda = 0.2747w - 6.296
            // n = 2^14, \lambda = 0.2685w - 9.339
            // n = 2^16, \lambda = 0.2740w - 11.610
            // n = 2^18, \lambda = 0.2715w - 13.390
            // n = 2^20, \lambda = 0.2691w - 15.210
            // n = 2^24, \lambda = 0.2751w - 19.830
            if (nn <= 10){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 6.296) / 0.2747), param.numCols());
            } else if (nn <= 14){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 9.339) / 0.2685), param.numCols());
            } else if (nn <= 16){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 11.610) / 0.2740), param.numCols());
            } else if (nn <= 18){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 13.390) / 0.2715), param.numCols());
            } else if (nn <= 20){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 15.210) / 0.2691), param.numCols());
            } else if (nn <= 24){
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 19.830) / 0.2751), param.numCols());
            } else {
                std::cout << "no proper parameter for this n, use n = 2^24" << std::endl;
                param.mBandWidth = std::min<u64>(static_cast<u64>((stasSecParam + 19.830) / 0.2751), param.numCols());
            }
        } else {
            throw std::runtime_error("no proper parameter for this epsilon");
        }
        return param;
    }

    void RBOKVS::init(const u64 &n, const double &epsilon, const u64 &stasSecParam, const block &seed){
        init(getParams(n, epsilon, stasSecParam, seed));
    }

    void RBOKVS::init(const RBOKVSParam &param){
        mN = param.mNumRows;
        mSize = param.numCols();
        mW = param.mBandWidth;
        mSsp = param.mStasSecParam;
        mRPos = param.mR1;
        mRBand = param.mR2;
        mPrng.SetSeed(param.mSeed);
        mTimer.reset();
    }

    void RBOKVS::setSeed(const block &seed){
        PRNG prng(seed);
        mRPos = prng.get<block>();
        mRBand = prng.get<block>();
        mPrng.SetSeed(prng.get<block>());
    }

    u64 RBOKVS::hashPos(const block &input){
        if (mSize == mW){
            return 0;
        }
        u8 hashOut[8];
        u64 out = 0;

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &mRPos, sizeof(mRPos));
        blake3_hasher_update(&hasher, &input, sizeof(input));
        blake3_hasher_finalize(&hasher, hashOut, 8);

        // todo: memory copy
        for (u64 i = 0; i < 8; ++i){
            out ^= (static_cast<u64>(hashOut[i]) << (56 - i * 8));
        }
        return out % (mSize - mW);
    }

    void RBOKVS::hashBand(const block &input, block *output){
        // number of blocks to store the band multiplied by 16 (number of bytes in a block)
        u64 wBlockBytes = divCeil(mW, 128) * 16;
        u64 wBytes = divCeil(mW, 8);
        u8 hashOut[wBlockBytes];

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &mRBand, sizeof(mRBand));
        blake3_hasher_update(&hasher, &input, sizeof(input));
        blake3_hasher_finalize(&hasher, hashOut, wBytes);

        if(mW % 8){
            hashOut[wBytes - 1] &= ~(0xFF >>(mW % 8));
        }

        // hashOut[wBytes - 1] &= ~(0xFF >> (8 - mW % 8));

        // padding zero to the end of the last block
        memset(hashOut + wBytes, 0, wBlockBytes - wBytes);

        for (u64 i = 0; i < wBlockBytes / 16; ++i){
            output[i].data()[7] = hashOut[i * 16];
            output[i].data()[6] = hashOut[i * 16 + 1];
            output[i].data()[5] = hashOut[i * 16 + 2];
            output[i].data()[4] = hashOut[i * 16 + 3];
            output[i].data()[3] = hashOut[i * 16 + 4];
            output[i].data()[2] = hashOut[i * 16 + 5];
            output[i].data()[1] = hashOut[i * 16 + 6];
            output[i].data()[0] = hashOut[i * 16 + 7];

            output[i].data()[15] = hashOut[i * 16 + 8];
            output[i].data()[14] = hashOut[i * 16 + 9];
            output[i].data()[13] = hashOut[i * 16 + 10];
            output[i].data()[12] = hashOut[i * 16 + 11];
            output[i].data()[11] = hashOut[i * 16 + 12];
            output[i].data()[10] = hashOut[i * 16 + 13];
            output[i].data()[9] = hashOut[i * 16 + 14];
            output[i].data()[8] = hashOut[i * 16 + 15];
        }
    }

    EncodeStatus RBOKVS::reformalize(MatrixRow &row){
        u64 wBlocks = divCeil(mW, 128);
        u64 numZeroBlocks = wBlocks;
        // find the first non-zero block
        for (u64 i = 0 ; i < wBlocks; ++i){
            if (row.data[i] != ZeroBlock){
                numZeroBlocks = i;
                break;
            }
        }

        if (numZeroBlocks == wBlocks){
            // all zero row
            if (row.val == ZeroBlock){
                // use a special value to indicate a meaningless row
                row.startPos = -1;
                return EncodeStatus::ALLZERO;
            } else {
                return EncodeStatus::FAIL;
            }
        }

        // shift the first non-zero block to the firset block and pad zeros
        u64 leftShift = static_cast<u64>(row.data[numZeroBlocks].mData[0] == 0) + 2 * numZeroBlocks;
        u64 *ptr = reinterpret_cast<u64*>(row.data.get());
        if (leftShift != 0){
            memmove(ptr, ptr + leftShift, sizeof(u64) * (2 * wBlocks - leftShift));
            memset(ptr + 2 * wBlocks - leftShift, 0, sizeof(u64) * leftShift);
            row.startPos += leftShift * 64;
        }

        // shift the first 1 to the first bit
        int numLeadingZeros = __builtin_clzll(ptr[0]);
        // no extra space
        // todo: maybe handle all block at one time but use more space
        if (numLeadingZeros != 0){
            for (u64 i = 0; i < 2 * wBlocks - leftShift - 1; i++){
                ptr[i] = (ptr[i] << numLeadingZeros) | (ptr[i + 1] >> (64 - numLeadingZeros));
            }
            ptr[2 * wBlocks - leftShift - 1] <<= numLeadingZeros;

            row.startPos += numLeadingZeros;
        }

        return EncodeStatus::SUCCESS;
    }

    EncodeStatus RBOKVS::reformalize(MatrixRow_LongValue &row, const u64 VALUE_LENGTH_IN_BLOCK){
        u64 wBlocks = divCeil(mW, 128);
        u64 numZeroBlocks = wBlocks;
        // find the first non-zero block
        for (u64 i = 0 ; i < wBlocks; ++i){
            if (row.data[i] != ZeroBlock){
                numZeroBlocks = i;
                break;
            }
        }

        if (numZeroBlocks == wBlocks){
            // all zero row
            bool flag = 0;
            for(u64 i = 0; i < VALUE_LENGTH_IN_BLOCK; i++){
                if (row.val[i] != ZeroBlock){
                    flag = 1;
                }
            }

            if (flag == 0){
                // use a special value to indicate a meaningless row
                row.startPos = -1;
                return EncodeStatus::ALLZERO;
            } else {
                    printf("EncodeStatus::FAIL");
                    printf("\n");
                    printf("flag == 0");
                    printf("\n");
                return EncodeStatus::FAIL;
            }
        }

        // shift the first non-zero block to the firset block and pad zeros
        u64 leftShift = static_cast<u64>(row.data[numZeroBlocks].mData[0] == 0) + 2 * numZeroBlocks;
        u64 *ptr = reinterpret_cast<u64*>(row.data.get());
        if (leftShift != 0){
            memmove(ptr, ptr + leftShift, sizeof(u64) * (2 * wBlocks - leftShift));
            memset(ptr + 2 * wBlocks - leftShift, 0, sizeof(u64) * leftShift);
            row.startPos += leftShift * 64;
        }

        // shift the first 1 to the first bit
        int numLeadingZeros = __builtin_clzll(ptr[0]);
        // no extra space
        // todo: maybe handle all block at one time but use more space
        if (numLeadingZeros != 0){
            for (u64 i = 0; i < 2 * wBlocks - leftShift - 1; i++){
                ptr[i] = (ptr[i] << numLeadingZeros) | (ptr[i + 1] >> (64 - numLeadingZeros));
            }
            ptr[2 * wBlocks - leftShift - 1] <<= numLeadingZeros;

            row.startPos += numLeadingZeros;
        }

        return EncodeStatus::SUCCESS;
    }

    EncodeStatus RBOKVS::insert(u64 *bitToRowMap, MatrixRow *rows, u64 rowIdx){
        
        //printf("31\n");
        EncodeStatus status = reformalize(rows[rowIdx]);
        if (status == EncodeStatus::FAIL || status == EncodeStatus::ALLZERO){
            return status;
        }

        //printf("32\n");
        u64 wBlocks = divCeil(mW, 128);
        u64 collidingRowIdx = bitToRowMap[rows[rowIdx].startPos];
        while (collidingRowIdx != mN){
            //printf("while round start\n");
            
            //printf("%d wBlocks\n", wBlocks);
            // band XOR
            for (u64 i = 0; i < wBlocks; i++){
                //printf("%d th band xor start\n", i);
                //print_element(rows[rowIdx].data[i]);
                rows[rowIdx].data[i] ^= rows[collidingRowIdx].data[i];
                //printf("%d thband xor done\n", i);
            }
            
            //printf("band xor done\n");
            // value XOR
            rows[rowIdx].val ^= rows[collidingRowIdx].val;
            //printf("value xor done\n");
            // reformalize row
            status = reformalize(rows[rowIdx]);
            //printf("reform done\n");
            if (status == EncodeStatus::FAIL || status == EncodeStatus::ALLZERO){
                return status;
            }
            collidingRowIdx = bitToRowMap[rows[rowIdx].startPos];
            
            //printf("while round done\n");
        }

        //printf("33\n");
        // When previous process is finished, that means this row find an empty index.
        // (this place hasn't been inserted)
        // then directly insert this row
        bitToRowMap[rows[rowIdx].startPos] = rowIdx;
        return EncodeStatus::SUCCESS;
    }

    EncodeStatus RBOKVS::insert(u64 *bitToRowMap, MatrixRow_LongValue *rows, u64 rowIdx, const u64 VALUE_LENGTH_IN_BLOCK){
        EncodeStatus status = reformalize(rows[rowIdx], VALUE_LENGTH_IN_BLOCK);
        if (status == EncodeStatus::FAIL || status == EncodeStatus::ALLZERO){
            return status;
        }

        u64 wBlocks = divCeil(mW, 128);
        u64 collidingRowIdx = bitToRowMap[rows[rowIdx].startPos];
        while (collidingRowIdx != mN){
            // band XOR
            for (u64 i = 0; i < wBlocks; ++i){
                rows[rowIdx].data[i] ^= rows[collidingRowIdx].data[i];
            }
            // value XOR
            for(u64 i = 0; i < VALUE_LENGTH_IN_BLOCK; i++){
                rows[rowIdx].val[i] ^= rows[collidingRowIdx].val[i];
            }
            // reformalize row
            status = reformalize(rows[rowIdx], VALUE_LENGTH_IN_BLOCK);
            if (status == EncodeStatus::FAIL || status == EncodeStatus::ALLZERO){
                return status;
            }
            collidingRowIdx = bitToRowMap[rows[rowIdx].startPos];
        }

        // When previous process is finished, that means this row find an empty index.
        // (this place hasn't been inserted)
        // then directly insert this row
        bitToRowMap[rows[rowIdx].startPos] = rowIdx;
        return EncodeStatus::SUCCESS;
    }


    EncodeStatus RBOKVS::encode(const block *keys, const block *vals, block *output){
        mTimer.setTimePoint("encode start");

        //printf("1\n");
        //printf("encode start\n");

        std::unique_ptr<u64[]> bitToRowMap(new u64[mSize]);
        std::unique_ptr<MatrixRow[]> rows(new MatrixRow[mN]);
        u64 wBlocks = divCeil(mW, 128);

        // initialize
        for (u64 i = 0; i < mSize; ++i){
            bitToRowMap[i] = mN;
        }
        memset(output, 0, sizeof(block) * mSize);

        mTimer.setTimePoint("alloc and init");

        //printf("set 0\n");

        // initialize rows
        // todo: maybe parallelize this
        for (u64 i = 0; i < mN; ++i){
            rows[i].startPos = hashPos(keys[i]);
            rows[i].data.reset(new block[wBlocks]);
            hashBand(keys[i], rows[i].data.get());
            rows[i].val = vals[i];

            // printf("%dth row: ", i);
            // print_row_of_matrix(rows[i], wBlocks);
        }
        // for(u64 i = 0; i < 5; ++i){
        //     printf("%dth row: ", i);
        //     print_row_of_matrix(rows[i], wBlocks);
        // }
        // printf("\n");

        mTimer.setTimePoint("alloc and hash");

        //printf("3\n");

        EncodeStatus status;
        for (u64 i = 0; i < mN; ++i){
            status = insert(bitToRowMap.get(), rows.get(), i);
            if (status == EncodeStatus::FAIL){
                return status;
            }
            
            // printf("%dth row: ", i);
            // print_row_of_matrix(rows[i], wBlocks);
        }

        // for(u64 i = 0; i < 5; ++i){
        //     printf("%dth row: ", i);
        //     print_row_of_matrix(rows[i], wBlocks);
        // }
        // printf("\n");
        //printf("alloc and hash\n");

        mTimer.setTimePoint("elimination");

        //printf("4\n");

        // solve the linear system
        u64 *ptr, tmp, j;
        for (i64 i = mSize - 1; i >= 0; --i){
            if (bitToRowMap[i] != mN){
                ptr = reinterpret_cast<u64*>(rows[bitToRowMap[i]].data.get());
                output[i] = rows[bitToRowMap[i]].val;
                // first way to solve the linear system
                // for (u64 j = i + 1; j < i + mW && j < mSize; ++j){
                //     if ((ptr[(j - i) / 64] >> (63 - (j - i) % 64)) & 1){
                //         output[i] ^= output[j];
                //     }
                // }
                ptr[0] &= 0x7FFFFFFFFFFFFFFF;
                j = i;
                // expand the loop, handling 64 bits at one time
                // except the last u64(maybe less than 64 bits)
                for ( ; j < i + mW - 64 && j < mSize - 64; j+=64){
                    tmp = ptr[(j - i) / 64];
                               output[i] ^= (tmp & 1) ? output[j + 63] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 62] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 61] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 60] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 59] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 58] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 57] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 56] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 55] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 54] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 53] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 52] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 51] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 50] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 49] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 48] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 47] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 46] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 45] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 44] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 43] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 42] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 41] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 40] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 39] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 38] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 37] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 36] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 35] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 34] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 33] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 32] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 31] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 30] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 29] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 28] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 27] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 26] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 25] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 24] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 23] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 22] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 21] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 20] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 19] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 18] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 17] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 16] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 15] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 14] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 13] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 12] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 11] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 10] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 9] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 8] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 7] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 6] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 5] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 4] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 3] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 2] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j + 1] : ZeroBlock;
                    tmp >>= 1; output[i] ^= (tmp & 1) ? output[j] : ZeroBlock;
                }
                for ( ; j < i + mW && j < mSize; ++j){
                    if((ptr[(j - i) / 64] >> (63 - (j - i) % 64)) & 1){
                        output[i] ^= output[j];
                    }
                }
            } else{
                output[i] = mPrng.get<block>();
            }
            
            // if((i % 10000) == 0){

            // printf("do %d th\n", i);
            // }
        }

        mTimer.setTimePoint("back substitution");

        return EncodeStatus::SUCCESS;
    }

    EncodeStatus RBOKVS::encode(const std::vector<block>& keys, const std::vector<std::vector<block>>& vals, const u64& VALUE_LENGTH_IN_BLOCK, std::vector<std::vector<block>>& output){
        mTimer.setTimePoint("encode start");

        std::unique_ptr<u64[]> bitToRowMap(new u64[mSize]);
        std::unique_ptr<MatrixRow_LongValue[]> rows(new MatrixRow_LongValue[mN]);
        u64 wBlocks = divCeil(mW, 128);


        // initialize
        for (u64 i = 0; i < mSize; ++i){
            bitToRowMap[i] = mN;
        }

        for (u64 i = 0; i < mSize; ++i){
            for(u64 j = 0; j < VALUE_LENGTH_IN_BLOCK; j++){
                output[i][j] = ZeroBlock;
            }
        }

        //mTimer.setTimePoint("alloc and init");

        // initialize rows
        // todo: maybe parallelize this
        for (u64 i = 0; i < mN; ++i){
            rows[i].startPos = hashPos(keys[i]);
            rows[i].data.reset(new block[wBlocks]);
            hashBand(keys[i], rows[i].data.get());
            // memcpy(rows[i].val.data(), vals[i].data(), sizeof(block) * VALUE_LENGTH_IN_BLOCK);
            rows[i].val.assign(vals[i].begin(), vals[i].end());
        }

        // for(u64 i = 0; i < 5; ++i){
        //     printf("%dth row: ", i);
        //     print_row_of_matrix_long_value(rows[i], wBlocks);
        // }
        // printf("\n");


        //mTimer.setTimePoint("alloc and hash");
        EncodeStatus status;
        for (u64 i = 0; i < mN; ++i){
            status = insert(bitToRowMap.get(), rows.get(), i, VALUE_LENGTH_IN_BLOCK);
            if (status == EncodeStatus::FAIL){
                return status;
            }
        }


        // for(u64 i = 0; i < 5; ++i){
        //     printf("%dth row: ", i);
        //     print_row_of_matrix_long_value(rows[i], wBlocks);
        // }
        // printf("\n");

        //mTimer.setTimePoint("elimination");

        ////////////////////////////////////////////////////////////////
        // need to check
        block ZeroBlocks[VALUE_LENGTH_IN_BLOCK];
        for(auto i = 0; i < VALUE_LENGTH_IN_BLOCK; i++){
            ZeroBlocks[i] = ZeroBlock;
        }

        // solve the linear system
        u64 *ptr, tmp, j;
        for (i64 i = mSize - 1; i >= 0; --i){
            if (bitToRowMap[i] != mN){
                ptr = reinterpret_cast<u64*>(rows[bitToRowMap[i]].data.get());
                // memcpy(output[i], rows[bitToRowMap[i]].val.data(), sizeof(block) * VALUE_LENGTH_IN_BLOCK);
                for(auto cnt = 0; cnt < VALUE_LENGTH_IN_BLOCK; cnt++){
                    output[i][cnt] = rows[bitToRowMap[i]].val[cnt];
                }
                // first way to solve the linear system
                // for (u64 j = i + 1; j < i + mW && j < mSize; ++j){
                //     if ((ptr[(j - i) / 64] >> (63 - (j - i) % 64)) & 1){
                //         output[i] ^= output[j];
                //     }
                // }
                ptr[0] &= 0x7FFFFFFFFFFFFFFF;
                j = i;
                // expand the loop, handling 64 bits at one time
                // except the last u64(maybe less than 64 bits)
                for ( ; j < i + mW - 64 && j < mSize - 64; j+=64){
                    tmp = ptr[(j - i) / 64];
                               // output[i] ^= (tmp & 1) ? output[j + 63] : ZeroBlock;
                               //XOR((output[i]), ((tmp & 1) ? output[j + 63] : ZeroBlocks.data()))
                               blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 63].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 62].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 61].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 60].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 59].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 58].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 57].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 56].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 55].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 54].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 53].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 52].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 51].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 50].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 49].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 48].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 47].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 46].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 45].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 44].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 43].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 42].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 41].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 40].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 39].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 38].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 37].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 36].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 35].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 34].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 33].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 32].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 31].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 30].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 29].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 28].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 27].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 26].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 25].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 24].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 23].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 22].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 21].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 20].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 19].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 18].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 17].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 16].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 15].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 14].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 13].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 12].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 11].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 10].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 9].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 8].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 7].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 6].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 5].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 4].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 3].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 2].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j + 1].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                    tmp >>= 1; blocks_XOR(output[i].data(), (tmp & 1) ? output[j].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
                }
                for ( ; j < i + mW && j < mSize; ++j){
                    if((ptr[(j - i) / 64] >> (63 - (j - i) % 64)) & 1){
                        blocks_XOR(output[i].data(), output[j].data(), VALUE_LENGTH_IN_BLOCK);
                    }
                }

            } else{
                //output[i] = mPrng.get<block>();
                block temp_block;
                for(u64 cnt = 0; cnt < VALUE_LENGTH_IN_BLOCK; cnt++){
                    output[i][cnt] = mPrng.get<block>();
                }
            }
        }

        //mTimer.setTimePoint("back substitution");

        //printf("encode done\n");
        return EncodeStatus::SUCCESS;
    }

    block RBOKVS::decode(const block *codeWords, const block &key){
        u64 startPos = hashPos(key);
        block data[divCeil(mW, 128)], res = ZeroBlock;
        hashBand(key, data);

        u64 *ptr = reinterpret_cast<u64*>(data);
        u64 tmp, j;
        for (j = 0 ; j < mW - 64; j+=64){
            tmp = ptr[j / 64];
                       res ^= (tmp & 1) ? codeWords[startPos+ j + 63] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 62] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 61] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 60] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 59] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 58] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 57] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 56] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 55] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 54] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 53] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 52] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 51] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 50] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 49] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 48] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 47] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 46] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 45] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 44] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 43] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 42] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 41] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 40] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 39] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 38] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 37] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 36] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 35] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 34] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 33] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 32] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 31] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 30] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 29] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 28] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 27] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 26] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 25] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 24] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 23] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 22] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 21] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 20] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 19] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 18] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 17] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 16] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 15] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 14] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 13] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 12] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 11] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 10] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 9] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 8] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 7] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 6] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 5] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 4] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 3] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 2] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j + 1] : ZeroBlock;
            tmp >>= 1; res ^= (tmp & 1) ? codeWords[startPos+ j] : ZeroBlock;
        }
        for ( ; j < mW; ++j){
            if((ptr[j / 64] >> (63 - j % 64)) & 1){
                res ^= codeWords[startPos + j];
            }
        }
        // don't expand the loop
        // for (u64 i = 0; i < mW; ++i){
        //     if ((ptr[i / 64] >> (63 - i % 64)) & 1){
        //         res ^= codeWords[startPos + i];
        //     }
        // }
        return res;
    }

    std::vector<block> RBOKVS::decode(const std::vector<std::vector<block>>& codeWords, const block &key, const u64& VALUE_LENGTH_IN_BLOCK){
        u64 startPos = hashPos(key);
        block data[divCeil(mW, 128)];
        
        std::vector<block> res(VALUE_LENGTH_IN_BLOCK, ZeroBlock);
        block ZeroBlocks[VALUE_LENGTH_IN_BLOCK];
        for(auto i = 0; i < VALUE_LENGTH_IN_BLOCK; i++){
            ZeroBlocks[i] = ZeroBlock;
        }

        hashBand(key, data);

        u64 *ptr = reinterpret_cast<u64*>(data);
        u64 tmp, j;
        for (j = 0 ; j < mW - 64; j+=64){
            tmp = ptr[j / 64];
                       // res ^= (tmp & 1) ? codeWords[startPos+ j + 63] : ZeroBlock;
                       blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 63].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 62].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 61].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 60].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 59].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 58].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 57].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 56].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 55].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 54].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 53].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 52].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 51].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 50].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 49].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 48].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 47].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 46].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 45].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 44].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 43].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 42].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 41].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 40].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 39].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 38].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 37].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 36].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 35].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 34].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 33].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 32].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 31].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 30].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 29].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 28].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 27].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 26].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 25].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 24].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 23].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 22].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 21].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 20].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 19].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 18].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 17].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 16].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 15].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 14].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 13].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 12].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 11].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 10].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 9].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 8].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 7].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 6].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 5].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 4].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 3].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 2].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j + 1].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
            tmp >>= 1; blocks_XOR(res.data(), (tmp & 1) ? codeWords[startPos+ j].data() : ZeroBlocks, VALUE_LENGTH_IN_BLOCK);
        }
        for ( ; j < mW; ++j){
            if((ptr[j / 64] >> (63 - j % 64)) & 1){
                // res ^= codeWords[startPos + j];
                blocks_XOR(res.data(), codeWords[startPos + j].data(), VALUE_LENGTH_IN_BLOCK);
            }
        }
        // don't expand the loop
        // for (u64 i = 0; i < mW; ++i){
        //     if ((ptr[i / 64] >> (63 - i % 64)) & 1){
        //         res ^= codeWords[startPos + i];
        //     }
        // }
        return res;
    }

    void RBOKVS::decode(const block *codeWords, const block *keys, u64 size, block *output, u64 numThreads){
        numThreads = std::max<u64>(1u, numThreads);
        u64 batchSize = size / numThreads;
        std::thread decodeThrds[numThreads];
        for (u64 i = 0; i < numThreads; ++i){
            decodeThrds[i] = std::thread([&, i](){
                const u64 start = i * batchSize;
                const u64 end = (i == numThreads - 1) ? size : start + batchSize;
                for (u64 j = start; j < end; ++j){
                    output[j] = decode(codeWords, keys[j]);
                }
            });
        }
        for (auto &thrd : decodeThrds) thrd.join();
    }

    void RBOKVS_rist::init(const u64 &n, const double &epsilon, const u64 &stasSecParam, const block &seed){
        num_element = n;
        double scaler = 1 + epsilon;
        num_columns = scaler * num_element;
        // todo: how to check band
        // width_band = 100;
        lambda = stasSecParam;
        okvs_prng = PRNG(seed);
        rand_band = okvs_prng.get<block>();
        rand_position = okvs_prng.get<block>();

        u64 nn = log2ceil(n);
        // compute width of band
        if (std::abs(epsilon - 0.03) <1e-5){
            // epsilon = 0.03
            // n = 2^10, \lambda = 0.08047w - 3.464
            // n = 2^14, \lambda = 0.08253w - 5.751
            // n = 2^16, \lambda = 0.08241w - 7.023
            // n = 2^18, \lambda = 0.08192w - 8.569
            // n = 2^20, \lambda = 0.08313w - 10.880
            // n = 2^24, \lambda = 0.08253w - 14.671
            if (nn <= 10){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 3.464) / 0.08047), num_columns);
            } else if (nn <= 14){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 5.751) / 0.08253), num_columns);
            } else if (nn <= 16){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 7.023) / 0.08241), num_columns);
            } else if (nn <= 18){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 8.569) / 0.08192), num_columns);
            } else if (nn <= 20){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 10.880) / 0.08313), num_columns);
            } else if (nn <= 24){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 14.671) / 0.08253), num_columns);
            } else {
                std::cout << "no proper parameter for this n, use parameters for n = 2^24" << std::endl;
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 14.671) / 0.08253), num_columns);
            }
        } else if (std::abs(epsilon - 0.05) < 1e-5){
            // epsilon = 0.05
            // n = 2^10, \lambda = 0.1388w - 4.424
            // n = 2^14, \lambda = 0.1389w - 6.976
            // n = 2^16, \lambda = 0.1399w - 8.942
            // n = 2^18, \lambda = 0.1388w - 10.710
            // n = 2^20, \lambda = 0.1407w - 12.920
            // n = 2^24, \lambda = 0.1376w - 16.741
            if (nn <= 10){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 4.424) / 0.1388), num_columns);
            } else if (nn <= 14){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 6.976) / 0.1389), num_columns);
            } else if (nn <= 16){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 8.942) / 0.1399), num_columns);
            } else if (nn <= 18){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 10.710) / 0.1388), num_columns);
            } else if (nn <= 20){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 12.920) / 0.1407), num_columns);
            } else if (nn <= 24){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 16.741) / 0.1376), num_columns);
            } else {
                std::cout << "no proper parameter for this n, use n = 2^24" << std::endl;
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 16.741) / 0.1376), num_columns);
            }
        } else if (std::abs(epsilon - 0.07) < 1e-5){
            // epsilon = 0.07
            // n = 2^10, \lambda = 0.1947w - 5.383
            // n = 2^14, \lambda = 0.1926w - 8.150
            // n = 2^16, \lambda = 0.1961w - 10.430
            // n = 2^18, \lambda = 0.1955w - 12.300
            // n = 2^20, \lambda = 0.1939w - 14.100
            if (nn <= 10){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 5.383) / 0.1947), num_columns);
            } else if (nn <= 14){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 8.150) / 0.1926), num_columns);
            } else if (nn <= 16){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 10.430) / 0.1961), num_columns);
            } else if (nn <= 18){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 12.300) / 0.1955), num_columns);
            } else if (nn <= 20){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 14.100) / 0.1939), num_columns);
            } else {
                std::cout << "no proper parameter for this n, use n = 2^20" << std::endl;
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 14.100) / 0.1939), num_columns);
            }
        } else if (std::abs(epsilon - 0.1) < 1e-5){
            // epsilon = 0.1
            // n = 2^10, \lambda = 0.2747w - 6.296
            // n = 2^14, \lambda = 0.2685w - 9.339
            // n = 2^16, \lambda = 0.2740w - 11.610
            // n = 2^18, \lambda = 0.2715w - 13.390
            // n = 2^20, \lambda = 0.2691w - 15.210
            // n = 2^24, \lambda = 0.2751w - 19.830
            if (nn <= 10){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 6.296) / 0.2747), num_columns);
            } else if (nn <= 14){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 9.339) / 0.2685), num_columns);
            } else if (nn <= 16){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 11.610) / 0.2740), num_columns);
            } else if (nn <= 18){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 13.390) / 0.2715), num_columns);
            } else if (nn <= 20){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 15.210) / 0.2691), num_columns);
            } else if (nn <= 24){
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 19.830) / 0.2751), num_columns);
            } else {
                std::cout << "no proper parameter for this n, use n = 2^24" << std::endl;
                width_band = std::min<u64>(static_cast<u64>((stasSecParam + 19.830) / 0.2751), num_columns);
            }
        } else {
            throw std::runtime_error("no proper parameter for this epsilon");
        }

        width_band = width_band / 4;
        //width_band = 40;


        //printf("rbokvs rist width = %d\n", width_band);

        return;
    }
    
    u64 RBOKVS_rist::hash_to_position(const block &input){
        if (num_columns == width_band){
            return 0;
        }
        u8 hashOut[8];
        u64 out = 0;

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &rand_position, sizeof(rand_position));
        blake3_hasher_update(&hasher, &input, sizeof(input));
        blake3_hasher_finalize(&hasher, hashOut, 8);

        // todo: memory copy
        for (u64 i = 0; i < 8; ++i){
            out ^= (static_cast<u64>(hashOut[i]) << (56 - i * 8));
        }
        return out % (num_columns - width_band);
    }

    void RBOKVS_rist::hash_to_band(const block &input, Rist25519_number *output){
        u64 width_band_in_byte = divCeil(width_band, 8);
        u8 hashOut[width_band_in_byte];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &rand_band, sizeof(rand_band));
        blake3_hasher_update(&hasher, &input, sizeof(input));
        blake3_hasher_finalize(&hasher, hashOut, width_band_in_byte);

        u64 i(0);
        for(i = 0; i < width_band_in_byte - 1; i++){
            output[i * 8 + 0] = Rist25519_number(bool(hashOut[i] & 0b10000000));
            output[i * 8 + 1] = Rist25519_number(bool(hashOut[i] & 0b01000000));
            output[i * 8 + 2] = Rist25519_number(bool(hashOut[i] & 0b00100000));
            output[i * 8 + 3] = Rist25519_number(bool(hashOut[i] & 0b00010000));
            output[i * 8 + 4] = Rist25519_number(bool(hashOut[i] & 0b00001000));
            output[i * 8 + 5] = Rist25519_number(bool(hashOut[i] & 0b00000100));
            output[i * 8 + 6] = Rist25519_number(bool(hashOut[i] & 0b00000010));
            output[i * 8 + 7] = Rist25519_number(bool(hashOut[i] & 0b00000001));
        }

        u64 j(0);
        if((width_band % 8) == 0){
            for(j = 0; j < 8; j++){
                output[i * 8 + j] = Rist25519_number(bool(hashOut[i] & (((u8)1)<< (7 - j))));
            }
        }else{
            for(j = 0; j < (width_band % 8); j++){
                output[i * 8 + j] = Rist25519_number(bool(hashOut[i] & (((u8)1)<< (7 - j))));
            }
        }
        
        return;

    }

    bool cmp(const MatrixRow_rist& x, const MatrixRow_rist& y)
    {
        return x.start_position < y.start_position;
    }

    EncodeStatus RBOKVS_rist::encode(const std::vector<block>& keys, const std::vector<std::vector<Rist25519_number>>& vals, const u64& VALUE_LENGTH_IN_NUMBER,
                                    std::vector<std::vector<Rist25519_point>>& output,
                                    const Rist25519_point& OKVS_RISTRETTO_BASEPOINT){
        

        std::vector<std::vector<Rist25519_number>> _data(num_columns, std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER));

        for (u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                _data[i][j] = Rist25519_number(okvs_prng);
            }
        }

        std::vector<MatrixRow_rist> rows(num_element);

        for(u64 i = 0; i < keys.size(); i++){
            rows[i].start_position = hash_to_position(keys[i]);

            rows[i].piv = 0;

            rows[i].data.reset(new Rist25519_number[width_band]);
            hash_to_band(keys[i], rows[i].data.get());

            rows[i].val = std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER);
            rows[i].val.assign(vals[i].begin(), vals[i].end());
        }

        
        // printf("encode key_%d : data\n", 21);
        // print_element(keys[21]);
        // printf("\n");
        // for(int i = 0; i < width_band; i++){
        //     printf("%d ", (rows[21].data[i] == Rist25519_number(1)));
        // }
        // printf("\n");
        // printf("encode hash pos: %d", rows[21].start_position);
        // printf("\n");
        // printf("encode val 21\n");
        // print_number(rows[21].val[0]);
        // printf("\n");

        std::sort(rows.begin(), rows.end(), cmp);
        // printf("\n");
        // printf("[sorted] encode hash pos 5: %d", rows[5].start_position);
        // printf("\n");
        // printf("\n");
        // printf("[sorted] encode hash pos 10: %d", rows[10].start_position);
        // printf("\n");
        // printf("\n");
        // printf("[sorted] encode hash pos 15: %d", rows[15].start_position);
        // printf("\n");

        u64 pivots(0);

        for(u64 row = 0; row < num_element; row++){
            //top:[0, row] ; bot[row+1, num_element - 1]
            auto some = rows.begin() + row;
            for(u64 i = 0; i < width_band; i++){
                if((some->data)[i] == Rist25519_number(0)){
                    continue;
                }
                some->piv = some->start_position + i;
                pivots += 1;
                if((some->data)[i] != Rist25519_number(1)){
                    Rist25519_number inv = (some->data)[i].inverse();
                    (some->data)[i] = Rist25519_number(1);
                    for(u64 j = i + 1; j < width_band; j++){
                        (some->data)[j] *= inv;
                    }
                    for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                        (some->val)[j] *= inv;
                    }
                }

                for(u64 j = row + 1; j < num_element; j++){
                    if(rows[j].start_position > some->piv){
                        break;
                    }
                    rows[j].piv = (some->piv) - (rows[j].start_position);
                    Rist25519_number multplier = rows[j].data[rows[j].piv];
                    if(multplier != Rist25519_number(0)){
                        if(multplier != Rist25519_number(1)){
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k] * multplier;
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k] * multplier;
                            }

                        }else{
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k];
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k];
                            }
                        }
                    }
                    rows[j].data[rows[j].piv] = Rist25519_number(0);
                }
                break;


            }
        }


        if(pivots != num_element){
            // printf("\n-------------------\nerror: band should not be all-zero\n-------------------\n");
        }

        for(i64 row = num_element - 1; row >= 0; row--){
            for(u64 i = 0; i < width_band; i++){
                if(rows[row].data[i] == Rist25519_number(0)){
                    continue;
                }
                if(rows[row].piv == (rows[row].start_position + i)){
                    continue;
                }
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    rows[row].val[k] -= _data[rows[row].start_position + i][k] * rows[row].data[i];
                }
            }
            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                _data[rows[row].piv][k] = rows[row].val[k];
            }
            
        }

        for(u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                output[i][j] = _data[i][j] * OKVS_RISTRETTO_BASEPOINT;
            }
        }

        // {
        //     MatrixRow_rist row_test;
        //     row_test.val = std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER);
        //     printf("output test key_%d : data\n", 21);
        //     print_element(keys[21]);
        //     printf("\n");
        //     row_test.val.assign(vals[21].begin(), vals[21].end());
        //     row_test.piv = 0;
        //     row_test.start_position = hash_to_position(keys[21]);
        //     printf("hash pos:%d\n", row_test.start_position);
        //     row_test.data.reset(new Rist25519_number[width_band]);
        //     hash_to_band(keys[21], row_test.data.get());
        //     Rist25519_number output_test = 0;
        //     Rist25519_point output_point_test = ZERO_POINT;
        //     //Rist25519_point trash = output_point_test;
        //     printf("output test band:\n");
        //     for(u64 i = 0; i < width_band; i++){
        //         output_test += _data[row_test.start_position + i][0] * row_test.data[i];
        //         if((row_test.data[i] != Rist25519_number(0))){
        //         output_point_test = output_point_test + (output[row_test.start_position + i][0]);
        //         }
        //         printf("%d ", (row_test.data[i] != Rist25519_number(0)));
        //     }
        //     printf("\n");
        //     printf("output test:\n");
        //     print_number(output_test);
        //     printf("\n");
        //     printf(" value 21:\n");
        //     print_number(vals[21][0]);
        //     printf("\n");
            
        //     printf("output test value point:\n");
        //     print_point(output_test * OKVS_RISTRETTO_BASEPOINT);
        //     printf("\n");
            
        //     //output_point_test = output_point_test - trash;
        //     printf("output test point output_point_test:\n");
        //     print_point(output_point_test);
        //     printf("\n");
            
        // }
        

        return SUCCESS;
    }

    EncodeStatus RBOKVS_rist::encode(const std::vector<block>& keys, const std::vector<std::vector<Rist25519_number>>& vals, const u64& VALUE_LENGTH_IN_NUMBER,
                                    std::vector<std::vector<Rist25519_point>>& output){
        

        std::vector<std::vector<Rist25519_number>> _data(num_columns, std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER));

        for (u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                _data[i][j] = Rist25519_number(okvs_prng);
            }
        }

        std::vector<MatrixRow_rist> rows(num_element);

        for(u64 i = 0; i < keys.size(); i++){
            rows[i].start_position = hash_to_position(keys[i]);

            rows[i].piv = 0;

            rows[i].data.reset(new Rist25519_number[width_band]);
            hash_to_band(keys[i], rows[i].data.get());

            rows[i].val = std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER);
            rows[i].val.assign(vals[i].begin(), vals[i].end());
        }

        std::sort(rows.begin(), rows.end(), cmp);

        u64 pivots(0);

        for(u64 row = 0; row < num_element; row++){
            //top:[0, row] ; bot[row+1, num_element - 1]
            auto some = rows.begin() + row;
            for(u64 i = 0; i < width_band; i++){
                if((some->data)[i] == Rist25519_number(0)){
                    continue;
                }
                some->piv = some->start_position + i;
                pivots += 1;
                if((some->data)[i] != Rist25519_number(1)){
                    Rist25519_number inv = (some->data)[i].inverse();
                    (some->data)[i] = Rist25519_number(1);
                    for(u64 j = i + 1; j < width_band; j++){
                        (some->data)[j] *= inv;
                    }
                    for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                        (some->val)[j] *= inv;
                    }
                }

                for(u64 j = row + 1; j < num_element; j++){
                    if(rows[j].start_position > some->piv){
                        break;
                    }
                    rows[j].piv = (some->piv) - (rows[j].start_position);
                    Rist25519_number multplier = rows[j].data[rows[j].piv];
                    if(multplier != Rist25519_number(0)){
                        if(multplier != Rist25519_number(1)){
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k] * multplier;
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k] * multplier;
                            }

                        }else{
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k];
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k];
                            }
                        }
                    }
                    rows[j].data[rows[j].piv] = Rist25519_number(0);
                }
                break;


            }
        }


        if(pivots != num_element){
            // printf("\n-------------------\nerror: band should not be all-zero\n-------------------\n");
        }

        for(i64 row = num_element - 1; row >= 0; row--){
            for(u64 i = 0; i < width_band; i++){
                if(rows[row].data[i] == Rist25519_number(0)){
                    continue;
                }
                if(rows[row].piv == (rows[row].start_position + i)){
                    continue;
                }
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    rows[row].val[k] -= _data[rows[row].start_position + i][k] * rows[row].data[i];
                }
            }
            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                _data[rows[row].piv][k] = rows[row].val[k];
            }
            
        }

        for(u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                output[i][j] = Rist25519_point::mulGenerator(_data[i][j]);
            }
        }

        return SUCCESS;
    }

    EncodeStatus RBOKVS_rist::encode(const std::vector<block>& keys, const std::vector<std::vector<Rist25519_number>>& vals, const u64& VALUE_LENGTH_IN_NUMBER,
                                    std::vector<std::vector<Rist25519_number>>& output){
        std::vector<std::vector<Rist25519_number>> _data(num_columns, std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER));

        for (u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                _data[i][j] = Rist25519_number(okvs_prng);
            }
        }

        std::vector<MatrixRow_rist> rows(num_element);

        for(u64 i = 0; i < keys.size(); i++){
            rows[i].start_position = hash_to_position(keys[i]);

            rows[i].piv = 0;

            rows[i].data.reset(new Rist25519_number[width_band]);
            hash_to_band(keys[i], rows[i].data.get());

            rows[i].val = std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER);
            rows[i].val.assign(vals[i].begin(), vals[i].end());
        }

        

        std::sort(rows.begin(), rows.end(), cmp);
        // printf("\n");
        u64 pivots(0);

        for(u64 row = 0; row < num_element; row++){
            //top:[0, row] ; bot[row+1, num_element - 1]
            auto some = rows.begin() + row;
            for(u64 i = 0; i < width_band; i++){
                if((some->data)[i] == Rist25519_number(0)){
                    continue;
                }
                some->piv = some->start_position + i;
                pivots += 1;
                if((some->data)[i] != Rist25519_number(1)){
                    Rist25519_number inv = (some->data)[i].inverse();
                    (some->data)[i] = Rist25519_number(1);
                    for(u64 j = i + 1; j < width_band; j++){
                        (some->data)[j] *= inv;
                    }
                    for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                        (some->val)[j] *= inv;
                    }
                }

                for(u64 j = row + 1; j < num_element; j++){
                    if(rows[j].start_position > some->piv){
                        break;
                    }
                    rows[j].piv = (some->piv) - (rows[j].start_position);
                    Rist25519_number multplier = rows[j].data[rows[j].piv];
                    if(multplier != Rist25519_number(0)){
                        if(multplier != Rist25519_number(1)){
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k] * multplier;
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k] * multplier;
                            }

                        }else{
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k];
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k];
                            }
                        }
                    }
                    rows[j].data[rows[j].piv] = Rist25519_number(0);
                }
                break;


            }
        }

        if(pivots != num_element){
            //printf("\n-------------------\nerror: band should not be all-zero\n-------------------\n");
        }

        for(i64 row = num_element - 1; row >= 0; row--){
            for(u64 i = 0; i < width_band; i++){
                if(rows[row].data[i] == Rist25519_number(0)){
                    continue;
                }
                if(rows[row].piv == (rows[row].start_position + i)){
                    continue;
                }
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    rows[row].val[k] -= _data[rows[row].start_position + i][k] * rows[row].data[i];
                }
            }
            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                _data[rows[row].piv][k] = rows[row].val[k];
            }
            
        }

        for(u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                output[i][j] = _data[i][j];
            }
        }

        return SUCCESS;
    }


    std::vector<Rist25519_point> RBOKVS_rist::decode(const std::vector<std::vector<Rist25519_point>>& codeWords, const block &key, const u64& VALUE_LENGTH_IN_NUMBER){
            
        u64 start_position = hash_to_position(key);
        std::unique_ptr<Rist25519_number[]> data;
        data.reset(new Rist25519_number[width_band]);
        hash_to_band(key, data.get());

        std::vector<Rist25519_point> result(VALUE_LENGTH_IN_NUMBER, ZERO_POINT);

        u64 width_band_in_byte = divCeil(width_band, 8);
        u8 hashOut[width_band_in_byte];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &rand_band, sizeof(rand_band));
        blake3_hasher_update(&hasher, &key, sizeof(key));
        blake3_hasher_finalize(&hasher, hashOut, width_band_in_byte);
        
        // printf("decode key 21\n");
        // print_element(key);
        // printf("\n");
        // printf("hash pos 21:%d\n", start_position);

        u64 i(0);
        for(i = 0; i < width_band_in_byte - 1; i++){

            // print_u8(hashOut + i, 1);

            if((hashOut[i] & 0b10000000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 0][k];
                }
            }
            if((hashOut[i] & 0b01000000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 1][k];
                }
            }
            if((hashOut[i] & 0b00100000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 2][k];
                }
            }
            if((hashOut[i] & 0b00010000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 3][k];
                }
            }
            if((hashOut[i] & 0b00001000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 4][k];
                }
            }
            if((hashOut[i] & 0b00000100) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 5][k];
                }
            }
            if((hashOut[i] & 0b00000010) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 6][k];
                }
            }
            if((hashOut[i] & 0b00000001) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 7][k];
                }
            }
        }


        u64 j(0);
        if((width_band % 8) == 0){

            // print_u8(hashOut + i, 1);
            // printf("\n");
            for(j = 0; j < 8; j++){
                if((hashOut[i] & (((u8)1)<< (7 - j))) != 0){
                    for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                        result[k] += codeWords[start_position + i * 8 + j][k];
                    }
                }
            }
        }else{
            for(j = 0; (j < (width_band % 8)); j++){
                if((hashOut[i] & (((u8)1)<< (7 - j))) != 0){
                    for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                        result[k] += codeWords[start_position + i * 8 + j][k];
                    }
                }
            }

        }

        return result;

    }

    EncodeStatus RBOKVS_rist::test_encode(const std::vector<block>& keys, const std::vector<std::vector<Rist25519_number>>& vals, const u64& VALUE_LENGTH_IN_NUMBER,
                                    std::vector<std::vector<Rist25519_number>>& output){
        std::vector<std::vector<Rist25519_number>> _data(num_columns, std::vector<Rist25519_number>(VALUE_LENGTH_IN_NUMBER));

        for (u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                _data[i][j] = Rist25519_number(okvs_prng);
            }
        }

        std::vector<MatrixRow_rist> rows(num_element);

        for(u64 i = 0; i < keys.size(); i++){
            rows[i].val.assign(vals[i].begin(), vals[i].end());
            rows[i].piv = 0;
            rows[i].start_position = hash_to_position(keys[i]);
            rows[i].data.reset(new Rist25519_number[width_band]);
            hash_to_band(keys[i], rows[i].data.get());
        }

        // printf("key_%d : data\n", 0);
        // for(int i = 0; i < width_band; i++){
        //     print_number(rows[0].data[i]);
        // }

        std::sort(rows.begin(), rows.end(), cmp);

        u64 pivots(0);

        for(u64 row = 0; row < num_element; row++){
            //top:[0, row] ; bot[row+1, num_element - 1]
            auto some = rows.begin() + row;
            for(u64 i = 0; i < width_band; i++){
                if((some->data)[i] == Rist25519_number(0)){
                    continue;
                }
                some->piv = some->start_position + i;
                pivots += 1;
                if((some->data)[i] != Rist25519_number(1)){
                    Rist25519_number inv = (some->data)[i].inverse();
                    (some->data)[i] = Rist25519_number(1);
                    for(u64 j = i + 1; j < width_band; j++){
                        (some->data)[j] *= inv;
                    }
                    for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                        (some->val)[j] *= inv;
                    }
                }

                for(u64 j = row + 1; j < num_element; j++){
                    if(rows[j].start_position > some->piv){
                        break;
                    }
                    rows[j].piv = some->piv - rows[j].start_position;
                    Rist25519_number multplier = rows[j].data[rows[j].piv];
                    if(multplier != Rist25519_number(0)){
                        if(multplier != Rist25519_number(1)){
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k] * multplier;
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k] * multplier;
                            }

                        }else{
                            for(u64 k = i + 1; k < width_band; k++){
                                rows[j].data[rows[j].piv + k - i] -= (some->data)[k];
                            }
                            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                                rows[j].val[k] -= (some->val)[k];
                            }
                        }
                    }
                    rows[j].data[rows[j].piv] = Rist25519_number(0);
                }
                break;


            }
        }

        if(pivots != num_element){
            printf("\n-------------------\nerror: band should not be all-zero\n-------------------\n");
        }

        for(i64 row = num_element - 1; row >= 0; row--){
            for(u64 i = 0; i < width_band; i++){
                if(rows[row].data[i] == Rist25519_number(0)){
                    continue;
                }
                if(rows[row].piv == (rows[row].start_position + i)){
                    continue;
                }
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    rows[row].val[k] -= _data[rows[row].start_position + i][k] * rows[row].data[i];
                }
            }
            for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                _data[rows[row].piv][k] = rows[row].val[k];
            }
            
        }

        for(u64 i = 0; i < num_columns; i++){
            for(u64 j = 0; j < VALUE_LENGTH_IN_NUMBER; j++){
                output[i][j] = _data[i][j];
            }
        }

        return SUCCESS;
    }

    std::vector<Rist25519_number> RBOKVS_rist::test_decode(const std::vector<std::vector<Rist25519_number>>& codeWords, const block &key, const u64& VALUE_LENGTH_IN_NUMBER){
            
        u64 start_position = hash_to_position(key);

        std::vector<Rist25519_number> result(VALUE_LENGTH_IN_NUMBER, Rist25519_number(0));

        u64 width_band_in_byte = divCeil(width_band, 8);
        u8 hashOut[width_band_in_byte];
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, &rand_band, sizeof(rand_band));
        blake3_hasher_update(&hasher, &key, sizeof(key));
        blake3_hasher_finalize(&hasher, hashOut, width_band_in_byte);

        u64 i(0);
        for(i = 0; i < width_band_in_byte - 1; i++){
            if((hashOut[i] & 0b10000000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 0][k];
                }
            }
            if((hashOut[i] & 0b01000000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 1][k];
                }
            }
            if((hashOut[i] & 0b00100000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 2][k];
                }
            }
            if((hashOut[i] & 0b00010000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 3][k];
                }
            }
            if((hashOut[i] & 0b00001000) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 4][k];
                }
            }
            if((hashOut[i] & 0b00000100) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 5][k];
                }
            }
            if((hashOut[i] & 0b00000010) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 6][k];
                }
            }
            if((hashOut[i] & 0b00000001) != 0){
                for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                    result[k] += codeWords[start_position + i * 8 + 7][k];
                }
            }
        }

        u64 j(0);
        if((width_band % 8) == 0){
            for(j = 0; j < 8; j++){
                if((hashOut[i] & (((u8)1)<< (7 - j))) != 0){
                    for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                        result[k] += codeWords[start_position + i * 8 + j][k];
                    }
                }
            }
        }else{
            for(j = 0; (j < (width_band % 8)); j++){
                if((hashOut[i] & (((u8)1)<< (7 - j))) != 0){
                    for(u64 k = 0; k < VALUE_LENGTH_IN_NUMBER; k++){
                        result[k] += codeWords[start_position + i * 8 + j][k];
                    }
                }
            }

        }
        return result;

    }

    void print_u8(u8* buffer, u64 length)
    {
        for(u64 i = 0; i < length; i++ )
        {
            printf("%02x ", buffer[i]);
        }

        printf("  ");
    }

    void print_u32(u32* buffer, u64 length)
    {
        for(u64 i = 0; i < length; i++ )
        {
            printf("%08x ", buffer[i]);
        }

        printf("  ");
    }

    void print_number(const Rist25519_number& n){
        for(u64 i = 0; i < 32; i++ )
        {
            printf("%02x ", n.data[i]);
        }

        printf("  ");
    }

    void print_point(Rist25519_point P)
    {
        Rist25519_point_in_bytes p_bytes;
        P.toBytes(p_bytes.data());
        print_u8(p_bytes.data(), POINT_LENGTH_IN_BYTE);
    }
    void print_point(Sodium::Ed25519 P){
        Rist25519_point_in_bytes p_bytes;
        P.toBytes(p_bytes.data());
        print_u8(p_bytes.data(), POINT_LENGTH_IN_BYTE);
    }
    void print_vec_point(std::vector<Rist25519_point> P){
        for(auto iter: P){
            print_point(iter);
            printf("\n");
        }
        printf("\n");
    }

    void print_element(element e)
    {
        std::cout << e << "  ";
    }

    void print_vector(std::vector<element> vec)
    {
        for(auto iter = vec.begin(); iter != vec.end(); iter++)
        {
            print_element(*iter);
            std::cout << std::endl;
        }
    }
    void print_vector(std::vector<u32> vec)
    {
        for(auto iter = vec.begin(); iter != vec.end(); iter++)
        {
            printf("%08x ", *iter);
        }
    }


    void print_row_data(osuCrypto::block* data, u64 wBlocks){
        for(auto i = 0; i < wBlocks; i++){
            print_element(data[i]);
        }
        std::cout << "  ";

    }

    
    void print_row_of_matrix(MatrixRow& a, u64 wBlocks){
        
        std::cout << "startPos: ";
        std::cout << a.startPos << " ";
        
        std::cout << "data: ";
        print_row_data(&(a.data[0]), wBlocks);
        
        std::cout << "val: ";
        print_element(a.val);

        std::cout << "\n";
    }

    void print_row_of_matrix_long_value(MatrixRow_LongValue& a, u64 wBlocks){
                std::cout << "startPos: ";
        std::cout << a.startPos << " ";
        
        std::cout << "data: ";
        print_row_data(&(a.data[0]), wBlocks);
        
        std::cout << "val: ";
        for(auto iter = a.val.begin(); iter != a.val.end(); iter++)
        {
            print_element(*iter);
        }

        std::cout << "\n";
    }

    void print_row_of_matrix_rist(MatrixRow_rist& a, u64 band_width){
        std::cout << "startPos: ";
        std::cout << a.start_position << " ";
        
        std::cout << "data: ";
        for(int i = 0; i < band_width; i++){
            print_number((a.data[i]));
            std::cout << "   ";
        }
        
        std::cout << "   val: ";
        for(auto iter = a.val.begin(); iter != a.val.end(); iter++)
        {
            print_number(*iter);
        }

        std::cout << "\n";
    }

    void print_grid(const std::vector<u64>& grid){
        for(auto iter : grid){
            std::cout << iter << " "; 
        }
    }

}
