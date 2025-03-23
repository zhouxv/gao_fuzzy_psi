#pragma once

#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"

namespace osuCrypto
{
    bool test_fpsi(const CLP &clp);

    void test_paillier_performance(const CLP &clp);
}