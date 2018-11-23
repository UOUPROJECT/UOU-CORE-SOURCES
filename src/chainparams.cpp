// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "main.h"

#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"
#include "base58.h"

#include <assert.h>
#include "aligned_malloc.h"

#include <boost/assign/list_of.hpp>

using namespace std;

#include "chainparamsseeds.h"

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

#define STARTBITS 0x1F00FFFF		// 520159231
// 0x1D00FFFF		486604799

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1051200;//262800X4
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // one hour
        consensus.nPowTargetSpacing = 120; // 154 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x90;
        pchMessageStart[1] = 0x0d;
        pchMessageStart[2] = 0xca;
        pchMessageStart[3] = 0xfe;
        vAlertPubKey = ParseHex("0493e2c2526335349a0523553ef6a18c00b4b35aea01a44364d4e2cc3abf29f280e81276ba2c2fa398bfbc0012321f9d74da5ed66bdc489829f9219e302a8c0e11");
        nDefaultPort = 10130;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        /**
         * Build the genesis block. Note that the output of its generation
         * transaction cannot be spent since it did not originally exist in the
         * database.
         *
         * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
         *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
         *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
         *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
         *   vMerkleTree: 4a5e1e
         */
        const char* pszTimestamp = "The time 05/Nov/2018 Bare Knuckle Bouts in Madagascar?Is It About More Than the Fighting'";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        //txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vin[0].scriptSig = CScript() << STARTBITS << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0;		//10000 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0472f0f1829990dbee40793a05ef07048845eb956300173e7d57964bf4bc9aae29e73f7757af72eb2258e669390d261021589cee374193d6a1a0881d810073b69c") << OP_CHECKSIG;
        //txNew.vout[0].scriptPubKey = GetScriptForDestination(CBitcoinAddress(DEV_ADDRESS).Get());
		//txNew.vout[0].scriptPubKey = CScript();

        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1541481599;
        genesis.nBits    = STARTBITS;
        genesis.nNonce   = 520202895;


        if(genesis.GetHash() != uint256S("0000edd739c16a51f5fe057f79a682a82bba760f2ce5b3701c010061fade82fc") ){
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            uint256 thash;
            while(true){
                //thash = genesis.FindBestPatternHash(collisions,scratchpad,8,&tmpflag);
                thash = genesis.GetPoWHash();
                //printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                if (UintToArith256(thash) <= hashTarget)
                    break;
                genesis.nNonce++;
                if (genesis.nNonce == 0){
                    LogPrintf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            printf("block.nTime = %u \n", genesis.nTime);
            printf("block.nNonce = %u \n", genesis.nNonce);
            printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            printf("block.nBits = %u \n", genesis.nBits);
            consensus.hashGenesisBlock=genesis.GetHash();
        }

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == genesis.GetHash());

        //assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();

        //vSeeds.push_back(CDNSSeedData("139.59.139.105", "139.59.139.105"));
        //vSeeds.push_back(CDNSSeedData("104.248.133.94", "104.248.133.94"));
        //vSeeds.push_back(CDNSSeedData("104.248.17.3", "104.248.17.3"));
        //vSeeds.push_back(CDNSSeedData("46.101.152.7", "46.101.152.7"));
        //vSeeds.push_back(CDNSSeedData("46.101.227.238", "46.101.227.238"));
        //vSeeds.push_back(CDNSSeedData("209.97.153.68", "209.97.153.68"));
        //vSeeds.push_back(CDNSSeedData("159.89.194.138", "159.89.194.138"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68);		// S T U
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,68+128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = { //(Checkpoints::CCheckpointData)
            boost::assign::map_list_of
            ( 0, uint256S("000032bd27c65ec42967b7854a49df222abdfae8d9350a61083af8eab2a25e03"))
            /*
            ( 2844, uint256S("0x0000049f16d6e1ddc6b3e7d1e44cc51c07af092dd42ef00016873cd3580bf4f5")),
            1454805021, // * UNIX timestamp of last checkpoint block
            3238,   // * total number of transactions between genesis and last checkpoint
                                    //   (the tx=... number in the SetBestChain debug.log lines)
            1000.0     // * estimated number of transactions per day after checkpoint
            */
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.fPowAllowMinDifficultyBlocks = true;
        pchMessageStart[0] = 0x90;
        pchMessageStart[1] = 0x0d;
        pchMessageStart[2] = 0xf0;
        pchMessageStart[3] = 0x0d;
        vAlertPubKey = ParseHex("0472f0f1829990dbee40793a05ef07048845eb956300173e7d57964bf4bc9aae29e73f7757af72eb2258e669390d261021589cee374193d6a1a0881d810073b69c");
        nDefaultPort = 10140;
        nMinerThreads = 0;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1541481599;
        genesis.nNonce = 520202895;

        //genesis.nStartLocation = 240876;
        //genesis.nFinalCalculation = 2094347097;


        if(genesis.GetHash() != uint256S("0000edd739c16a51f5fe057f79a682a82bba760f2ce5b3701c010061fade82fc") ){
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            uint256 thash;
            while(true){
                //thash = genesis.FindBestPatternHash(collisions,scratchpad,8,&tmpflag);
                thash = genesis.GetPoWHash();
                LogPrintf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(),
                hashTarget.ToString().c_str());
                if (UintToArith256(thash) <= hashTarget)
                    break;
                genesis.nNonce=genesis.nNonce+10000;
                if (genesis.nNonce == 0){
                    LogPrintf("NONCE WRAPPED, incrementing time\n");
                    ++genesis.nTime;
                }
            }
            LogPrintf("block.nTime = %u \n", genesis.nTime);
            LogPrintf("block.nNonce = %u \n", genesis.nNonce);
            LogPrintf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
            LogPrintf("block.nBits = %u \n", genesis.nBits);
            consensus.hashGenesisBlock=genesis.GetHash();
        }

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == genesis.GetHash());

        //consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("westcoast.hodlcoin.com", "westcoast.hodlcoin.com")); //West Coast
        //vSeeds.push_back(CDNSSeedData("174.140.166.133","174.140.166.133"));//Hodl-lay-yee-hoo

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68);//O P Q R S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,68+128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();


        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = { //(Checkpoints::CCheckpointData)
            boost::assign::map_list_of
            ( 0, uint256S("00d655aae75ceef9bc13fd8c6168177746ce85286d11ef56de959f4e9b6ff6af"))
            ( 375491, uint256S("0000013e0f3d708a18f787f8b463b4adfebd40af43fa4674e1ac395de8d75e20")),
            1515148272,
            704236,
            10
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        pchMessageStart[0] = 0x90;
        pchMessageStart[1] = 0x0d;
        pchMessageStart[2] = 0xfe;
        pchMessageStart[3] = 0xe1;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        genesis.nTime = 1296688602;
        genesis.nBits = STARTBITS;
        genesis.nNonce = 2;
        consensus.hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 10150;
        //assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = { //(Checkpoints::CCheckpointData)
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
