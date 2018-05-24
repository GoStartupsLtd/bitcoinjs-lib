// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731

module.exports = {
  bitcoingold: {
    messagePrefix: '\x1DBitcoin Gold Signed Message:\n',
    bech32: 'btg',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x26,
    scriptHash: 0x17,
    wif: 0x80,
    forkHeight: 491407,
    equihash: {
      n: 144,
      k: 5,
      equihashForkHeight: 888888, // TODO Change once live
      preEquihashFork: {
        n: 200,
        k: 9
      }
    }
  },
  bitcoingoldtestnet: {
    messagePrefix: '\x1DBitcoin Gold Signed Message:\n',
    bech32: 'tbtg',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    forkHeight: 1,
    equihash: {
      n: 96,
      k: 5
    }
  },
  bitcoingoldregtest: {
    messagePrefix: '\x1DBitcoin Gold Signed Message:\n',
    bech32: 'tbtg',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    forkHeight: 2000,
    equihash: {
      n: 96,
      k: 5
    }
  },
  bitcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80
  },
  testnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef
  },
  litecoin: {
    messagePrefix: '\x19Litecoin Signed Message:\n',
    bip32: {
      public: 0x019da462,
      private: 0x019d9cfe
    },
    pubKeyHash: 0x30,
    scriptHash: 0x32,
    wif: 0xb0
  }
}
