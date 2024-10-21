import { derivePath } from 'ed25519-hd-key'
import {  mnemonicToSeed } from 'bip39'
import { KeyPair, keyPairFromSeed, mnemonicToPrivateKey, sign } from '@ton/crypto'
import { Address, beginCell, Builder, Cell, external, internal, SendMode, StateInit, storeMessage, storeMessageRelaxed, toNano, WalletContractV4, WalletContractV5R1 } from '@ton/ton'
import { input, password, rawlist } from '@inquirer/prompts';
import chalk from "chalk";


async function extractKeysFromLedgerMnemonic(mnemonic: string, index: number) {
  const seed = await mnemonicToSeed(mnemonic)
  const seedContainer = derivePath(`m/44'/607'/0'/0'/${index}'/0'`, seed.toString('hex'))
  const keyPair = keyPairFromSeed(seedContainer.key)
  const wallet = WalletContractV4.create({
    workchain: 0,
    publicKey: keyPair.publicKey,
  })

  return { contract: wallet, keyPair }
}

async function extractKeysFromMyTonWalletMultiChainMnemonic(mnemonic: string, index: number) {
  const seed = await mnemonicToSeed(mnemonic);
  const seedContainer = derivePath(`m/44'/607'/${index}'`, seed.toString('hex'));
  const keyPair = keyPairFromSeed(seedContainer.key);
  const wallet = WalletContractV5R1.create({
    workchain: 0,
    publicKey: keyPair.publicKey,
  });

  return { contract: wallet, keyPair }

}

class TONX {
  network: 'testnet' | 'mainnet'
  apiKey: string
  endpoint: string

  constructor(apiKey: string, network: 'testnet' | 'mainnet', version: string = 'v2') {
    this.apiKey = apiKey
    this.network = network
    this.endpoint = `https://${network}-rpc.tonxapi.com/${version}/json-rpc/${apiKey}`
  }


  async runGetMethod(address: string, method: string, stack: any[]) {
    const response = await fetch(this.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: '1',
        jsonrpc: '2.0',
        method: 'runGetMethod',
        params: {
          address,
          method,
          stack,
        },
      }),
    })
    const data = await response.json() as any
    return data.result 
  }


}


class Wallet {
  contract: WalletContractV4
  keyPair: KeyPair

  constructor(keyPair: KeyPair) {
    const wallet = WalletContractV4.create({
      workchain: 0,
      publicKey: keyPair.publicKey,
    })
    this.contract = wallet
    this.keyPair = keyPair
  }

  static async init(mnemonic: string){
    const mnemonicStringArray = mnemonic.split(' ')
    const keyPair = await mnemonicToPrivateKey(mnemonicStringArray)
    return new Wallet(keyPair)
  }

  async getSeqno(client: TONX) {
    const response = await client.runGetMethod(this.contract.address.toString(), 'seqno', [])
    const seqnoHex = response.result.stack[0][1]
    const seqno = Number.parseInt(seqnoHex, 16)
    return seqno
  }

  rawSign(orderHashHex: string) {
    const signature = sign(Buffer.from(orderHashHex, 'hex'), this.keyPair.secretKey)
    return {
      buffer: signature,
      signatureHex: signature.toString('hex'),
    }
    // const signature = nacl.sign.detached(hexToBytes(orderHashHex), this.keyPair.secretKey);
    // return bytesToHex(signature);
  }
  rawSign2(orderHashHex: string) {
    const signature = sign(Buffer.from(orderHashHex, 'hex'), this.keyPair.secretKey)
    return signature.toString('hex')
    // const signature = nacl.sign.detached(hexToBytes(orderHashHex), this.keyPair.secretKey);
    // return bytesToHex(signature);
  }

  createExtMsgBoc(
    intMsgParams: {
      toAddress: string
      value: string
      bounce?: boolean
      init?: StateInit
      body?: string | Cell
    },
    seqno: number,
    opCode = 0,
  ) {
    const { toAddress, value, init, bounce = true, body } = intMsgParams
    const intMsg = internal({
      to: Address.parse(toAddress), // Send TON to this address
      value: toNano(value),
      init,
      bounce,
      body,
    })
    const msg = beginCell()
      .storeUint(this.contract.walletId, 32)
      .storeUint(0xFFFFFFFF, 32)
      .storeUint(seqno, 32)
      .storeUint(opCode, 8)
      .storeUint(SendMode.PAY_GAS_SEPARATELY, 8)
      .storeRef(beginCell().store(storeMessageRelaxed(intMsg)))

    const signedMsg = {
      builder: msg,
      cell: msg.endCell(),
    }
    const extMsgBody = beginCell()
      .storeBuffer(sign(signedMsg.cell.hash(), this.keyPair.secretKey))
      .storeBuilder(signedMsg.builder)
      .endCell()

    const extMsg = external({
      to: this.contract.address,
      init: this.contract.init,
      body: extMsgBody,
    })

    const extMsgCell = beginCell()
      .store(storeMessage(extMsg))
      .endCell()

    return {
      boc: extMsgCell.toBoc(),
      string: extMsgCell.toBoc().toString('base64'),
      message: extMsg,
      extMsgBody,
    }
  }
}




function  createExternalMessageWithSignatures(
  index: number,
  orderCell: Cell,
  signatures: [Uint8Array, number][],
  wallet: Wallet,
) {
  const filterSignatures = signatures.filter((_) => _[1] !== index);

  let serializeSignaturesBuilder: Builder | null = null;
  for (const [i, _] of filterSignatures.entries()) {
      // console.log(Buffer.from(_[0]).toString('hex'), _[1]);
      if (i === 0) {
          serializeSignaturesBuilder = new Builder();
          serializeSignaturesBuilder.storeBuffer(Buffer.from(_[0]));
          serializeSignaturesBuilder.storeUint(_[1], 8);
          serializeSignaturesBuilder.storeBit(0);
      } else {
          const newSerializeSignaturesBuilder = new Builder();
          newSerializeSignaturesBuilder.storeBuffer(Buffer.from(_[0]));
          newSerializeSignaturesBuilder.storeUint(_[1], 8);
          newSerializeSignaturesBuilder.storeBit(1);
          newSerializeSignaturesBuilder.storeRef(serializeSignaturesBuilder!.endCell());
          serializeSignaturesBuilder = newSerializeSignaturesBuilder;
      }
  }

  const tmpBuilder = new Builder();
  tmpBuilder.storeUint(index, 8);
  if (!serializeSignaturesBuilder) {
      tmpBuilder.storeBit(0);
  } else {
      tmpBuilder.storeBit(1);
      tmpBuilder.storeRef(serializeSignaturesBuilder.endCell());
  }
  tmpBuilder.storeSlice(orderCell.beginParse());
  const bodyHash = tmpBuilder.endCell().hash().toString('hex');
  const sign = wallet.rawSign(bodyHash);

  const bodyBuilder = new Builder();
  bodyBuilder.storeBuffer(sign.buffer);
  bodyBuilder.storeSlice(tmpBuilder.endCell().beginParse());

  return bodyBuilder.endCell().toBoc()
}

enum WalletType {
  NormalV4 = 0,
  Ledger = 1,
  MyTonWalletMultiChain = 2,
}


async function main() {
  let tonkeyAddress: Address;
  let thresholds: number;
  const ledgerMnemonics: {
    mnemonic: string,
    nonBounceableAddress: string,
    index: number,
    type: WalletType
  }[] = [];
  const wallets: {wallet: Wallet, index: number}[] = [];

  try {
    tonkeyAddress = Address.parse(await input({ message: 'Enter your tonkey address:' }));
    console.info(`your tonkey non-bounceable address is ${tonkeyAddress.toString({ bounceable: false })}`);
  } catch (error) {
    console.error(error);
    throw new Error('Invalid address');
  }

  try {
    thresholds = parseInt(await input({ message: 'Enter the threshold of your multiSig wallet:'}));
    console.log(`your threshold is ${thresholds}`);
  } catch (error) {
    console.error(error);
    throw new Error('Invalid threshold');
  }

  for (let i = 0; i < thresholds; i++) {
    const type = await rawlist({ 
      message: `What's your wallet type?`,
      choices: [
        {
          name: 'normal',
          value: WalletType.NormalV4
        },
        {
          name: 'ledger',
          value: WalletType.Ledger
        },
        {
          name: 'MyTonWallet multi chain',
          value: WalletType.MyTonWalletMultiChain
        }
      ] 
    });
    const mnemonic = await password({ message: `Enter the mnemonic of the key:`, mask: true});
    const nonBounceableAddress = await input({ message: `Enter the non-bounceable address of the key:` });
    const index = await input({ message: `Enter the index of the key:` });

    const result = {
      mnemonic,
      nonBounceableAddress,
      index: parseInt(index),
      type
    }

    ledgerMnemonics.push(result);
  }

  for (const m of ledgerMnemonics) {
    //TODO: make it multi-type
    let index = 0
    let found = false
    switch (m.type) {
      case WalletType.NormalV4:
        const keyPair = await mnemonicToPrivateKey(m.mnemonic.split(' '))
        const wallet = new Wallet(keyPair)
        wallets.push({wallet, index: m.index})
        break;
      case WalletType.Ledger:
        index = 0
        found = false
        while(!found){
          const { contract, keyPair } = await extractKeysFromLedgerMnemonic(m.mnemonic, index)
          const address = contract.address.toString({ bounceable: false })
          // const privateKeyHex = keyPair.secretKey.toString('hex').slice(0, 64)
          if(address === m.nonBounceableAddress){
            const publicKeyHex = keyPair.publicKey.toString('hex')
            console.log(`Found the keypair for the target address ${m.nonBounceableAddress}`)
            console.log(`Public key: ${publicKeyHex}`)
            const wallet = new Wallet(keyPair)
            wallets.push({wallet, index: m.index})
            found = true
          }
          index++
        }
        break;
      case WalletType.MyTonWalletMultiChain:
        index = 0
        found = false
        while(!found){
          const { contract, keyPair } = await extractKeysFromMyTonWalletMultiChainMnemonic(m.mnemonic, index)
          const address = contract.address.toString({ bounceable: false })
          // const privateKeyHex = keyPair.secretKey.toString('hex').slice(0, 64)
          if(address === m.nonBounceableAddress){
            const publicKeyHex = keyPair.publicKey.toString('hex')
            console.log(`Found the keypair for the target address ${m.nonBounceableAddress}`)
            console.log(`Public key: ${publicKeyHex}`)
            const wallet = new Wallet(keyPair)
            wallets.push({wallet, index: m.index})
            found = true
          }
          index++
        }
        break;

    }
  };

  const rawTxhash = await input({ message: 'Enter the raw tx hash:' });
  const orderCellBoc = await input({ message: 'Enter the order cell boc:' });
  const signatures: [Uint8Array, number][] = [];
  wallets.forEach((w, i) => {
    const sign = w.wallet.rawSign(rawTxhash)
    signatures.push([sign.buffer, w.index]);
    if(i === thresholds - 1){
      const boc = createExternalMessageWithSignatures(w.index, Cell.fromHex(orderCellBoc), signatures, w.wallet)
      const message = external({
        to: tonkeyAddress,
        body: Cell.fromBoc(boc)[0]
      })
      const extMsgCell = beginCell()
      .store(storeMessage(message))
      .endCell()
      console.log(chalk.magenta('your external message boc is following above, please copy it:'))
      
      console.log(chalk.green(extMsgCell.toBoc().toString('base64')))  
    }
  })


}

main()