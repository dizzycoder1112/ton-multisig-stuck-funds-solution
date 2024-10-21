import { derivePath } from 'ed25519-hd-key'
import {  mnemonicToSeed } from 'bip39'
import { KeyPair, keyPairFromSeed, mnemonicToPrivateKey, sign } from '@ton/crypto'
import { Address, beginCell, Builder, Cell, external, internal, SendMode, StateInit, storeMessage, storeMessageRelaxed, toNano, WalletContractV4 } from '@ton/ton'
import { input } from '@inquirer/prompts';

const to_hex_array: string[] = [];
const to_byte_map: Record<string, number> = {};
for (let ord = 0; ord <= 0xff; ord++) {
  let s = ord.toString(16);
  if (s.length < 2) {
    s = "0" + s;
  }
  to_hex_array.push(s);
  to_byte_map[s] = ord;
}



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
      signature,
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
  const signature = wallet.rawSign2(bodyHash);

  const bodyBuilder = new Builder();
  bodyBuilder.storeBuffer(Buffer.from(signature, 'hex'));
  bodyBuilder.storeSlice(tmpBuilder.endCell().beginParse());

  return bodyBuilder.endCell().toBoc()
}


async function main() {
  let tonkeyAddress: Address;
  let thresholds: number;
  const mnemonics: string[] = [];

  try {
    tonkeyAddress = Address.parse(await input({ message: 'Enter your tonkey address: ' }));
    console.info(`your tonkey address is ${tonkeyAddress.toString({ bounceable: false })}`);
  } catch (error) {
    console.error(error);
    throw new Error('Invalid address');
  }

  try {
    thresholds = parseInt(await input({ message: 'Enter the threshold of your multiSig wallet: ' }));
    console.log(`your threshold is ${thresholds}`);
  } catch (error) {
    console.error(error);
    throw new Error('Invalid threshold');
  }

  for (let i = 0; i < thresholds; i++) {
    mnemonics.push(await input({ message: `Enter the mnemonic of the ${i + 1}th key` }));
  }





}

main()


// async function run(){
//   const mnemonic = ""
//   const wallet = await Wallet.init(mnemonic)
//   const rawTxhash = "8da63e8b87b37ae43c83787be78b6cb66eb914b3fd487a20fb33ed4ac60a5bc7"
//   const orderCellBoc = "b5ee9c7241010201004800011e00008e388cae08ac0000000100000301006842000d4657ab40e2a465a4a8b16229e180b483bd4ca12ff56e88288cbc34dbfa4f9f202faf080000000000000000000000000000d7be5224"
//   const signature  = wallet.rawSign(rawTxhash)
//   const signatures: [Uint8Array, number][] = [];
//   signatures.push([signature.signature, 0]);

//   const ledgerMnemonic =""
//   const targetTonWalletAddress = "UQBUQSw-F6EMKVpun_Uj_raPCczMyU0mw01W2ZRPrpJiBo-J" //it's non-bounceable address

//   let keyPair: KeyPair | null = null;
//   let index = 0
//   let found = true
//   while(found){
//     const { contract, keyPair: tmpKeyPair } = await extractKeysFromLedgerMnemonic(ledgerMnemonic, index)
//     const address = contract.address.toString({ bounceable: false })
//     const publicKeyHex = tmpKeyPair.publicKey.toString('hex')
//     const privateKeyHex = tmpKeyPair.secretKey.toString('hex').slice(0, 64)
//     console.log(`new target address ${address}`)
//     console.log(`Public key: ${publicKeyHex}`)
//     console.log(`Private key: ${privateKeyHex}`)
//     if(address === targetTonWalletAddress){
//       console.log(`Found the keypair for the target address ${targetTonWalletAddress}`)
//       keyPair = tmpKeyPair
//       found = false
//     }

//     index++
//   }
//   if(!keyPair){
//     throw new Error(`Could not find the keypair for the target address ${targetTonWalletAddress}`)
//   }
//   const wallet2 = new Wallet(keyPair)
//   console.log(wallet2)
//   const sign2 = wallet2.rawSign(rawTxhash)
//   signatures.push([sign2.signature, 1]);
  

//   const boc = createExternalMessageWithSignatures(1, Cell.fromHex(orderCellBoc), signatures, wallet2)
//   // const bocHex = createExternalMessageWithSignatures2(1, cell3FromString(orderCellBoc).stringCell, signatures, wallet2.rawSign2)

//   const a = external({
//     to: Address.parse('EQA73dVDgA1DyuhDsdSQR6cdpR9H8gM5lrnso-huxy6iBIDZ'),
//     body: Cell.fromBoc(boc)[0]
//   })
//   console.log(a)

//   const extMsgCell = beginCell()
//       .store(storeMessage(a))
//       .endCell()

//   console.log(extMsgCell.toBoc().toString('base64'))  

// }
// run()