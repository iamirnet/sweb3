<?php

namespace iAmirNet\SWeb3;

class Account
{
    public string $privateKey;
    public string $publicKey;
    public string $address;

    public function sign(string $message)
    {
        $hash = Accounts::hashMessage($message);
        $signature = $this->signRaw($hash);
        $signature->message = $message;

        return $signature;
    }

    public function signRaw(string $hash)
    {
        //https://ethereum.stackexchange.com/questions/35425/web3-js-eth-sign-vs-eth-accounts-sign-producing-different-signatures
        $pk = $this->privateKey;
        if (substr($pk, 0, 2) != '0x') $pk  = '0x' . $pk;

        // 64 hex characters + hex-prefix
        if (strlen($pk) != 66) {
            throw new \Exception("Private key must be length 64 + 2  (" . strlen($pk) . " provided)");
        }

        $ec = new \Elliptic\EC('secp256k1');
        try {
            $ecPrivateKey = $ec->keyFromPrivate(substr($pk, 2), 'hex');
        } catch (\Exception $e) {
            $ecPrivateKey = $ec->keyFromPrivate($pk, 'hex');
        }

        //https://ethereum.stackexchange.com/questions/86485/create-signed-message-without-json-rpc-node-in-php
        $signature = $ecPrivateKey->sign($hash, ['canonical' => true, "n" => null,]);
        $r = str_pad($signature->r->toString(16), 64, '0', STR_PAD_LEFT);
        $s = str_pad($signature->s->toString(16), 64, '0', STR_PAD_LEFT);
        $v = dechex($signature->recoveryParam + 27);

        $res = new \stdClass();
        $res->messageHash = '0x'.$hash;
        $res->r = '0x'.$r;
        $res->s = '0x'.$s;
        $res->v = '0x'.$v;
        $res->signature = '0x'.$r.$s.$v;//$signature;

        return $res;

        //echo "Signed Hello world is:\n";
        //echo "Using my script:\n";
        //echo "0x$r$s$v\n";
        //echo "Using MEW:\n";
        //echo "0x2f52dfb196b75398b78c0e6c6aee8dc08d7279f2f88af5588ad7728f1e93dd0a479a710365c91ba649deb6c56e2e16836ffc5857cfd1130f159aebd05377d3a01c\n";

        //web3.eth.accounts.sign('Some data', '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
        //> {
        //	message: 'Some data',
        //	messageHash: '0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655',
        //	v: '0x1c',
        //	r: '0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd',
        //	s: '0x6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029',
        ///	signature: '0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c'
        //}
    }

}
